"""Ostorlab Agent implementation for Semgrep"""

import json
import logging
import pathlib
import subprocess
import tempfile
from typing import Any

import jsbeautifier
from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from rich import logging as rich_logging

from agent import utils


logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = 120
REPOSITORY_COMMAND_TIMEOUT = 1200
# Number of semgrep rules that can time out on a file before the file is skipped, 0 will have no limit.
TIMEOUT_THRESHOLD = 0
# 500MB
FILE_SIZE_LIMIT = 500 * 1024 * 1024
# 2GB
DEFAULT_MEMORY_LIMIT = 2 * 1024 * 1024 * 1024
REPOSITORY_CODE_PATH = "/code"
REPOSITORY_SELECTOR = "v3.asset.repository"
REPOSITORY_ARCHIVE_SELECTOR = "v3.asset.file.repository_archive"
# Directory bundling Ostorlab custom semgrep rules that are applied on top of
# the default `auto` registry ruleset. Resolved relative to this module so it
# works both inside the Docker image (`/app/agent/rules`) and from a source
# checkout.
RULES_DIR = str(pathlib.Path(__file__).resolve().parent / "rules")

FILE_TYPE_WHITELIST = (
    ".js",
    ".html",
    ".py",
    ".txt",
    ".css",
    ".mustache",
    ".java",
    ".ts",
    ".env",
)


def _run_analysis(
    input_file_path: str,
    max_memory_limit: int = DEFAULT_MEMORY_LIMIT,
    command_timeout: int = COMMAND_TIMEOUT,
) -> tuple[bytes, bytes] | None:
    command = [
        "opengrep",
        "scan",
        "-q",
        "--config",
        "auto",
        "--config",
        RULES_DIR,
        "--timeout",
        str(command_timeout),
        "--timeout-threshold",
        str(TIMEOUT_THRESHOLD),
        "--max-target-bytes",
        str(FILE_SIZE_LIMIT),
        "--max-memory",
        str(max_memory_limit),
        "--json",
        input_file_path,
    ]
    try:
        output = subprocess.run(
            command, capture_output=True, check=True, timeout=command_timeout
        )
    except subprocess.CalledProcessError as e:
        logger.error(
            "An error occurred while running the command. Error message: %s", e
        )
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Timeout occurred while running command")
        return None

    return (output.stdout, output.stderr)


class SemgrepAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Semgrep agent."""

    def process(self, message: m.Message) -> None:
        """Trigger Semgrep analysis and emit found vulnerabilities

        Args:
            message: A message containing the path and the content of the file to be processed

        """
        memory_limit = (
            self.args.get("memory_limit", DEFAULT_MEMORY_LIMIT) or DEFAULT_MEMORY_LIMIT
        )

        if message.selector == REPOSITORY_ARCHIVE_SELECTOR:
            self._process_repository_archive_asset(message, memory_limit)
            return

        if message.selector == REPOSITORY_SELECTOR:
            self._process_repository_asset(message, memory_limit)
            return

        path = message.data.get("path")

        if (
            utils.should_exclude_path(path, self.args.get("exclude_path_regexes"))
            is True
        ):
            return

        content = utils.get_file_content(message)

        if content is None:
            logger.error("Received empty file.")
            return

        file_type = utils.get_file_type(content, path)
        logger.info("Analyzing file `%s` with type `%s`.", path, file_type)

        if file_type not in FILE_TYPE_WHITELIST:
            logger.debug("File type is blacklisted.")
            return

        bundle_id = message.data.get("ios_metadata", {}).get("bundle_id")
        package_name = message.data.get("android_metadata", {}).get("package_name")
        harmony_bundle_name = message.data.get("harmonyos_metadata", {}).get(
            "bundle_name"
        )

        with tempfile.NamedTemporaryFile(suffix=file_type) as infile:
            if path is not None and path.endswith(".js") is True:
                # Beautify JavaScript source code to handle minified JS. By using Beautifier, we reduce false positive
                # and produce better reports.
                try:
                    infile.write(
                        jsbeautifier.beautify(content.decode(errors="ignore")).encode()
                    )
                except AttributeError as e:
                    logger.warning(
                        "Error occurred %s while formatting file %s.", e, path
                    )
                    return
            else:
                infile.write(content)
            infile.flush()

            output = _run_analysis(infile.name, memory_limit)

            if output is None:
                logger.error("Subprocess completed with errors.")
                return

            stdout, stderr = output

            if isinstance(stdout, bytes) and len(stderr) == 0:
                json_output = json.loads(stdout)
                json_output["path"] = path
                self._emit_results(
                    json_output=json_output,
                    package_name=package_name,
                    bundle_id=bundle_id,
                    harmony_bundle_name=harmony_bundle_name,
                )
                logger.debug("Semgrep completed without errors.")
            else:
                logger.error("Semgrep completed with errors %s", stderr)

    def _scan_repository_code(self, memory_limit: int) -> dict[str, Any] | None:
        """Scan the source code extracted to the shared /code volume, the content carried by the message is never read."""
        output = _run_analysis(
            REPOSITORY_CODE_PATH,
            memory_limit,
            command_timeout=REPOSITORY_COMMAND_TIMEOUT,
        )
        if output is None:
            logger.error("Repository scan completed with errors.")
            return None

        stdout, stderr = output
        if not isinstance(stdout, bytes) or len(stderr) > 0:
            logger.error("Repository scan completed with errors %s", stderr)
            return None

        json_output: dict[str, Any] = json.loads(stdout)
        logger.debug("Repository scan completed without errors.")
        return json_output

    def _process_repository_asset(self, message: m.Message, memory_limit: int) -> None:
        """Scan a repository asset and report against its repository URL."""
        json_output = self._scan_repository_code(memory_limit)
        if json_output is None:
            return

        self._emit_results(
            json_output=json_output,
            repository_url=message.data.get("repository_url"),
            commit_hash=message.data.get("commit_hash"),
            provider=message.data.get("provider"),
        )

    def _process_repository_archive_asset(
        self, message: m.Message, memory_limit: int
    ) -> None:
        """Scan a repository archive asset and report against its content URL, it carries no repository URL, commit hash nor provider."""
        json_output = self._scan_repository_code(memory_limit)
        if json_output is None:
            return

        self._emit_results(
            json_output=json_output,
            archive_content_url=message.data.get("content_url"),
        )

    def _emit_results(
        self,
        json_output: dict[str, Any],
        package_name: str | None = None,
        bundle_id: str | None = None,
        harmony_bundle_name: str | None = None,
        repository_url: str | None = None,
        commit_hash: str | None = None,
        provider: str | None = None,
        archive_content_url: str | None = None,
    ) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in utils.parse_results(
            json_output=json_output,
            package_name=package_name,
            bundle_id=bundle_id,
            harmony_bundle_name=harmony_bundle_name,
            repository_url=repository_url,
            commit_hash=commit_hash,
            provider=provider,
            archive_content_url=archive_content_url,
        ):
            logger.info("Found vulnerability: %s", vuln)
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
                dna=vuln.vuln_dna,
            )


if __name__ == "__main__":
    logger.info("Starting Agent ...")
    SemgrepAgent.main()
