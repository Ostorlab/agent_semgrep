"""Ostorlab Agent implementation for Semgrep"""

import json
import logging
import subprocess
import tempfile
import jsbeautifier
from typing import Any

from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent import agent
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
# Number of semgrep rules that can time out on a file before the file is skipped, 0 will have no limit.
TIMEOUT_THRESHOLD = 0
# 500MB
FILE_SIZE_LIMIT = 500 * 1024 * 1024
# 2GB
DEFAULT_MEMORY_LIMIT = 2 * 1024 * 1024 * 1024

FILE_TYPE_BLACKLIST = (
    ".car",
    ".dex",
    ".dylib",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".json",
    ".mobileprovision",
    ".nib",
    ".pdf",
    ".plist",
    ".png",
    ".psd",
    ".so",
    ".strings",
    ".svg",
    ".symbols",
    ".ttf",
    ".woff",
    ".woff2",
    ".zip",
    ".xml",
)


def _run_analysis(
    input_file_path: str, max_memory_limit: int = DEFAULT_MEMORY_LIMIT
) -> tuple[bytes, bytes] | None:
    command = [
        "semgrep",
        "-q",
        "--config",
        "auto",
        "--timeout",
        str(COMMAND_TIMEOUT),
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
            command, capture_output=True, check=True, timeout=COMMAND_TIMEOUT
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
        content = utils.get_file_content(message)
        path = message.data.get("path")
        memory_limit = (
            self.args.get("memory_limit", DEFAULT_MEMORY_LIMIT) or DEFAULT_MEMORY_LIMIT
        )

        if content is None:
            logger.error("Received empty file.")
            return

        file_type = utils.get_file_type(content, path)
        logger.info("Analyzing file `%s` with type `%s`.", path, file_type)

        if file_type in FILE_TYPE_BLACKLIST:
            logger.debug("File type is blacklisted.")
            return

        with tempfile.NamedTemporaryFile(suffix=file_type) as infile:
            if path is not None and path.endswith(".js") is True:
                # Beautify JavaScript source code to handle minified JS. By using Beautifier, we reduce false positive
                # and produce better reports.
                infile.write(
                    jsbeautifier.beautify(content.decode(errors="ignore")).encode()
                )
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
                self._emit_results(json_output)
                logger.debug("Semgrep completed without errors.")
            else:
                logger.error("Semgrep completed with errors %s", stderr)

    def _emit_results(self, json_output: dict[str, Any]) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in utils.parse_results(json_output):
            logger.info("Found vulnerability: %s", vuln)
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
            )


if __name__ == "__main__":
    logger.info("Starting Agent ...")
    SemgrepAgent.main()
