"""Ostorlab Agent implementation for Semgrep"""
import json
import logging
import subprocess
import tempfile
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

COMMAND_TIMEOUT = 90


def _run_analysis(input_file_path: str) -> bytes | None:
    command = ["semgrep", "--config", "auto", "-q", "--json", input_file_path]
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

    return output.stdout


class SemgrepAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Semgrep agent."""

    def process(self, message: m.Message) -> None:
        """Trigger Semgrep analysis and emit found vulnerabilities

        Args:
            message: A message containing the path and the content of the file to be processed

        """
        content = message.data.get("content")
        path = message.data.get("path")

        if content is None:
            logger.error("Received empty file.")
            return

        file_type = utils.get_file_type(content, path)

        with tempfile.NamedTemporaryFile(suffix=file_type) as infile:
            infile.write(content)
            infile.flush()

            output = _run_analysis(infile.name)

            if isinstance(output, bytes):
                json_output = json.loads(output)
                json_output["path"] = path
                self._emit_results(json_output)
                logger.info("Process completed without errors.")
            else:
                logger.error("Process completed with errors.")

    def _emit_results(self, json_output: dict[str, Any]) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in utils.parse_results(json_output):
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
            )


if __name__ == "__main__":
    logger.info("Starting Agent ...")
    SemgrepAgent.main()
