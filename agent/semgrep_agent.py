"""Ostorlab Agent implementation for Semgrep"""
import json
import logging
import os
import subprocess
import tempfile
from typing import Dict

from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from rich import logging as rich_logging

from agent import result_parser

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class SemgrepAgent(agent.Agent, vuln_mixin.AgentReportVulnMixin):
    """Semgrep agent."""

    def _emit_results(self, json_output: Dict) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in result_parser.parse_results(json_output):
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
            )

    def _run_analysis(self, input_file_path: str) -> bytes:
        command = ["semgrep", "--config", "auto", "-q", "--json", input_file_path]
        try:
            output = subprocess.run(command, capture_output=True, check=True)
        except subprocess.CalledProcessError:
            logger.error("An error occurred while running the command")
            return
        except subprocess.TimeoutExpired:
            logger.warning("Timeout")
            return

        return output.stdout

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

        if path is None:
            logger.error("File path was not provided")
            return

        file_split = os.path.splitext(path)

        if len(file_split) != 2:
            logger.error("File provided without extension")
            return

        with tempfile.NamedTemporaryFile(suffix=file_split[1]) as infile:
            infile.write(content)

            infile.flush()

            json_output = json.loads(self._run_analysis(infile.name))

            json_output["path"] = path

            self._emit_results(json_output)

        logger.info("Analysis Done")


if __name__ == "__main__":
    logger.info("Starting Agent ...")
    SemgrepAgent.main()
