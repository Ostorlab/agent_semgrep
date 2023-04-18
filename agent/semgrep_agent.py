"""Ostorlab Agent implementation for Semgrep"""
import json
import logging
import subprocess
import tempfile
from typing import Any, Optional

from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
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


class SemgrepAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Semgrep agent."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        agent_report_vulnerability_mixin.AgentReportVulnMixin.__init__(self)
        self.timeout: Optional[int] = self.args.get("timeout")

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

            output = self._run_analysis(infile.name)

            if isinstance(output, bytes):
                json_output = json.loads(output)
                json_output["path"] = path
                self._emit_results(json_output)
                logger.info("Process completed without errors")
            else:
                logger.error("Process completed with errors")

    def _run_analysis(self, input_file_path: str) -> bytes | None:
        command = ["semgrep", "--config", "auto",
                   "-q", "--json", input_file_path]
        try:
            output = subprocess.run(
                command, capture_output=True, check=True, timeout=self.timeout
            )
        except subprocess.CalledProcessError as e:
            logger.error(
                "An error occurred while running the command. Error message: %s", e
            )
            return None
        except subprocess.TimeoutExpired:
            logger.warning("Timeout occured while running command")
            return None

        return output.stdout

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
