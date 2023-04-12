"""Semgrep agent implementation"""
import logging
from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent.message import message as m

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class SemgrepAgent(agent.Agent):
    """Semgrep agent."""

    def start(self) -> None:
        """TODO (author): add your description here."""
        logger.info("running start")

    def process(self, message: m.Message) -> None:
        """Process the source file

        Args:
            message: A message containing the file to be processed.
             The message should contain the file content and path.

        """

        content = message.data.get("content")




if __name__ == "__main__":
    logger.info("starting agent ...")
    SemgrepAgent.main()
