"""
    conftest for semgrep agent tests
"""

import pytest
import random
import pathlib
from typing import Dict

from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from agent import semgrep_agent


@pytest.fixture
def scan_message_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    path = "files/vulnerable.java"
    with open(path, "rb") as infile:
        msg_data = {"content": infile.read(), "path": path}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def test_agent(
    agent_persist_mock: Dict[str | bytes, str | bytes]
) -> semgrep_agent.SemgrepAgent:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/semgrep",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )
        return semgrep_agent.SemgrepAgent(definition, settings)
