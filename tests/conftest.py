"""conftest for Opengrep agent tests"""

import random
import pathlib
from typing import Any, cast

import pytest
from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import opengrep_agent

JSON_OUTPUT = {
    "errors": [],
    "paths": {
        "_comment": "<add --verbose for a list of skipped paths>",
        "scanned": ["/tmp/tmpza6g8qu0.java"],
    },
    "results": [
        {
            "check_id": "java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle",
            "end": {"col": 66, "line": 28, "offset": 791},
            "extra": {
                "engine_kind": "OSS",
                "fingerprint": "[REDACTED]",
                "fix": "AES/GCM/NoPadding",
                "is_ignored": False,
                "lines": "        Cipher cipher = Cipher.getInstance('AES/CBC/PKCS5Padding');",
                "message": "Using CBC with PKCS5Padding is susceptible to padding oracle attacks. "
                "A malicious actor could discern the difference between plaintext with valid or invalid padding. "
                "Further, CBC mode does not include any integrity checks. Use 'AES/GCM/NoPadding' instead.",
                "metadata": {
                    "category": "security",
                    "confidence": "HIGH",
                    "cwe": [
                        "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
                    ],
                    "impact": "MEDIUM",
                    "license": "Commons Clause License Condition v1.0[LGPL-2.1-only]",
                    "likelihood": "HIGH",
                    "owasp": [
                        "A03:2017 - Sensitive Data Exposure",
                        "A02:2021 - Cryptographic Failures",
                    ],
                    "references": [
                        "https://capec.mitre.org/data/definitions/463.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                        "https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY",
                    ],
                    "semgrep.dev": {
                        "rule": {
                            "origin": "community",
                            "rule_id": "ZqU5oD",
                            "url": "https://semgrep.dev/[REDACTED]",
                            "version_id": "zyTeEO",
                        }
                    },
                    "shortlink": "https://sg.run/ydxr",
                    "source": "https://semgrep.dev/r/java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle",
                    "source-rule-url": "https://find-sec-bugs.github.io/bugs.htm#PADDING_ORACLE",
                    "subcategory": ["audit"],
                    "technology": ["java"],
                },
                "metavars": {},
                "severity": "WARNING",
            },
            "path": "/tmp/tmpza6g8qu0.java",
            "start": {"col": 44, "line": 28, "offset": 769},
        }
    ],
    "version": "1.17.1",
    "path": "/code/app.java",
}


@pytest.fixture
def scan_message_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    path = "tests/files/vulnerable.java"
    with open(path, "rb") as infile:
        msg_data = {
            "content": infile.read(),
            "path": path,
            "android_metadata": {"package_name": "a.b.c"},
        }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def ios_scan_message_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    path = "tests/files/vulnerable.java"
    with open(path, "rb") as infile:
        msg_data = {
            "content": infile.read(),
            "path": path,
            "ios_metadata": {"bundle_id": "a.b.c"},
        }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_js_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    path = "tests/files/minified.js"
    with open(path, "rb") as infile:
        msg_data = {"content": infile.read(), "path": path}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_compressed_js_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    path = "tests/files/compressed_file.js"
    with open(path, "rb") as infile:
        msg_data = {"content": infile.read(), "path": path}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def test_agent(
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> opengrep_agent.OpengrepAgent:
    with (pathlib.Path(__file__).parent.parent / "oxo.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/opengrep",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )
        return opengrep_agent.OpengrepAgent(definition, settings)


@pytest.fixture()
def vulnerabilities() -> list[dict[str, Any]]:
    vulnz = cast(list[dict[str, Any]], JSON_OUTPUT.get("results"))

    return vulnz


@pytest.fixture()
def opengrep_json_output() -> dict[str, Any]:
    return JSON_OUTPUT
