"""Unittests for Semgrep agent."""
import subprocess
from typing import Union

from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import semgrep_agent
from agent import utils

JSON_OUTPUT = b"""
{
  "errors": [],
  "paths": {
    "_comment": "<add --verbose for a list of skipped paths>",
    "scanned": [
      "/tmp/tmpza6g8qu0.java"
    ]
  },
  "results": [
    {
      "check_id": "java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle",
      "end": {
        "col": 66,
        "line": 28,
        "offset": 791
      },
      "extra": {
        "engine_kind": "OSS",
        "fingerprint": "[REDACTED]",
        "fix": "AES/GCM/NoPadding",
        "is_ignored": false,
        "lines": "        Cipher cipher = Cipher.getInstance('AES/CBC/PKCS5Padding');",
        "message": "Using CBC with PKCS5Padding is susceptible to padding oracle attacks. A malicious actor could discern the difference between plaintext with valid or invalid padding. Further, CBC mode does not include any integrity checks. Use 'AES/GCM/NoPadding' instead.",
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
            "A02:2021 - Cryptographic Failures"
          ],
          "references": [
            "https://capec.mitre.org/data/definitions/463.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes",
            "https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY"
          ],
          "semgrep.dev": {
            "rule": {
              "origin": "community",
              "rule_id": "ZqU5oD",
              "url": "https://semgrep.dev/playground/r/zyTeEO/java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle",
              "version_id": "zyTeEO"
            }
          },
          "shortlink": "https://sg.run/ydxr",
          "source": "https://semgrep.dev/r/java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle",
          "source-rule-url": "https://find-sec-bugs.github.io/bugs.htm#PADDING_ORACLE",
          "subcategory": [
            "audit"
          ],
          "technology": [
            "java"
          ]
        },
        "metavars": {},
        "severity": "WARNING"
      },
      "path": "/tmp/tmpza6g8qu0.java",
      "start": {
        "col": 44,
        "line": 28,
        "offset": 769
      }
    }
  ],
  "version": "1.17.1"
}"""

EMPTY_JSON_OUTPUT = b"""
{
  "errors": [],
  "paths": {
    "_comment": "<add --verbose for a list of skipped paths>",
    "scanned": [
      "/tmp/tmpxqhzjli3.java"
    ]
  },
  "results": [],
  "version": "1.17.1"
}"""


def testAgentSemgrep_whenAnalysisRunsWithoutErrors_emitsBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[Union[str, bytes], Union[str, bytes]],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the semgrep analysis runs without errors and yields vulnerabilities.
    """

    mocker.patch(
        "agent.semgrep_agent.SemgrepAgent._run_analysis",
        return_value=JSON_OUTPUT,
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == "MEDIUM"
    assert (
        agent_mock[0].data["title"]
        == "Using CBC with PKCS5Padding is susceptible to padding oracle attacks"
    )
    assert len(agent_mock[0].data["references"]) >= 3


def testAgentSemgrep_whenAnalysisRunsWithoutPathWithoutErrors_emitsBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[Union[str, bytes], Union[str, bytes]],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the semgrep analysis runs without a path provided and without errors and yields vulnerabilities.
    """

    mocker.patch(
        "agent.semgrep_agent.SemgrepAgent._run_analysis",
        return_value=JSON_OUTPUT,
    )

    del scan_message_file.data["path"]

    test_agent.process(scan_message_file)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == "MEDIUM"
    assert (
        agent_mock[0].data["title"]
        == "Using CBC with PKCS5Padding is susceptible to padding oracle attacks"
    )
    assert len(agent_mock[0].data["references"]) >= 3


def testAgentSemgrep_whenAnalysisRunsWithoutErrors_doesNotEmitBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[Union[str, bytes], Union[str, bytes]],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the semgrep analysis runs without errors and does not yield vulnerabilities.
    """

    mocker.patch(
        "agent.semgrep_agent.SemgrepAgent._run_analysis",
        return_value=EMPTY_JSON_OUTPUT,
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) == 0


def testAgentSemgrep_whenAnalysisRunsWithTimeout_doesNotEmitBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[Union[str, bytes], Union[str, bytes]],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the process execution:
    case where the process runs with timeout.
    """

    mocker.patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="", timeout=30)
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) == 0


def testAgentSemgrep_whenAnalysisRunsWithCalledProcessError_doesNotEmitBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[Union[str, bytes], Union[str, bytes]],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the process execution:
    case where the process runs with called process error.
    """

    mocker.patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(cmd="", returncode=2),
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) == 0


def testGetFileType_withPathProvided_returnsBackFileType(
    scan_message_file: message.Message,
) -> None:
    """Unittest for the file type extraction:
    case when the path is provided
    """
    content = scan_message_file.data["content"]
    path = scan_message_file.data["path"]
    file_type = utils.get_file_type(content, path)

    assert file_type == ".java"


def testGetFileType_withoutPathProvided_returnsBackFileType(
    scan_message_file: message.Message,
) -> None:
    """Unittest for the file type extraction:
    case when the path is not provided
    """
    content = scan_message_file.data["content"]
    file_type = utils.get_file_type(content, None)

    assert file_type == ".java"
