"""Unittests for Semgrep agent."""
import subprocess

from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import semgrep_agent

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
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
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

ERROR_MESSAGE = b"""
semgrep error: Invalid rule schema
  --> .semgrep/settings.yml:1
1 | anonymous_user_id: e274d9a4-8bac-4a87-b4a2-83243557981a
2 | has_shown_metrics_notification: true

One of these properties is missing: 'rules'

[ERROR] invalid configuration file found (1 configs were invalid)
"""

EMPTY_ERROR_MESSAGE = b""


def testAgentSemgrep_whenAnalysisRunsWithoutErrors_emitsBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the semgrep analysis runs without errors and yields vulnerabilities.
    """
    mocker.patch(
        "agent.semgrep_agent._run_analysis",
        return_value=(JSON_OUTPUT, EMPTY_ERROR_MESSAGE),
    )

    test_agent.process(scan_message_file)
    vuln = agent_mock[0].data

    assert vuln["title"] == "Cbc Padding Oracle"
    assert vuln["risk_rating"] == "MEDIUM"
    assert vuln["recommendation"] == "AES/GCM/NoPadding"
    assert (
        vuln["description"]
        == "Using CBC with PKCS5Padding is susceptible to padding oracle attacks. "
        "A malicious actor could discern the difference between plaintext with "
        "valid or invalid padding. Further, CBC mode does not include any "
        "integrity checks. Use 'AES/GCM/NoPadding' instead."
    )

    assert [entry["url"] for entry in vuln["references"]] == [
        "https://capec.mitre.org/data/definitions/463.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        "https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY",
    ]
    assert not any(
        [
            vuln["has_public_exploit"],
            vuln["privacy_issue"],
            vuln["targeted_by_malware"],
            vuln["targeted_by_nation_state"],
            vuln["targeted_by_ransomware"],
        ]
    )
    assert vuln["security_issue"] is True
    assert (
        vuln["technical_detail"]
        == "The file `tests/files/vulnerable.java` has a security issue at line `28`, column "
        "`44`:\n"
        "```java\n"
        "Cipher cipher = Cipher.getInstance('AES/CBC/PKCS5Padding');\n"
        "```\n"
        "\n"
        "The issue was identified as "
        "`java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle` and the "
        "message from the code analysis is `Using CBC with PKCS5Padding is "
        "susceptible to padding oracle attacks. A malicious actor could discern the "
        "difference between plaintext with valid or invalid padding. Further, CBC "
        "mode does not include any integrity checks. Use 'AES/GCM/NoPadding' "
        "instead.`."
    )


def testAgentSemgrep_whenAnalysisRunsWithoutPathWithoutErrors_emitsBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the semgrep analysis runs without a path provided and without errors and yields vulnerabilities.
    """
    mocker.patch(
        "agent.semgrep_agent._run_analysis",
        return_value=(JSON_OUTPUT, EMPTY_ERROR_MESSAGE),
    )

    del scan_message_file.data["path"]
    test_agent.process(scan_message_file)
    vuln = agent_mock[0].data

    assert vuln["title"] == "Cbc Padding Oracle"
    assert vuln["risk_rating"] == "MEDIUM"
    assert vuln["recommendation"] == "AES/GCM/NoPadding"
    assert (
        vuln["description"]
        == "Using CBC with PKCS5Padding is susceptible to padding oracle attacks. "
        "A malicious actor could discern the difference between plaintext with "
        "valid or invalid padding. Further, CBC mode does not include any "
        "integrity checks. Use 'AES/GCM/NoPadding' instead."
    )

    assert [entry["url"] for entry in vuln["references"]] == [
        "https://capec.mitre.org/data/definitions/463.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        "https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY",
    ]
    assert not any(
        [
            vuln["has_public_exploit"],
            vuln["privacy_issue"],
            vuln["targeted_by_malware"],
            vuln["targeted_by_nation_state"],
            vuln["targeted_by_ransomware"],
        ]
    )
    assert vuln["security_issue"] is True
    assert (
        vuln["technical_detail"]
        == "The file `/tmp/tmpza6g8qu0.java` has a security issue at line `28`, column "
        "`44`:\n"
        "```java\n"
        "Cipher cipher = Cipher.getInstance('AES/CBC/PKCS5Padding');\n"
        "```\n"
        "\n"
        "The issue was identified as "
        "`java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle` and the "
        "message from the code analysis is `Using CBC with PKCS5Padding is "
        "susceptible to padding oracle attacks. A malicious actor could discern the "
        "difference between plaintext with valid or invalid padding. Further, CBC "
        "mode does not include any integrity checks. Use 'AES/GCM/NoPadding' "
        "instead.`."
    )


def testAgentSemgrep_whenAnalysisRunsWithoutErrors_doesNotEmitBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the semgrep analysis runs without errors and does not yield vulnerabilities.
    """
    mocker.patch(
        "agent.semgrep_agent._run_analysis",
        return_value=(EMPTY_JSON_OUTPUT, EMPTY_ERROR_MESSAGE),
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) == 0


def testAgentSemgrep_whenAnalysisRunsWithErrors_doesNotEmitBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the semgrep analysis runs without errors and does not yield vulnerabilities.
    """
    mocker.patch(
        "agent.semgrep_agent._run_analysis",
        return_value=(EMPTY_JSON_OUTPUT, ERROR_MESSAGE),
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) == 0


def testAgentSemgrep_whenAnalysisRunsWithTimeout_doesNotEmitBackVulnerability(
    test_agent: semgrep_agent.SemgrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_persist_mock: dict[str | bytes, str | bytes],
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
