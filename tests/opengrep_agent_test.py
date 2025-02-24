"""Unittests for Opengrep agent."""

import subprocess

from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import opengrep_agent

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


def testAgentOpengrep_whenAnalysisRunsWithoutErrors_emitsBackVulnerability(
    test_agent: opengrep_agent.OpengrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the opengrep analysis runs without errors and yields vulnerabilities.
    """
    mocker.patch(
        "agent.opengrep_agent._run_analysis",
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
    assert vuln["references"] == [
        {
            "title": "capec.mitre.org",
            "url": "https://capec.mitre.org/data/definitions/463.html",
        },
        {
            "title": "cheatsheetseries.owasp.org",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        },
        {
            "title": "find-sec-bugs.github.io",
            "url": "https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY",
        },
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
        == "Cbc Padding Oracle: Using CBC with PKCS5Padding is susceptible to padding "
        "oracle attacks. A malicious actor could discern the difference between "
        "plaintext with valid or invalid padding. Further, CBC mode does not include "
        "any integrity checks. Use 'AES/GCM/NoPadding' instead.\n"
        "    \n"
        "The issue was detected in `tests/files/vulnerable.java`, line `28`, column "
        "`44`, below is a code snippet from the vulnerable code\n"
        "```java\n"
        "Cipher cipher = Cipher.getInstance('AES/CBC/PKCS5Padding');\n"
        "```"
    )
    assert vuln["vulnerability_location"] is not None
    assert vuln["vulnerability_location"]["metadata"][0]["type"] == "FILE_PATH"
    assert (
        vuln["vulnerability_location"]["metadata"][0]["value"]
        == "tests/files/vulnerable.java"
    )
    assert vuln["vulnerability_location"]["android_store"] is not None
    assert vuln["vulnerability_location"]["android_store"]["package_name"] == "a.b.c"


def testAgentOpengrep_whenAnalysisRunsWithoutPathWithoutErrors_emitsBackVulnerability(
    test_agent: opengrep_agent.OpengrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the opengrep analysis runs without a path provided and without errors and yields vulnerabilities.
    """
    mocker.patch(
        "agent.opengrep_agent._run_analysis",
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

    assert vuln["references"] == [
        {
            "title": "capec.mitre.org",
            "url": "https://capec.mitre.org/data/definitions/463.html",
        },
        {
            "title": "cheatsheetseries.owasp.org",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        },
        {
            "title": "find-sec-bugs.github.io",
            "url": "https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY",
        },
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
        == "Cbc Padding Oracle: Using CBC with PKCS5Padding is susceptible to padding "
        "oracle attacks. A malicious actor could discern the difference between "
        "plaintext with valid or invalid padding. Further, CBC mode does not include "
        "any integrity checks. Use 'AES/GCM/NoPadding' instead.\n"
        "    \n"
        "The issue was detected in `/tmp/tmpza6g8qu0.java`, line `28`, column `44`, "
        "below is a code snippet from the vulnerable code\n"
        "```java\n"
        "Cipher cipher = Cipher.getInstance('AES/CBC/PKCS5Padding');\n"
        "```"
    )


def testAgentOpengrep_whenAnalysisRunsWithoutErrors_doesNotEmitBackVulnerability(
    test_agent: opengrep_agent.OpengrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the opengrep analysis runs without errors and does not yield vulnerabilities.
    """
    mocker.patch(
        "agent.opengrep_agent._run_analysis",
        return_value=(EMPTY_JSON_OUTPUT, EMPTY_ERROR_MESSAGE),
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) == 0


def testAgentOpengrep_whenAnalysisRunsWithErrors_doesNotEmitBackVulnerability(
    test_agent: opengrep_agent.OpengrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the opengrep analysis runs without errors and does not yield vulnerabilities.
    """
    mocker.patch(
        "agent.opengrep_agent._run_analysis",
        return_value=(EMPTY_JSON_OUTPUT, ERROR_MESSAGE),
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) == 0


def testAgentOpengrep_whenAnalysisRunsWithTimeout_doesNotEmitBackVulnerability(
    test_agent: opengrep_agent.OpengrepAgent,
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


def testAgentOpengrep_whenAnalysisRunsWithCalledProcessError_doesNotEmitBackVulnerability(
    test_agent: opengrep_agent.OpengrepAgent,
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


def testAgentOpengrep_whenAnalysisRunsOnJsFile_emitsBackVulnerability(
    test_agent: opengrep_agent.OpengrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_js_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the opengrep analysis runs without a path provided and without errors and yields vulnerabilities.
    """
    mocker.patch(
        "agent.opengrep_agent._run_analysis",
        return_value=(JSON_OUTPUT, EMPTY_ERROR_MESSAGE),
    )

    test_agent.process(scan_message_js_file)

    assert len(agent_mock) > 0


def testAgentOpengrep_whenAnalysisRunsOnCompressedJsFile_emitsNoVulnerability(
    test_agent: opengrep_agent.OpengrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_compressed_js_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the opengrep analysis runs with a compressed js file shouldn't yield vulnerabilities.
    """
    mocker.patch(
        "agent.opengrep_agent._run_analysis",
        return_value=(JSON_OUTPUT, EMPTY_ERROR_MESSAGE),
    )

    test_agent.process(scan_message_compressed_js_file)

    assert len(agent_mock) == 0


def testAgentOpengrep_whenValidMessage_constructCorrectCommand(
    test_agent: opengrep_agent.OpengrepAgent,
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test testing opengrep command construction."""
    command_mock = mocker.patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(cmd="", returncode=2),
    )

    test_agent.process(scan_message_file)

    assert command_mock.call_args.args[0][0] == "opengrep"
    assert command_mock.call_args.args[0][1] == "--metrics"
    assert command_mock.call_args.args[0][2] == "auto"
    assert command_mock.call_args.args[0][3] == "-q"
    assert command_mock.call_args.args[0][4] == "--config"
    assert command_mock.call_args.args[0][5] == "auto"
    assert command_mock.call_args.args[0][6] == "--timeout"
    assert command_mock.call_args.args[0][7] == "120"
    assert command_mock.call_args.args[0][8] == "--timeout-threshold"
    assert command_mock.call_args.args[0][9] == "0"
    assert command_mock.call_args.args[0][10] == "--max-target-bytes"
    assert command_mock.call_args.args[0][11] == "524288000"
    assert command_mock.call_args.args[0][12] == "--max-memory"
    assert command_mock.call_args.args[0][13] == "2147483648"
    assert command_mock.call_args.args[0][14] == "--json"


def testAgentOpengrep_whenIosAsset_addsIosAssetToVulnLocation(
    test_agent: opengrep_agent.OpengrepAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ios_scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for the full life cycle of the agent:
    case where the opengrep analysis runs without errors and yields vulnerabilities.
    """
    mocker.patch(
        "agent.opengrep_agent._run_analysis",
        return_value=(JSON_OUTPUT, EMPTY_ERROR_MESSAGE),
    )

    test_agent.process(ios_scan_message_file)
    vuln = agent_mock[0].data

    assert vuln["title"] == "Cbc Padding Oracle"
    assert vuln["risk_rating"] == "MEDIUM"
    assert vuln["recommendation"] == "AES/GCM/NoPadding"
    assert vuln["security_issue"] is True
    assert vuln["vulnerability_location"] is not None
    assert vuln["vulnerability_location"]["metadata"][0]["type"] == "FILE_PATH"
    assert (
        vuln["vulnerability_location"]["metadata"][0]["value"]
        == "tests/files/vulnerable.java"
    )
    assert vuln["vulnerability_location"]["ios_store"] is not None
    assert vuln["vulnerability_location"]["ios_store"]["bundle_id"] == "a.b.c"
