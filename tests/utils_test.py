"""Unittests for Semgrep Agent Utilities"""
import typing

from ostorlab.agent.message import message

from agent import utils

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

VULNERABILITIES = typing.cast(list[dict[str, typing.Any]], JSON_OUTPUT.get("results"))


def testConstructTechnicalDetail_allDetailsProvided_returnsTechnicalDetail() -> None:
    """Unittest for the technical detail generation:
    case when all details are provided
    """
    path = typing.cast(str, JSON_OUTPUT.get("path"))
    vulnerability_json = VULNERABILITIES[0]
    technical_detail = utils.construct_technical_detail(vulnerability_json, path)

    assert (
        technical_detail
        == "The file `/code/app.java` has a security issue at line `28`, column `44`.\n"
        "The issue was identified as `java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle` "
        "and the message from the code analysis is "
        "`Using CBC with PKCS5Padding is susceptible to padding oracle attacks. "
        "A malicious actor could discern the difference between plaintext with valid or invalid padding. "
        "Further, CBC mode does not include any integrity checks. Use 'AES/GCM/NoPadding' instead.`."
    )


def testConstructTechnicalDetail_whenMissingSomeDetail_returnsTechnicalDetail() -> None:
    """Unittest for the technical detail generation:
    case when all details are provided
    """
    vulnerability_json = VULNERABILITIES[0]
    del vulnerability_json["check_id"]

    technical_detail = utils.construct_technical_detail(
        vulnerability_json, "/code/app.java"
    )

    assert (
        technical_detail
        == "The file `/code/app.java` has a security issue at line `28`, column `44`.\n"
        "The issue was identified as `N/A` "
        "and the message from the code analysis is "
        "`Using CBC with PKCS5Padding is susceptible to padding oracle attacks. "
        "A malicious actor could discern the difference between plaintext with valid or invalid padding. "
        "Further, CBC mode does not include any integrity checks. Use 'AES/GCM/NoPadding' instead.`."
    )


def testParseResults_whenVulnerabilitiesAreFound_returnsVulnerability() -> None:
    """Unittest for the results parser:
    case when vulnerabilities are found
    """
    for idx, vulnerability in enumerate(utils.parse_results(JSON_OUTPUT)):
        vuln = vulnerability.entry
        assert (
            vuln.title
            == "Using CBC with PKCS5Padding is susceptible to padding oracle attacks"
        )
        assert vuln.risk_rating == "MEDIUM"
        assert vuln.recommendation == "AES/GCM/NoPadding"
        assert (
            vuln.description
            == "Using CBC with PKCS5Padding is susceptible to padding oracle attacks. "
            "A malicious actor could discern the difference between plaintext with "
            "valid or invalid padding. Further, CBC mode does not include any "
            "integrity checks. Use 'AES/GCM/NoPadding' instead."
        )

        assert (
            list(vuln.references.values())
            == VULNERABILITIES[idx]["extra"]["metadata"]["references"]
        )
        assert not any(
            [
                vuln.has_public_exploit,
                vuln.privacy_issue,
                vuln.targeted_by_malware,
                vuln.targeted_by_nation_state,
                vuln.targeted_by_ransomware,
            ]
        )
        assert vuln.security_issue is True


def testParseResults_whenNoVulnerabilitiesAreFound_returnsVulnerability() -> None:
    """Unittest for the results parser:
    case when no vulnerabilities are found
    """
    JSON_OUTPUT["results"] = []

    assert next(utils.parse_results(JSON_OUTPUT), None) is None


def testGetFileType_withPathProvided_returnsFileType(
    scan_message_file: message.Message,
) -> None:
    """Unittest for the file type extraction:
    case when the path is provided
    """
    content = scan_message_file.data["content"]
    path = scan_message_file.data["path"]
    file_type = utils.get_file_type(content, path)

    assert file_type == ".java"


def testGetFileType_withoutPathProvided_returnsFileType(
    scan_message_file: message.Message,
) -> None:
    """Unittest for the file type extraction:
    case when the path is not provided
    """
    content = scan_message_file.data["content"]
    file_type = utils.get_file_type(content, None)

    assert file_type == ".java"
