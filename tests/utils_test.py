"""Unittests for Opengrep Agent Utilities"""

from typing import Any
import requests

import pytest
import requests_mock as reqs_mock
from ostorlab.agent.message import message as m

from agent import utils


def testConstructTechnicalDetail_allDetailsProvided_returnsTechnicalDetail(
    vulnerabilities: list[dict[str, Any]],
) -> None:
    """Unittest for the technical detail generation:
    case when all details are provided
    """
    vulnerability_json = vulnerabilities[0]
    technical_detail = utils.construct_technical_detail(
        vulnerability_json, "tests/files/vulnerable.java"
    )

    assert (
        technical_detail
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


def testParseResults_whenVulnerabilitiesAreFound_returnsVulnerability(
    opengrep_json_output: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
) -> None:
    """Unittest for the results parser:
    case when vulnerabilities are found
    """
    for idx, vulnerability in enumerate(utils.parse_results(opengrep_json_output)):
        vuln = vulnerability.entry
        assert vuln.title == "Cbc Padding Oracle"
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
            == vulnerabilities[idx]["extra"]["metadata"]["references"]
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


def testParseResults_whenNoVulnerabilitiesAreFound_returnsVulnerability(
    opengrep_json_output: dict[str, Any],
) -> None:
    """Unittest for the results parser:
    case when no vulnerabilities are found
    """
    opengrep_json_output["results"] = []

    assert next(utils.parse_results(opengrep_json_output), None) is None


def testGetFileType_withPathProvided_returnsFileType(
    scan_message_file: m.Message,
) -> None:
    """Unittest for the file type extraction:
    case when the path is provided
    """
    content = scan_message_file.data["content"]
    path = scan_message_file.data["path"]
    file_type = utils.get_file_type(content, path)

    assert file_type == ".java"


def testGetFileType_withoutPathProvided_returnsFileType(
    scan_message_file: m.Message,
) -> None:
    """Unittest for the file type extraction:
    case when the path is not provided
    """
    content = scan_message_file.data["content"]
    file_type = utils.get_file_type(content, None)

    assert file_type == ".java"


def testConstructVulnerabilityTitle_whenCheckIdIsAvailable_returnsTitle() -> None:
    """Unittest for the title construction:
    case when check id is available
    """
    check_id = "java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle"

    title = utils.construct_vulnerability_title(check_id)

    assert title == "Cbc Padding Oracle"


def testConstructVulnerabilityTitle_whenCheckIdIsNotAvailable_raisesException() -> None:
    """Unittest for the title construction:
    case when check id is missing
    """
    with pytest.raises(ValueError) as exception:
        utils.construct_vulnerability_title(None)

    assert exception.typename == "ValueError"
    assert exception.value.args[0] == "Check ID is not defined"


def testFilterDescription_caseRegexRedos_returnFilteredDescription() -> None:
    """Unit test for filter description:
    case when regex ReDos description
    """
    description = (
        "RegExp() called with a token function argument, this might allow an attacker to cause "
        "a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks "
        "the main thread. For this reason, it is recommended to use hardcoded regexes instead. If "
        "your regex is run on user-controlled input, consider performing input validation or use a "
        "regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify "
        "that the regex does not appear vulnerable to ReDoS."
    )

    filtered_description = utils.filter_description(description)

    assert (
        filtered_description
        == "RegExp() called with a function argument, this might allow an attacker to cause a Regular "
        "Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. "
        "For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on "
        "user-controlled input, consider performing input validation or use a regex checking/sanitization "
        "library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear "
        "vulnerable to ReDoS."
    )


def testGetFileContent_whenContentIsNotNone_returnTheContent() -> None:
    """Test that the content is returned when it is not empty."""
    message = m.Message.from_data(
        selector="v3.asset.file.android.apk", data={"content": b"content"}
    )

    content = utils.get_file_content(message)

    assert content == b"content"


def testGetFileContent_whenContentIsEmpty_shouldTryToDownloadTheFile(
    requests_mock: reqs_mock.mocker.Mocker,
) -> None:
    """Test that the file is downloaded when the content is empty."""
    message = m.Message.from_data(
        selector="v3.asset.file.android.apk",
        data={"content_url": "https://example.com/legendary.apk"},
    )
    requests_mock.get(
        "https://example.com/legendary.apk", content=b"downloaded_content"
    )

    content = utils.get_file_content(message)

    assert content == b"downloaded_content"


def testGetFileContent_whenContentUrlIsUnreacheable_shouldRetryThreeTimes(
    requests_mock: reqs_mock.mocker.Mocker,
) -> None:
    """Test that the file download is retried three times."""
    message = m.Message.from_data(
        selector="v3.asset.file.android.apk",
        data={"content_url": "https://example.com/legendary.apk"},
    )
    download_file_mock = requests_mock.get(
        "https://example.com/legendary.apk", exc=requests.exceptions.ConnectionError
    )

    content = utils.get_file_content(message)

    assert content is None
    assert download_file_mock.call_count == 3


def testGetFileContent_whenNoContentIsAvailable_shouldReturnNone() -> None:
    """Test that None is returned when no content is available."""
    message = m.Message.from_data(selector="v3.asset.file.android.apk", data={})

    content = utils.get_file_content(message)

    assert content is None
