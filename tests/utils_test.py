"""Unittests for Semgrep Agent Utilities"""

from typing import Any

import pytest
import requests
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
    semgrep_json_output: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
) -> None:
    """Unittest for the results parser:
    case when vulnerabilities are found
    """
    for idx, vulnerability in enumerate(utils.parse_results(semgrep_json_output)):
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
    semgrep_json_output: dict[str, Any],
) -> None:
    """Unittest for the results parser:
    case when no vulnerabilities are found
    """
    semgrep_json_output["results"] = []

    assert next(utils.parse_results(semgrep_json_output), None) is None


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


@pytest.mark.parametrize(
    ("repository_url", "expected_repository_name"),
    [
        (
            "https://github.com/org/repo.git",
            "repo",
        ),
        (
            "https://github.com/org/repo/",
            "repo",
        ),
    ],
)
def testConstructRepositoryAssetDirectoryName_whenRepositoryUrlHasSuffixes_returnsAssetDirectory(
    repository_url: str,
    expected_repository_name: str,
    repository_commit_hash: str,
) -> None:
    """Repository URLs with .git or trailing slash use the bare repo name."""
    asset_directory = utils.construct_repository_asset_directory_name(
        repository_url, repository_commit_hash
    )

    assert asset_directory == f"{expected_repository_name}_{repository_commit_hash}"


def testConstructRepositoryAssetDirectoryName_whenRepositoryUrlHasNoSuffix_returnsAssetDirectory(
    repository_commit_hash: str,
) -> None:
    """Repository URLs without .git or trailing slash still derive the repo name."""
    repository_url = "https://github.com/org/repo"

    asset_directory = utils.construct_repository_asset_directory_name(
        repository_url, repository_commit_hash
    )

    assert asset_directory == f"repo_{repository_commit_hash}"


def testConstructRepositoryArchiveAssetDirectoryName_whenContentUrlHasQueryString_returnsAssetDirectory() -> (
    None
):
    """Archive content URL query strings are ignored when deriving the directory."""
    content_url = "https://example.com/uploads/cc3714?X-Goog-Algorithm=GOO"

    asset_directory = utils.construct_repository_archive_asset_directory_name(
        content_url
    )

    assert asset_directory == "cc3714"


def testConstructRepositoryArchiveAssetDirectoryName_whenUploadUrlHasPathAfterId_returnsUploadId() -> (
    None
):
    """Archive content URLs with extra path segments use the upload id."""
    content_url = "https://example.com/uploads/cc3714/archive/main.zip"

    asset_directory = utils.construct_repository_archive_asset_directory_name(
        content_url
    )

    assert asset_directory == "cc3714"


def testConstructRepositoryArchiveAssetDirectoryName_whenContentUrlHasNoUploadsSegment_raisesValueError() -> (
    None
):
    """Archive content URLs without an `uploads` segment are rejected, not silently accepted."""
    content_url = "https://github.com/org/repo/archive/main.zip"

    with pytest.raises(ValueError):
        utils.construct_repository_archive_asset_directory_name(content_url)


def testConstructRepositoryArchiveAssetDirectoryName_whenUploadsHasNoIdAfter_raisesValueError() -> (
    None
):
    """Archive content URLs ending at `uploads` with no following id are rejected."""
    content_url = "https://example.com/uploads"

    with pytest.raises(ValueError):
        utils.construct_repository_archive_asset_directory_name(content_url)


def testShouldExcludePath_whenPathMatchesWorkspacePattern_shouldReturnTrue() -> None:
    result = utils.should_exclude_path("/workspace/src/main.py", [r"^/workspace(/|$)"])

    assert result is True


def testShouldExcludePath_whenPathDoesNotMatch_shouldReturnFalse() -> None:
    result = utils.should_exclude_path("/tmp/main.py", [r"^/workspace(/|$)"])

    assert result is False


def testShouldExcludePath_whenSimilarPrefixNotUnderWorkspace_shouldReturnFalse() -> (
    None
):
    result = utils.should_exclude_path("/workspace_backup/a.py", [r"^/workspace(/|$)"])

    assert result is False


def testShouldExcludePath_whenPathIsNone_shouldReturnFalse() -> None:
    result = utils.should_exclude_path(None, [r"^/workspace(/|$)"])

    assert result is False


def testShouldExcludePath_whenExcludePathsIsEmpty_shouldReturnFalse() -> None:
    result = utils.should_exclude_path("/workspace/a.py", [])

    assert result is False


def testShouldExcludePath_whenExcludePathsIsNone_shouldReturnFalse() -> None:
    result = utils.should_exclude_path("/workspace/a.py", None)

    assert result is False


def testShouldExcludePath_whenRegexIsInvalid_shouldSkipPatternAndReturnFalse() -> None:
    result = utils.should_exclude_path("/workspace/a.py", ["[invalid("])

    assert result is False


def _express_data_exfiltration_vulnerability(
    lines: str,
    *,
    check_id: str = (
        "javascript.express.security.express-data-exfiltration"
        ".express-data-exfiltration"
    ),
) -> dict[str, Any]:
    """Build a semgrep finding for the express-data-exfiltration rule."""
    return {
        "check_id": check_id,
        "start": {"col": 19, "line": 319, "offset": 0},
        "end": {"col": 56, "line": 319, "offset": 37},
        "path": "/code/961.js",
        "extra": {
            "lines": lines,
            "message": (
                "Depending on the context, user control data in `Object.assign` "
                "can cause web response to include data that it should not have "
                "or can lead to a mass assignment vulnerability."
            ),
            "metadata": {
                "impact": "MEDIUM",
                "technology": ["express"],
                "references": [],
            },
            "metavars": {},
        },
    }


def testIsHttpOptionsAssignExpressDataExfiltration_whenHttpOptionsMerge_returnsTrue() -> (
    None
):
    """Client-side HTTP request options merge is suppressed."""
    vulnerability = _express_data_exfiltration_vulnerability(
        lines=(
            "const n = Object.assign({\n"
            '                                        method: s.method || "GET",\n'
            "                                        headers: s.headers\n"
            "                                    }, i),"
        )
    )

    assert utils.is_http_options_assign_express_data_exfiltration(vulnerability) is True


def testIsHttpOptionsAssignExpressDataExfiltration_whenHeadersBeforeMethod_returnsTrue() -> (
    None
):
    """Property order inside the options literal does not matter."""
    vulnerability = _express_data_exfiltration_vulnerability(
        lines=(
            "const n = Object.assign({ headers: s.headers, "
            'method: s.method || "GET" }, i),'
        )
    )

    assert utils.is_http_options_assign_express_data_exfiltration(vulnerability) is True


def testIsHttpOptionsAssignExpressDataExfiltration_whenGenuineMassAssignment_returnsFalse() -> (
    None
):
    """A genuine server-side mass assignment is still reported."""
    vulnerability = _express_data_exfiltration_vulnerability(
        lines="let data = Object.assign(defaultData, req.query)"
    )

    assert (
        utils.is_http_options_assign_express_data_exfiltration(vulnerability) is False
    )


def testIsHttpOptionsAssignExpressDataExfiltration_whenOptionsLiteralWithoutHeaders_returnsFalse() -> (
    None
):
    """An options literal missing the headers key is still reported."""
    vulnerability = _express_data_exfiltration_vulnerability(
        lines='Object.assign({ method: "GET" }, req.query)'
    )

    assert (
        utils.is_http_options_assign_express_data_exfiltration(vulnerability) is False
    )


def testIsHttpOptionsAssignExpressDataExfiltration_whenOtherRule_returnsFalse() -> None:
    """Findings from other rules are never suppressed by this filter."""
    vulnerability = _express_data_exfiltration_vulnerability(
        lines='Object.assign({ method: s.method || "GET", headers: s.headers }, i),',
        check_id=(
            "javascript.express.security.audit.remote-property-injection"
            ".remote-property-injection"
        ),
    )

    assert (
        utils.is_http_options_assign_express_data_exfiltration(vulnerability) is False
    )


def testIsHttpOptionsAssignExpressDataExfiltration_whenMissingExtra_returnsFalse() -> (
    None
):
    """A finding without `extra` data is never suppressed."""
    vulnerability = _express_data_exfiltration_vulnerability(
        lines='Object.assign({ method: s.method || "GET", headers: s.headers }, i),'
    )
    vulnerability["extra"] = {}

    assert (
        utils.is_http_options_assign_express_data_exfiltration(vulnerability) is False
    )


def testParseResults_whenHttpOptionsMergeFinding_doesNotYieldVulnerability() -> None:
    """Client HTTP options-merge express-data-exfiltration findings are dropped."""
    json_output: dict[str, Any] = {
        "path": "/code/961.js",
        "results": [
            _express_data_exfiltration_vulnerability(
                lines=(
                    "const n = Object.assign({\n"
                    "                                        method: s.method || "
                    '"GET",\n'
                    "                                        headers: s.headers\n"
                    "                                    }, i),"
                )
            )
        ],
    }

    assert next(utils.parse_results(json_output), None) is None


def testParseResults_whenGenuineMassAssignmentFinding_yieldsVulnerability() -> None:
    """Genuine express-data-exfiltration findings are still reported."""
    json_output: dict[str, Any] = {
        "path": "/code/app.js",
        "results": [
            _express_data_exfiltration_vulnerability(
                lines="let data = Object.assign(defaultData, req.query)"
            )
        ],
    }

    vulnerabilities = list(utils.parse_results(json_output))

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].entry.title == "Express Data Exfiltration"
