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


def _logger_credential_disclosure_vulnerability(
    lines: str,
    *,
    format_string: str | None = None,
    check_id: str = (
        "python.lang.security.audit.logging.python-logger-credential-disclosure"
    ),
) -> dict[str, Any]:
    """Build a python-logger-credential-disclosure finding mirroring the registry
    check id and the `$FORMAT_STRING` metavariable the rule captures."""
    metavars = {
        "$LOGGER_OBJ": {"abstract_content": "logger"},
        "$LOGGER_CALL": {"abstract_content": "warning"},
    }
    if format_string is not None:
        metavars["$FORMAT_STRING"] = {"abstract_content": format_string}
    return {
        "check_id": check_id,
        "path": "logger.py",
        "start": {"line": 1, "col": 1},
        "end": {"line": 5, "col": 1},
        "extra": {
            "lines": lines,
            "message": "Detected a python logger call with a potential hardcoded "
            "secret being logged.",
            "metavars": metavars,
            "metadata": {"technology": ["python"], "impact": "MEDIUM"},
            "severity": "WARNING",
        },
    }


LOGGER_CREDENTIAL_FP_LINES = (
    "logger.warning(\n"
    '    "oauth_refresh.token_url_missing connector_id=%s tenant=%s '
    'connector_type=%s",\n'
    "    connector.id,\n"
    "    tenant_id,\n"
    "    connector_type,\n"
    ")"
)
LOGGER_CREDENTIAL_FP_FORMAT_STRING = (
    '"oauth_refresh.token_url_missing connector_id=%s tenant=%s connector_type=%s"'
)


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenKeywordEmbedded_returnsTrue() -> (
    None
):
    """The credential keyword only appears inside the event identifier
    token_url_missing, so the finding is a false positive."""
    vulnerability = _logger_credential_disclosure_vulnerability(
        LOGGER_CREDENTIAL_FP_LINES,
        format_string=LOGGER_CREDENTIAL_FP_FORMAT_STRING,
    )

    assert utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is True


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenMetavarMissing_returnsTrue() -> (
    None
):
    """Without the $FORMAT_STRING metavar the format string is recovered from the
    matched lines, so the embedded-keyword finding is still suppressed."""
    vulnerability = _logger_credential_disclosure_vulnerability(
        LOGGER_CREDENTIAL_FP_LINES
    )

    assert utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is True


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenStandaloneToken_returnsFalse() -> (
    None
):
    """A format string naming the credential as a standalone word is a genuine
    disclosure and must stay reported."""
    vulnerability = _logger_credential_disclosure_vulnerability(
        'logger.info("token: %s", token)',
        format_string='"token: %s"',
    )

    assert (
        utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is False
    )


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenStandaloneApiKey_returnsFalse() -> (
    None
):
    """The upstream rule's own `api key %s` test case is not suppressed."""
    vulnerability = _logger_credential_disclosure_vulnerability(
        'logger.error("api call using api key %s failed", api_key)',
        format_string='"api call using api key %s failed"',
    )

    assert (
        utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is False
    )


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenStandaloneSecret_returnsFalse() -> (
    None
):
    """The upstream rule's own `my secret value: %s` test case is not suppressed."""
    vulnerability = _logger_credential_disclosure_vulnerability(
        'logger.info("here is my secret value: %s", secret)',
        format_string='"here is my secret value: %s"',
    )

    assert (
        utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is False
    )


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenStandalonePassword_returnsFalse() -> (
    None
):
    """A format string logging a password with a standalone keyword is not suppressed."""
    vulnerability = _logger_credential_disclosure_vulnerability(
        'logger.debug("password: %s", password)',
        format_string='"password: %s"',
    )

    assert (
        utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is False
    )


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenSingleQuotedFormatString_returnsTrue() -> (
    None
):
    """Single-quoted format strings are handled the same way."""
    vulnerability = _logger_credential_disclosure_vulnerability(
        "logger.warning('oauth_refresh.token_url_missing connector_id=%s', cid)",
        format_string="'oauth_refresh.token_url_missing connector_id=%s'",
    )

    assert utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is True


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenOtherRule_returnsFalse() -> (
    None
):
    """The suppression is scoped to the python-logger-credential-disclosure rule."""
    vulnerability = _logger_credential_disclosure_vulnerability(
        LOGGER_CREDENTIAL_FP_LINES,
        format_string=LOGGER_CREDENTIAL_FP_FORMAT_STRING,
        check_id="python.lang.security.audit.some-other-rule",
    )

    assert (
        utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is False
    )


def testIsEmbeddedKeywordLoggerCredentialDisclosure_whenNoExtra_returnsFalse() -> None:
    """A finding with no extractable format string is never suppressed."""
    vulnerability = {
        "check_id": "python.lang.security.audit.logging.python-logger-credential-disclosure"
    }

    assert (
        utils.is_embedded_keyword_logger_credential_disclosure(vulnerability) is False
    )


def testParseResults_whenLoggerCredentialKeywordEmbedded_suppressesFinding() -> None:
    """The exact false positive observed on AiSOC-main is not reported."""
    json_output = {
        "results": [
            _logger_credential_disclosure_vulnerability(
                LOGGER_CREDENTIAL_FP_LINES,
                format_string=LOGGER_CREDENTIAL_FP_FORMAT_STRING,
            )
        ],
        "path": "logger.py",
    }

    assert list(utils.parse_results(json_output)) == []


def testParseResults_whenLoggerCredentialKeywordEmbeddedWithoutMetavar_suppressesFinding() -> (
    None
):
    """The same false positive is suppressed through the lines fallback."""
    json_output = {
        "results": [
            _logger_credential_disclosure_vulnerability(LOGGER_CREDENTIAL_FP_LINES)
        ],
        "path": "logger.py",
    }

    assert list(utils.parse_results(json_output)) == []


def testParseResults_whenLoggerLogsStandaloneToken_keepsFinding() -> None:
    """A genuine token disclosure still yields the vulnerability."""
    json_output = {
        "results": [
            _logger_credential_disclosure_vulnerability(
                'logger.info("token: %s", token)',
                format_string='"token: %s"',
            )
        ],
        "path": "logger.py",
    }

    findings = list(utils.parse_results(json_output))

    assert len(findings) == 1
    assert findings[0].entry.title == "Python Logger Credential Disclosure"


def testParseResults_whenLoggerCredentialKeywordEmbeddedOtherRule_keepsFinding() -> (
    None
):
    """Findings from other rules with the same lines are still reported."""
    json_output = {
        "results": [
            _logger_credential_disclosure_vulnerability(
                LOGGER_CREDENTIAL_FP_LINES,
                format_string=LOGGER_CREDENTIAL_FP_FORMAT_STRING,
                check_id="python.lang.security.audit.some-other-rule",
            )
        ],
        "path": "logger.py",
    }

    assert len(list(utils.parse_results(json_output))) == 1


@pytest.mark.parametrize(
    "label",
    [
        "credentials",
        "tokens",
        "secrets",
        "passwords",
        "api keys",
        "access_token",
        "refresh_token",
        "client_secret",
        "user_password",
        "auth_token",
        "bearer_token",
        "mytoken",
        "token_url_missing token",
        "token_url_missing access_token",
        "token_url_missing credentials",
    ],
)
def testParseResults_whenCredentialNameIsPluralOrCompound_keepsFinding(
    label: str,
) -> None:
    format_string = f"{label}: %s"
    finding = _logger_credential_disclosure_vulnerability(
        f'logger.info("{format_string}", value)', format_string=format_string
    )

    assert (
        len(list(utils.parse_results({"results": [finding], "path": "logger.py"}))) == 1
    )


_POSTMESSAGE_ORIGIN_VALIDATION_CHECK_ID = (
    "javascript.browser.security.insufficient-postmessage-origin-validation."
    "insufficient-postmessage-origin-validation"
)


def _postmessage_origin_vulnerability(
    lines: str,
    *,
    check_id: str = _POSTMESSAGE_ORIGIN_VALIDATION_CHECK_ID,
) -> dict[str, Any]:
    """Build a semgrep finding for the postmessage-origin-validation rule."""
    return {
        "check_id": check_id,
        "start": {"line": 85, "col": 1},
        "extra": {
            "message": "No validation of origin is done by the addEventListener API.",
            "lines": lines,
            "metadata": {
                "technology": ["browser"],
                "impact": "LOW",
                "references": [],
            },
            "fix": "",
        },
        "path": "/code/static_ad_volume.js",
    }


SCOPED_SDK_MUTE_HANDLER_LINES = """window.addEventListener("message", event => {
    const data = event.data;
    if (typeof data === "object" && data !== null && data.command === "nimbusMute" && typeof data.muted === "boolean") {
        window.nimbus.muted = data.muted;
        event.stopImmediatePropagation()
    }
});"""


def testIsScopedMessageHandler_whenScopedSdkMuteHandler_returnsTrue() -> None:
    """A message handler scoped to a fixed command that only toggles a mute flag is benign."""
    vulnerability = _postmessage_origin_vulnerability(SCOPED_SDK_MUTE_HANDLER_LINES)

    assert (
        utils.is_scoped_message_handler_insufficient_postmessage_origin_validation(
            vulnerability
        )
        is True
    )


def testParseResults_whenScopedSdkMuteHandler_emitsNoVulnerability() -> None:
    """The scoped SDK mute handler FP is suppressed end to end."""
    json_output = {
        "path": "/code/static_ad_volume.js",
        "results": [_postmessage_origin_vulnerability(SCOPED_SDK_MUTE_HANDLER_LINES)],
    }

    assert list(utils.parse_results(json_output)) == []


def testIsScopedMessageHandler_whenDataReachesSink_returnsFalse() -> None:
    """A handler writing message data into the DOM without any guard is still reported."""
    lines = """window.addEventListener("message", event => {
    document.getElementById("content").innerHTML = event.data.html;
});"""
    vulnerability = _postmessage_origin_vulnerability(lines)

    assert (
        utils.is_scoped_message_handler_insufficient_postmessage_origin_validation(
            vulnerability
        )
        is False
    )


def testParseResults_whenDataReachesSink_stillEmitsVulnerability() -> None:
    """A genuine postmessage XSS handler is still reported."""
    lines = """window.addEventListener("message", event => {
    document.getElementById("content").innerHTML = event.data.html;
});"""
    json_output = {
        "path": "/code/app.js",
        "results": [_postmessage_origin_vulnerability(lines)],
    }

    result = list(utils.parse_results(json_output))

    assert len(result) == 1
    assert result[0].entry.title == "Insufficient Postmessage Origin Validation"


def testIsScopedMessageHandler_whenCommandGuardButNavigation_returnsFalse() -> None:
    """A command-guarded handler that navigates from message data is still reported."""
    lines = """window.addEventListener("message", event => {
    if (event.data.command === "loadUrl") {
        window.location = event.data.url;
    }
});"""
    vulnerability = _postmessage_origin_vulnerability(lines)

    assert (
        utils.is_scoped_message_handler_insufficient_postmessage_origin_validation(
            vulnerability
        )
        is False
    )


def testIsScopedMessageHandler_whenOtherRule_returnsFalse() -> None:
    """The filter never suppresses a different check id."""
    vulnerability = _postmessage_origin_vulnerability(
        SCOPED_SDK_MUTE_HANDLER_LINES,
        check_id="javascript.browser.security.eval-detected.eval-detected",
    )

    assert (
        utils.is_scoped_message_handler_insufficient_postmessage_origin_validation(
            vulnerability
        )
        is False
    )


def testIsScopedMessageHandler_whenLinesMissing_returnsFalse() -> None:
    """A finding without matched lines is never suppressed."""
    vulnerability = {"check_id": _POSTMESSAGE_ORIGIN_VALIDATION_CHECK_ID}

    assert (
        utils.is_scoped_message_handler_insufficient_postmessage_origin_validation(
            vulnerability
        )
        is False
    )


@pytest.mark.parametrize(
    "sink",
    [
        'document.getElementById("ad").innerHTML = data.html;',
        "eval(data.code);",
        "document.write(data.html);",
        "window.location.href = data.url;",
        "window.location = data.url;",
        'element.insertAdjacentHTML("beforeend", data.html);',
        "frame.src = data.url;",
        "link.href = data.url;",
        'element["innerHTML"] = data.html;',
        'element.setAttribute("src", data.url);',
        "setTimeout(data.code, 0);",
        "Function(data.code)();",
        "frame.srcdoc = data.html;",
        "window.open(data.url);",
        "$('#ad').html(data.html);",
        "handleMessage(data);",
    ],
)
def testParseResults_whenMuteHandlerAlsoContainsSink_keepsFinding(sink: str) -> None:
    lines = SCOPED_SDK_MUTE_HANDLER_LINES.replace(
        "window.nimbus.muted = data.muted;",
        f"window.nimbus.muted = data.muted;\n{sink}",
    )
    result = list(
        utils.parse_results(
            {
                "path": "/code/app.js",
                "results": [_postmessage_origin_vulnerability(lines)],
            }
        )
    )

    assert len(result) == 1
    assert result[0].entry.title == "Insufficient Postmessage Origin Validation"
