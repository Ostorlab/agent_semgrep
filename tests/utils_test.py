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


def _direct_use_of_jinja2_vulnerability(
    lines: str,
    *,
    check_id: str = "python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2",
) -> dict[str, Any]:
    """Build a direct-use-of-jinja2 finding for the given matched lines."""
    return {"check_id": check_id, "extra": {"lines": lines}}


def testIsAutoescapeEnabledDirectUseOfJinja2_whenAutoescapeTrue_returnsTrue() -> None:
    """An Environment(autoescape=True) construct does not bypass HTML escaping."""
    vulnerability = _direct_use_of_jinja2_vulnerability(
        "page = Environment(autoescape=True).from_string(test_html).render("
    )

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is True


def testIsAutoescapeEnabledDirectUseOfJinja2_whenAutoescapeTrueInNestedLoader_returnsTrue() -> (
    None
):
    """Autoescape=True is detected even when the constructor carries other arguments."""
    vulnerability = _direct_use_of_jinja2_vulnerability(
        "env = Environment(loader=FileSystemLoader('.'), autoescape=True)"
    )

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is True


def testIsAutoescapeEnabledDirectUseOfJinja2_whenJinja2Prefixed_returnsTrue() -> None:
    """The jinja2.Environment(autoescape=True) form is also autoescaping."""
    vulnerability = _direct_use_of_jinja2_vulnerability(
        "env = jinja2.Environment(autoescape=True)"
    )

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is True


def testIsAutoescapeEnabledDirectUseOfJinja2_whenAutoescapeFalse_returnsFalse() -> None:
    """Autoescaping explicitly disabled is not suppressed."""
    vulnerability = _direct_use_of_jinja2_vulnerability(
        "page = Environment(autoescape=False).from_string(test_html).render("
    )

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is False


def testIsAutoescapeEnabledDirectUseOfJinja2_whenNoAutoescapeArg_returnsFalse() -> None:
    """An Environment() without autoescape keeps the XSS warning."""
    vulnerability = _direct_use_of_jinja2_vulnerability(
        "page = Environment().from_string(test_html).render("
    )

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is False


def testIsAutoescapeEnabledDirectUseOfJinja2_whenOtherRule_returnsFalse() -> None:
    """Findings for other rules are never suppressed."""
    vulnerability = _direct_use_of_jinja2_vulnerability(
        "page = Environment(autoescape=True).from_string(test_html).render(",
        check_id="python.lang.security.audit.mako-templates-detected.mako-templates-detected",
    )

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is False


def testParseResults_whenAutoescapeEnabledDirectJinja2_isSuppressed() -> None:
    """An autoescaping Environment finding is filtered out of the results."""
    semgrep_json_output = {
        "results": [
            _direct_use_of_jinja2_vulnerability(
                "page = Environment(autoescape=True).from_string(test_html).render("
            )
        ],
        "path": "/code/app.py",
    }

    assert next(utils.parse_results(semgrep_json_output), None) is None


def testParseResults_whenAutoescapeNotEnabledDirectJinja2_isReported() -> None:
    """An Environment() without autoescape still yields a finding."""
    semgrep_json_output = {
        "results": [
            _direct_use_of_jinja2_vulnerability(
                "page = Environment().from_string(test_html).render("
            )
        ],
        "path": "/code/app.py",
    }

    vulnerabilities = list(utils.parse_results(semgrep_json_output))

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].entry.title == "Direct Use Of Jinja2"


@pytest.mark.parametrize(
    "lines",
    [
        "Environment(\n    loader=loader,\n    # autoescape=True\n)",
        'Environment("autoescape=True")',
        'Environment("text, autoescape=True")',
        "Environment(loader=Loader(autoescape=True))",
        "Environment(autoescape=TrueValue)",
        "Environment(autoescape=True and False)",
        "Environment(autoescape=True if flag else False)",
        "Environment(autoescape=True, **options)",
        "# Environment(autoescape=True)\nEnvironment()",
        "'Environment(autoescape=True)'; Environment()",
        "Environment(",
    ],
)
def testIsAutoescapeEnabledDirectUseOfJinja2_whenSettingIsNotTrueKeyword_returnsFalse(
    lines: str,
) -> None:
    vulnerability = {
        "check_id": "python.flask.security.direct-use-of-jinja2.direct-use-of-jinja2",
        "extra": {"lines": lines},
    }

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is False


@pytest.mark.parametrize(
    "lines",
    [
        "safe = Environment(autoescape=True); unsafe = Environment()",
        "unsafe = Environment(); safe = Environment(autoescape=True)",
        "Environment(autoescape=True); Environment(autoescape=False)",
        "Environment(autoescape=False); Environment(autoescape=True)",
        "Environment(loader=Environment(), autoescape=True)",
        "Environment(loader=Environment(autoescape=True))",
        "Environment(loader=Loader(Environment()), autoescape=True)",
        "Environment(autoescape=True); Environment(",
        "Environment(); Environment(autoescape=True).render(",
    ],
)
def testParseResults_whenAnyJinjaConstructorIsUnsafe_retainsFinding(
    lines: str,
) -> None:
    """A safe sibling or outer constructor cannot hide an unsafe constructor."""
    vulnerability = _direct_use_of_jinja2_vulnerability(lines)
    semgrep_json_output = {"results": [vulnerability], "path": "/code/app.py"}

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is False
    vulnerabilities = list(utils.parse_results(semgrep_json_output))
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].entry.title == "Direct Use Of Jinja2"


@pytest.mark.parametrize(
    "lines",
    [
        "Environment(autoescape=True); jinja2.Environment(autoescape=True)",
        "Environment(loader=Environment(autoescape=True), autoescape=True)",
        "Environment(autoescape=True); Environment(autoescape=True).render(",
        "Environment(autoescape=True) # Environment()",
        'Environment(autoescape=True).from_string("Environment()").render(',
    ],
)
def testParseResults_whenAllJinjaConstructorsAreSafe_suppressesFinding(
    lines: str,
) -> None:
    """Safe constructors remain suppressible, including truncated render snippets."""
    vulnerability = _direct_use_of_jinja2_vulnerability(lines)
    semgrep_json_output = {"results": [vulnerability], "path": "/code/app.py"}

    assert utils.is_autoescape_enabled_direct_use_of_jinja2(vulnerability) is True
    assert list(utils.parse_results(semgrep_json_output)) == []
