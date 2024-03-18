"""Utilities for Semgrep Agent"""

import dataclasses
import mimetypes
import requests
import logging
import os
import re
from typing import Any, Iterator
from urllib import parse


import tenacity
import magic
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.message import message as m


LINE_SIZE_MAX = 5000
DOWNLOAD_REQUEST_TIMEOUT = 60
NUMBER_RETRIES = 3

RISK_RATING_MAPPING = {
    "UNKNOWN": agent_report_vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": agent_report_vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": agent_report_vulnerability_mixin.RiskRating.HIGH,
}

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: agent_report_vulnerability_mixin.RiskRating


def construct_technical_detail(vulnerability: dict[str, Any], path: str) -> str:
    """Constructs a technical detail paragraph from a Semgrep vulnerability json output.

    Args:
        vulnerability: Semgrep json output of a given vulnerability.
        path: Analyzed file path

    Returns:
        Technical detail paragraph.
    """
    check_id = vulnerability.get("check_id")
    line = vulnerability.get("start", {}).get("line", "N/A")
    col = vulnerability.get("start", {}).get("col", "N/A")
    message = vulnerability["extra"].get("message", "N/A")
    path = path or vulnerability.get("path", "N/A")
    lines = vulnerability["extra"].get("lines", "").strip()[:LINE_SIZE_MAX]
    technology = vulnerability["extra"].get("metadata", {}).get("technology", [""])[0]
    title = construct_vulnerability_title(check_id)

    technical_detail = f"""{title}: {message}
    
The issue was detected in `{path}`, line `{line}`, column `{col}`, below is a code snippet from the vulnerable code
```{technology}
{lines}
```"""

    return technical_detail


def construct_vulnerability_title(check_id: str | None) -> str:
    """Constructs a vulnerability title from Semgrep vulnerability check id.

    Args:
        check_id: Semgrep vulnerability check id.

    Returns:
        vulnerability title.
    """
    if check_id is None:
        raise ValueError("Check ID is not defined")
    return check_id.split(".")[-1].replace("-", " ").title()


def filter_description(description: str) -> str:
    description = re.sub(
        r"RegExp\(\) called with a (.*) function argument",
        "RegExp() called with a function argument",
        description,
    )
    return description


def parse_results(json_output: dict[str, Any]) -> Iterator[Vulnerability]:
    """Parses JSON generated Semgrep results and yield vulnerability entries.

    Args:
        json_output: Semgrep json output.

    Yields:
        Vulnerability entry.
    """

    vulnerabilities = json_output.get("results", [])
    path = json_output.get("path", "")

    for vulnerability in vulnerabilities:
        extra = vulnerability.get("extra", {})
        description = filter_description(extra.get("message", ""))
        title = construct_vulnerability_title(vulnerability.get("check_id"))
        metadata = extra.get("metadata", {})
        impact = metadata.get("impact", "UNKNOWN")
        fix = extra.get("fix", "")
        references = {
            parse.urlparse(value).netloc or value: value
            for value in metadata.get("references", [])
        }

        technical_detail = construct_technical_detail(vulnerability, path)

        yield Vulnerability(
            entry=kb.Entry(
                title=title,
                risk_rating=impact,
                short_description=description,
                description=description,
                references=references,
                recommendation=fix,
                security_issue=True,
                privacy_issue=False,
                has_public_exploit=False,
                targeted_by_malware=False,
                targeted_by_ransomware=False,
                targeted_by_nation_state=False,
            ),
            technical_detail=technical_detail,
            risk_rating=RISK_RATING_MAPPING[impact],
        )


def get_file_type(content: bytes, path: str | None) -> str:
    if path is None:
        mime = magic.from_buffer(content, mime=True)
        file_type = mimetypes.guess_extension(mime)
        return str(file_type)
    else:
        file_split = os.path.splitext(path)[1]
        if len(file_split) < 2:
            return get_file_type(content, None)
        return file_split


@tenacity.retry(
    stop=tenacity.stop_after_attempt(NUMBER_RETRIES),
    retry=tenacity.retry_if_exception_type(requests.exceptions.RequestException),
    retry_error_callback=lambda retry_state: retry_state.outcome.result()
    if retry_state.outcome is not None
    else None,
)
def _download_file(file_url: str) -> bytes | None:
    """Download a file.

    Args:
        file_url : The URL of the file to download.

    Returns:
        bytes: The content of the file.
    """
    response = requests.get(file_url, timeout=DOWNLOAD_REQUEST_TIMEOUT)
    if response.status_code == 200 and isinstance(response.content, bytes) is True:
        return response.content

    return None


def get_file_content(message: m.Message) -> bytes | None:
    """Get the file content from a message.

    Args:
        message : The message containing the file data.

    Returns:
        bytes: The content of the file.
    """
    content = message.data.get("content")
    if isinstance(content, bytes) is True:
        return content
    content_url: str | None = message.data.get("content_url")
    if content_url is not None:
        try:
            content = _download_file(content_url)
        except requests.exceptions.RequestException as e:
            logger.error("Could not download file %s. Error: %s.", content_url, e)
        return content

    return None
