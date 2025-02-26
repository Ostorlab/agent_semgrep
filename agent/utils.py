"""Utilities for Opengrep Agent"""

import dataclasses
import mimetypes
import requests
import logging
import os
import re
from typing import Any, Iterator
from urllib import parse
import json


import tenacity
import magic
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import (
    agent_report_vulnerability_mixin as vulnerability_mixin,
)
from ostorlab.agent.message import message as m
from ostorlab.assets import asset as os_asset
from ostorlab.assets import ios_store
from ostorlab.assets import android_store


LINE_SIZE_MAX = 5000
DOWNLOAD_REQUEST_TIMEOUT = 60
NUMBER_RETRIES = 3

RISK_RATING_MAPPING = {
    "UNKNOWN": vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": vulnerability_mixin.RiskRating.HIGH,
}

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: vulnerability_mixin.RiskRating
    vuln_dna: str
    vulnerability_location: vulnerability_mixin.VulnerabilityLocation | None = None


def construct_technical_detail(vulnerability: dict[str, Any], path: str) -> str:
    """Constructs a technical detail paragraph from a Opengrep vulnerability json output.

    Args:
        vulnerability: Opengrep json output of a given vulnerability.
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
    """Constructs a vulnerability title from Opengrep vulnerability check id.

    Args:
        check_id: Opengrep vulnerability check id.

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


def _sort_dict(dictionary: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Recursively sort dictionary keys and lists within.
    Args:
        dictionary: The dictionary to sort.
    Returns:
        A sorted dictionary or list.
    """
    if isinstance(dictionary, dict):
        return {k: _sort_dict(v) for k, v in sorted(dictionary.items())}
    if isinstance(dictionary, list):
        return sorted(
            dictionary,
            key=lambda x: json.dumps(x, sort_keys=True)
            if isinstance(x, dict)
            else str(x),
        )
    return dictionary


def _compute_vulnerability_dna(
    title: str,
    lines: str,
    vulnerability_location: vulnerability_mixin.VulnerabilityLocation | None,
) -> str:
    """Compute a deterministic, debuggable DNA representation for a vulnerability.
    Args:
        title: Generate KB title.
        lines: the lines where the vulnerability was detected.
        vulnerability_location: the computed vulnerability location.
    Returns:
        A deterministic JSON representation of the vulnerability DNA.
    """
    dna_data: dict[str, Any] = {
        "title": title,
        "lines": lines,
    }

    if vulnerability_location is not None:
        location_dict: dict[str, Any] = vulnerability_location.to_dict()
        sorted_location_dict = _sort_dict(location_dict)
        dna_data["location"] = sorted_location_dict

    return json.dumps(dna_data, sort_keys=True)


def _prepare_vulnerability_location(
    file_path: str, package_name: str | None = None, bundle_id: str | None = None
) -> vulnerability_mixin.VulnerabilityLocation | None:
    """Prepare a `VulnerabilityLocation` instance with iOS asset & its Bundle ID, with file path as vulnerability metadata."""
    if bundle_id is None and package_name is None:
        return None
    asset: os_asset.Asset | None = None
    if bundle_id is not None:
        asset = ios_store.IOSStore(bundle_id=bundle_id)
    if package_name is not None:
        asset = android_store.AndroidStore(package_name=package_name)

    return vulnerability_mixin.VulnerabilityLocation(
        asset=asset,
        metadata=[
            vulnerability_mixin.VulnerabilityLocationMetadata(
                metadata_type=vulnerability_mixin.MetadataType.FILE_PATH,
                value=file_path,
            )
        ],
    )


def parse_results(
    json_output: dict[str, Any],
    package_name: str | None = None,
    bundle_id: str | None = None,
) -> Iterator[Vulnerability]:
    """Parses JSON generated Opengrep results and yield vulnerability entries.

    Args:
        json_output: Opengrep json output.
        package_name: optional application package name to augment the vulnerability location.
        bundle_id: optional bundle identifier to augment the vulnerability location.

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
        path = path or vulnerability.get("path")
        vulnerability_location = None
        if path is not None:
            vulnerability_location = _prepare_vulnerability_location(
                file_path=path, package_name=package_name, bundle_id=bundle_id
            )

        lines = vulnerability["extra"].get("lines", "").strip()[:LINE_SIZE_MAX]

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
            vulnerability_location=vulnerability_location,
            vuln_dna=_compute_vulnerability_dna(title, lines, vulnerability_location),
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
