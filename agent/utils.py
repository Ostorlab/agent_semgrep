"""Utilities for Semgrep Agent"""
import dataclasses
import mimetypes
import os
from typing import Any, Iterator

import magic
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import file

RISK_RATING_MAPPING = {
    "UNKNOWN": agent_report_vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": agent_report_vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": agent_report_vulnerability_mixin.RiskRating.HIGH,
}


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: agent_report_vulnerability_mixin.RiskRating
    vulnerability_location: agent_report_vulnerability_mixin.VulnerabilityLocation


def construct_technical_detail(vulnerability: dict[str, Any], path: str) -> str:
    check_id = vulnerability.get("check_id", "N/A")
    line = vulnerability.get("start", {}).get("line", "N/A")
    col = vulnerability.get("start", {}).get("col", "N/A")
    message = vulnerability["extra"].get("message", "N/A")
    path = path or vulnerability.get("path", "")

    technical_detail = f"""The file `{path}` has a security issue at line `{line}`, column `{col}`.
The issue was identified as `{check_id}` and the message from the code analysis is `{message}`."""

    return technical_detail


def parse_results(json_output: dict[str, Any]) -> Iterator[Vulnerability]:
    """Parses JSON generated Semgrep results and yield vulnerability entries.

    Args:
        json_output: Semgrep json output.

    Yields:
        Vulnerability entry.
    """

    file_path = json_output.get("path", "")

    vulnerabilities = json_output.get("results", [])

    for vulnerability in vulnerabilities:
        extra = vulnerability.get("extra", {})
        description = extra.get("message", "")
        title = description.split(".")[0]
        metadata = extra.get("metadata", {})
        impact = metadata.get("impact", "UNKNOWN")
        fix = extra.get("fix", "")
        references = {
            f"source-{idx + 1}": value
            for (idx, value) in enumerate(metadata.get("references", []))
        }

        technical_detail = construct_technical_detail(vulnerability, file_path)

        vuln_location = agent_report_vulnerability_mixin.VulnerabilityLocation(
            asset=file.File(),
            metadata=[
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    metadata_type=agent_report_vulnerability_mixin.MetadataType.FILE_PATH,
                    value=file_path,
                )
            ],
        )

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
            vulnerability_location=vuln_location,
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
