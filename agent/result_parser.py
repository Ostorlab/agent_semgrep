"""Module to parse semgrep json results."""
import dataclasses
from typing import Dict, Iterator, Any

from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import file


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: agent_report_vulnerability_mixin.RiskRating
    vulnerability_location: agent_report_vulnerability_mixin.VulnerabilityLocation


def construct_technical_detail(
    title: str, description: str, impact: str, references: Dict[str, str]
) -> str:
    """Construct human readable report using vulnerability json

    Args:
        title
        description
        impact
        references

    Returns:
        Technical detail of the vulnerability
    """

    references_list = "\n".join(list(references.values()))

    technical_detail = f"""
```
Vulnerability Report:

Vulnerability: {title}

Impact: {impact}

Description:

{description}

References:

{references_list}
```
"""

    return technical_detail


def parse_results(json_output: Dict[str, Any]) -> Iterator[Vulnerability]:
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

        technical_detail = construct_technical_detail(
            title, description, impact, references
        )

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
            risk_rating=impact,
            vulnerability_location=vuln_location,
        )
