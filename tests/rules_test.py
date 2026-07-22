"""Tests for the bundled Ostorlab custom semgrep rules."""

import pathlib
import re
from typing import Any

import pytest
import yaml

from agent import semgrep_agent

RULES_DIR = pathlib.Path(semgrep_agent.RULES_DIR)
FILES_DIR = pathlib.Path(__file__).parent / "files"


def _load_rules() -> list[dict[str, Any]]:
    """Load every bundled rule definition from the rules directory.

    Returns:
        A flat list of rule mappings (each a dict), merged from all rule files.
    """
    rules: list[dict[str, Any]] = []
    for rule_file in sorted(RULES_DIR.glob("*.yml")):
        with rule_file.open() as handle:
            loaded = yaml.safe_load(handle)
        rules.extend(loaded.get("rules", []))
    return rules


def _curl_bash_rule() -> dict[str, Any]:
    """Return the curl|bash unpinned-installer rule mapping."""
    for rule in _load_rules():
        if rule.get("id") == "ostorlab.supply-chain.curl-bash-unpinned-installer":
            return rule
    pytest.fail("curl-bash-unpinned-installer rule is missing from the rules dir.")


def testRulesDir_whenResolved_containsAtLeastOneRuleFile() -> None:
    """The bundled rules directory exists and ships at least one rule file."""
    assert RULES_DIR.is_dir() is True
    rule_files = list(RULES_DIR.glob("*.yml"))
    assert len(rule_files) > 0


def testCurlBashRule_whenInspected_hasRequiredSemgrepFields() -> None:
    """The rule exposes the fields the semgrep agent relies on at report time."""
    rule = _curl_bash_rule()

    assert rule.get("languages") == ["generic"]
    assert rule.get("severity") == "WARNING"
    assert isinstance(rule.get("pattern-regex"), str)

    metadata = rule.get("metadata", {})
    assert metadata.get("impact") == "HIGH"
    assert isinstance(metadata.get("cwe"), list)
    assert len(metadata.get("cwe", [])) > 0
    assert isinstance(metadata.get("references"), list)
    assert len(metadata.get("references", [])) > 0


def testCurlBashRule_whenRegexCompiled_matchesUnpinnedInstallerPatterns() -> None:
    """The detection regex flags code piped from curl/wget into a shell."""
    compiled = re.compile(str(_curl_bash_rule()["pattern-regex"]))

    vulnerable_samples = [
        '    - curl --silent "https://example.com/-/raw/main/installer" | bash',
        "curl https://get.example.com/install.sh | sh",
        "wget -qO- https://example.com/install | sudo bash",
        '  curl "https://x.io/r/installer" |sh',
        "curl -fsSL https://x.io/install | zsh",
    ]
    for sample in vulnerable_samples:
        assert compiled.search(sample) is not None, f"expected match: {sample}"


def testCurlBashRule_whenRegexCompiled_doesNotMatchPinnedOrNonShellPatterns() -> None:
    """The detection regex leaves benign, integrity-checked downloads alone."""
    compiled = re.compile(str(_curl_bash_rule()["pattern-regex"]))

    benign_samples = [
        '    - curl --fail --show-error --silent "https://x.io/-/raw/<SHA>/installer" -o installer.sh',
        "    - sha256sum -c installer.sha256",
        "    - bash installer.sh",
        '    - echo "curl https://x.io/install" | tee log.txt',
        "# curl https://example.com/install | bash  (documentation comment)",
    ]
    for sample in benign_samples:
        assert compiled.search(sample) is None, f"unexpected match: {sample}"


def testCurlBashRule_matchesFixtureVulnerableCiFile() -> None:
    """The rule regex fires on the vulnerable fixture and not the pinned one."""
    compiled = re.compile(str(_curl_bash_rule()["pattern-regex"]))

    vulnerable = (FILES_DIR / "unpinned_curl_bash.gitlab-ci.yml").read_text()
    assert compiled.search(vulnerable) is not None

    pinned = (FILES_DIR / "pinned_curl_bash.gitlab-ci.yml").read_text()
    assert compiled.search(pinned) is None
