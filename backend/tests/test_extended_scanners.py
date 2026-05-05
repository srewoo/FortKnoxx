"""
Smoke tests for the extended-coverage scanner wrappers and SARIF
exporter. These tests deliberately do NOT require any of the underlying
CLIs to be installed — they verify that each wrapper degrades gracefully
on a host without the binary, so CI stays green on minimal images.
"""

import asyncio
import sys
from pathlib import Path

import pytest

# Make sure backend/ is importable when tests run from repo root.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanners.osv_scanner import OSVScanner  # noqa: E402
from scanners.cyclonedx_scanner import CycloneDXScanner  # noqa: E402
from scanners.license_scanner import LicenseScanner  # noqa: E402
from scanners.schemathesis_scanner import SchemathesisScanner  # noqa: E402
from scanners.garak_scanner import GarakScanner  # noqa: E402
from scanners.promptfoo_scanner import PromptfooScanner  # noqa: E402
from scanners.prowler_scanner import ProwlerScanner  # noqa: E402
from scanners.kube_bench_scanner import KubeBenchScanner  # noqa: E402
from scanners.kube_hunter_scanner import KubeHunterScanner  # noqa: E402
from exporters.sarif import export as sarif_export  # noqa: E402


WRAPPERS = [
    OSVScanner, CycloneDXScanner, LicenseScanner, SchemathesisScanner,
    GarakScanner, PromptfooScanner, ProwlerScanner, KubeBenchScanner,
    KubeHunterScanner,
]


@pytest.mark.parametrize("scanner_cls", WRAPPERS)
def test_wrapper_skips_when_binary_missing(scanner_cls, tmp_path, monkeypatch):
    """Each wrapper must return [] (never raise) when the CLI is absent."""
    monkeypatch.setattr("shutil.which", lambda _name: None)
    scanner = scanner_cls()
    # is_available() must report False under the patched env.
    assert asyncio.run(scanner.is_available()) is False
    # scan() should return an empty list without raising.
    result = asyncio.run(_call_scan(scanner, tmp_path))
    assert result == []


async def _call_scan(scanner, tmp_path):
    # Each scanner takes a different signature; pick a safe default.
    name = type(scanner).__name__
    if name in {"OSVScanner", "CycloneDXScanner", "LicenseScanner", "PromptfooScanner"}:
        return await scanner.scan(str(tmp_path))
    if name == "SchemathesisScanner":
        return await scanner.scan(str(tmp_path), base_url="http://localhost:0")
    if name == "GarakScanner":
        return await scanner.scan()
    if name == "ProwlerScanner":
        return await scanner.scan(provider="aws")
    if name == "KubeBenchScanner":
        return await scanner.scan()
    if name == "KubeHunterScanner":
        return await scanner.scan()
    raise AssertionError(f"unhandled scanner: {name}")


def test_sarif_exporter_emits_valid_skeleton():
    findings = [
        {
            "id": "CVE-2024-12345",
            "title": "Test vulnerability",
            "description": "Demo CVE",
            "severity": "high",
            "scanner": "osv-scanner",
            "package": "demo",
            "installed_version": "1.0.0",
            "fixed_version": "1.0.1",
            "file_path": "requirements.txt",
            "line_start": 4,
            "references": ["https://example.com/CVE-2024-12345"],
        }
    ]
    log = sarif_export(findings, tool_name="FortKnoxx-test")
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "FortKnoxx-test"
    rule_ids = [r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]]
    assert "CVE-2024-12345" in rule_ids
    result = log["runs"][0]["results"][0]
    assert result["ruleId"] == "CVE-2024-12345"
    assert result["level"] == "error"  # high → error
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "requirements.txt"
    assert loc["region"]["startLine"] == 4
