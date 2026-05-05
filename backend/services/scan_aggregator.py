"""ScanAggregator — turns scanner output into Vulnerability records.

WHY: the per-scanner aggregation loops in `process_scan_results` were
the source of the original `'str' object has no attribute 'get'`
incident (one bad Trivy finding tanked the whole scan). The hardened
versions in server.py kept the bug from recurring, but the loops are
still ~290 LOC of inline code with shared state — hard to test, easy
to break.

This module encapsulates that state and the per-scanner shape
knowledge into a class. Each `add_*` method is independently testable
and resilient: any one bad finding is logged and skipped without
disrupting the rest.

Behaviour parity is the goal — this is a refactor, not a redesign.
The same severity_counts, the same OWASP buckets, the same dict
shapes that go into Mongo today.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from api.schemas import Vulnerability
from services.normalisation import map_to_owasp, normalize_severity
from services.result_safety import safe_findings

logger = logging.getLogger(__name__)


@dataclass
class ScanAggregator:
    """Accumulates findings across many scanners for a single scan.

    Construct with the repo + scan ids, call the per-scanner ``add_*``
    methods in any order, then read the public state attributes when
    the run is done.
    """

    repo_id: str
    scan_id: str

    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    quality_issues: list[dict[str, Any]] = field(default_factory=list)
    compliance_issues: list[dict[str, Any]] = field(default_factory=list)
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    )

    # ----- helpers --------------------------------------------------- #

    def _bump(self, severity: str) -> None:
        if severity not in self.severity_counts:
            severity = "medium"
        self.severity_counts[severity] = self.severity_counts.get(severity, 0) + 1

    def _stamp(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Add the per-row metadata that the Mongo writers expect."""
        return {
            **payload,
            "repo_id": self.repo_id,
            "scan_id": self.scan_id,
            "id": str(uuid.uuid4()),
            "created_at": datetime.now(UTC),
        }

    # ----- structured-output scanners (Semgrep / Gitleaks / Trivy / Checkov) #

    def add_semgrep(self, findings: Iterable[Any]) -> None:
        for finding in safe_findings(findings, "Semgrep"):
            try:
                severity = normalize_severity(finding.get("extra", {}).get("severity", "medium"))
                category = finding.get("check_id", "unknown")
                vuln = Vulnerability(
                    repo_id=self.repo_id,
                    scan_id=self.scan_id,
                    file_path=finding.get("path", "unknown"),
                    line_start=finding.get("start", {}).get("line", 0),
                    line_end=finding.get("end", {}).get("line", 0),
                    severity=severity,
                    category=category,
                    owasp_category=map_to_owasp(category, finding.get("extra", {}).get("message", ""), ""),
                    title=finding.get("extra", {}).get("message", "Security Issue"),
                    description=finding.get("extra", {}).get("message", ""),
                    code_snippet=finding.get("extra", {}).get("lines", ""),
                    detected_by="Semgrep",
                )
                self.vulnerabilities.append(vuln.model_dump())
                self._bump(severity)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process Semgrep finding, skipping: %s", exc)

    def add_gitleaks(self, findings: Iterable[Any]) -> None:
        for secret in safe_findings(findings, "Gitleaks"):
            try:
                vuln = Vulnerability(
                    repo_id=self.repo_id,
                    scan_id=self.scan_id,
                    file_path=secret.get("File", "unknown"),
                    line_start=secret.get("StartLine", 0),
                    line_end=secret.get("EndLine", 0),
                    severity="critical",
                    category="secret-exposure",
                    owasp_category="A02",
                    title=f"Secret Detected: {secret.get('Description', 'Unknown')}",
                    description=f"Secret found: {secret.get('Secret', '')[:20]}...",
                    code_snippet=secret.get("Secret", "")[:50],
                    detected_by="Gitleaks",
                )
                self.vulnerabilities.append(vuln.model_dump())
                self._bump("critical")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process Gitleaks finding, skipping: %s", exc)

    def add_trivy(self, findings: Iterable[Any]) -> None:
        for dep in safe_findings(findings, "Trivy"):
            try:
                severity = normalize_severity(dep.get("Severity", "MEDIUM"))
                cvss_field = dep.get("CVSS")
                cvss_score = None
                if isinstance(cvss_field, dict):
                    nvd = cvss_field.get("nvd")
                    if isinstance(nvd, dict):
                        cvss_score = nvd.get("V3Score")
                cwe_ids = dep.get("CweIDs") or []
                cwe = cwe_ids[0] if isinstance(cwe_ids, list) and cwe_ids else None
                vuln = Vulnerability(
                    repo_id=self.repo_id,
                    scan_id=self.scan_id,
                    file_path=dep.get("PkgName", "dependency"),
                    line_start=0,
                    line_end=0,
                    severity=severity,
                    category="vulnerable-dependency",
                    owasp_category="A06",
                    title=dep.get("Title", "Vulnerable Dependency"),
                    description=dep.get("Description", ""),
                    code_snippet=f"{dep.get('PkgName', '')}@{dep.get('InstalledVersion', '')}",
                    cwe=cwe,
                    cvss_score=cvss_score,
                    detected_by="Trivy",
                )
                self.vulnerabilities.append(vuln.model_dump())
                self._bump(severity)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process Trivy finding, skipping: %s", exc)

    def add_checkov(self, findings: Iterable[Any]) -> None:
        for check in safe_findings(findings, "Checkov"):
            try:
                severity = normalize_severity(
                    check.get("check_result", {}).get("result", {}).get("severity", "MEDIUM")
                )
                file_line_range = check.get("file_line_range") or [0, 0]
                if not isinstance(file_line_range, list) or len(file_line_range) < 2:
                    file_line_range = [0, 0]
                evaluated_keys = check.get("check_result", {}).get("result", {}).get("evaluated_keys") or [""]
                description = evaluated_keys[0] if isinstance(evaluated_keys, list) and evaluated_keys else ""
                vuln = Vulnerability(
                    repo_id=self.repo_id,
                    scan_id=self.scan_id,
                    file_path=check.get("file_path", "unknown"),
                    line_start=file_line_range[0],
                    line_end=file_line_range[1],
                    severity=severity,
                    category="iac-misconfiguration",
                    owasp_category="A05",
                    title=check.get("check_name", "IaC Misconfiguration"),
                    description=description,
                    code_snippet="",
                    detected_by="Checkov",
                )
                self.vulnerabilities.append(vuln.model_dump())
                self._bump(severity)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process Checkov finding, skipping: %s", exc)

    # ----- dict-style scanners (already shaped like a Vulnerability dict) ---

    def _add_dict_findings(
        self,
        findings: Iterable[Any],
        scanner_name: str,
        *,
        target: list[dict[str, Any]],
        default_severity: str = "medium",
        bump_severity: bool = True,
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        for finding in safe_findings(findings, scanner_name):
            try:
                stamped = self._stamp(finding)
                if extra_fields:
                    stamped.update(extra_fields)
                target.append(stamped)
                if bump_severity:
                    self._bump(normalize_severity(finding.get("severity", default_severity)))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process %s finding, skipping: %s", scanner_name, exc)

    def add_bandit(self, findings: Iterable[Any]) -> None:
        self._add_dict_findings(findings, "Bandit", target=self.vulnerabilities)

    def add_trufflehog(self, findings: Iterable[Any]) -> None:
        self._add_dict_findings(
            findings, "TruffleHog", target=self.vulnerabilities, default_severity="critical"
        )

    def add_grype(self, findings: Iterable[Any]) -> None:
        self._add_dict_findings(findings, "Grype", target=self.vulnerabilities)

    def add_eslint(self, findings: Iterable[Any]) -> None:
        self._add_dict_findings(findings, "ESLint", target=self.vulnerabilities)

    def add_nuclei(self, findings: Iterable[Any]) -> None:
        self._add_dict_findings(findings, "Nuclei", target=self.vulnerabilities)

    def add_enhanced_security(self, findings: Iterable[Any]) -> None:
        """Snyk / gosec / cargo-audit / spotbugs / pyre / zap / api-fuzzer / horusec."""
        self._add_dict_findings(findings, "Enhanced", target=self.vulnerabilities)

    def add_dep_audit(self, findings: Iterable[Any]) -> None:
        """pip-audit + npm-audit consolidated stream."""
        self._add_dict_findings(findings, "DepAudit", target=self.vulnerabilities)

    def add_quality(self, findings: Iterable[Any]) -> None:
        """Pylint, Flake8, Radon, ShellCheck, Hadolint, SQLFluff, pydeps."""
        self._add_dict_findings(
            findings,
            "Quality",
            target=self.quality_issues,
            bump_severity=False,
            extra_fields={"issue_type": "quality"},
        )

    def add_compliance(self, findings: Iterable[Any]) -> None:
        """Syft license-compliance findings."""
        self._add_dict_findings(
            findings,
            "Syft",
            target=self.compliance_issues,
            bump_severity=False,
            extra_fields={"issue_type": "compliance"},
        )

    # ----- AI-typed scanners (objects, not dicts) ------------------- #

    def add_zero_day(self, anomalies: Iterable[Any]) -> None:
        for anomaly in anomalies or []:
            try:
                vuln = Vulnerability(
                    repo_id=self.repo_id,
                    scan_id=self.scan_id,
                    file_path=anomaly.file_path,
                    line_start=anomaly.line_number,
                    line_end=anomaly.line_number,
                    severity=anomaly.severity,
                    category=f"zero-day-{anomaly.type}",
                    owasp_category=map_to_owasp(anomaly.type, anomaly.description, ""),
                    title=anomaly.title,
                    description=(
                        f"{anomaly.description}\n\n"
                        f"Anomaly Score: {anomaly.anomaly_score:.2f}\n"
                        f"Confidence: {anomaly.confidence:.2f}"
                    ),
                    code_snippet=anomaly.code_snippet,
                    detected_by="Zero-Day Detector (AI)",
                )
                self.vulnerabilities.append(vuln.model_dump())
                self._bump(anomaly.severity)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process Zero-Day finding, skipping: %s", exc)

    def add_business_logic(self, violations: Iterable[Any]) -> None:
        for violation in violations or []:
            try:
                vuln = Vulnerability(
                    repo_id=self.repo_id,
                    scan_id=self.scan_id,
                    file_path=violation.file_path,
                    line_start=violation.line_number,
                    line_end=violation.line_number,
                    severity=violation.severity,
                    category=f"business-logic-{violation.type}",
                    owasp_category=map_to_owasp(violation.type, violation.description, ""),
                    title=violation.title,
                    description=(
                        f"{violation.description}\n\n"
                        f"**Attack Scenario:**\n{violation.attack_scenario}\n\n"
                        f"**Recommendation:**\n{violation.recommendation}"
                    ),
                    code_snippet=violation.proof_of_concept or f"Endpoint: {violation.endpoint}",
                    detected_by="Business Logic Scanner (AI)",
                )
                self.vulnerabilities.append(vuln.model_dump())
                self._bump(violation.severity)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process Business Logic finding, skipping: %s", exc)

    def add_llm_security(self, vulns: Iterable[Any]) -> None:
        for llm_vuln in vulns or []:
            try:
                vuln = Vulnerability(
                    repo_id=self.repo_id,
                    scan_id=self.scan_id,
                    file_path=llm_vuln.endpoint_file,
                    line_start=llm_vuln.endpoint_line,
                    line_end=llm_vuln.endpoint_line,
                    severity=llm_vuln.severity,
                    category=f"llm-security-{llm_vuln.vulnerability_type}",
                    owasp_category="A03",
                    title=llm_vuln.title,
                    description=(
                        f"{llm_vuln.description}\n\n**Risk Assessment:**\n"
                        f"- Jailbreak Risk: {llm_vuln.jailbreak_risk:.2%}\n"
                        f"- Data Leak Probability: {llm_vuln.data_leak_probability:.2%}\n"
                        f"- Permission Abuse Risk: {llm_vuln.permission_abuse_risk:.2%}\n\n"
                        f"**Remediation:**\n{llm_vuln.remediation}"
                    ),
                    code_snippet=f"Successful Payload:\n{llm_vuln.successful_payload[:200]}...",
                    detected_by="LLM Security Scanner (AI)",
                )
                self.vulnerabilities.append(vuln.model_dump())
                self._bump(llm_vuln.severity)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process LLM Security finding, skipping: %s", exc)

    def add_auth_scanner(self, vulns: Iterable[Any]) -> None:
        for auth_vuln in vulns or []:
            try:
                vuln = Vulnerability(
                    repo_id=self.repo_id,
                    scan_id=self.scan_id,
                    file_path=auth_vuln.file_path,
                    line_start=auth_vuln.line_number,
                    line_end=auth_vuln.line_number,
                    severity=auth_vuln.severity,
                    category=f"auth-{auth_vuln.type}",
                    owasp_category="A07",
                    title=auth_vuln.title,
                    description=(
                        f"{auth_vuln.description}\n\n"
                        f"**Attack Scenario:**\n{auth_vuln.attack_scenario}\n\n"
                        f"**Remediation:**\n{auth_vuln.remediation}\n\n"
                        f"**Confidence:** {auth_vuln.confidence:.0%}"
                    ),
                    code_snippet=auth_vuln.code_snippet or "",
                    detected_by="Auth Scanner (AI)",
                )
                self.vulnerabilities.append(vuln.model_dump())
                self._bump(auth_vuln.severity)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process Auth Scanner finding, skipping: %s", exc)

    # ----- finalisation --------------------------------------------- #

    def recompute_severity_counts(self) -> None:
        """Rebuild severity_counts from `self.vulnerabilities`.

        Called after upstream code (false-positive filter,
        context-analyzer prioritization) has reshaped the
        vulnerabilities list. Uses normalize_severity to handle
        non-string severities written by older scanners.
        """
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in self.vulnerabilities:
            sev = normalize_severity(vuln.get("severity", "medium"))
            if sev not in counts:
                sev = "medium"
            vuln["severity"] = sev
            counts[sev] += 1
        self.severity_counts = counts
