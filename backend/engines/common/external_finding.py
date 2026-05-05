"""
Shared finding dataclass used by external-tool wrapper engines (SCA, secrets,
SBOM/license, DAST, API fuzz, LLM red-team, cloud, k8s).

Each wrapper engine produces ExternalToolFinding instances. The unified
scanner funnels them through SchemaConverter.convert_generic to produce
Universal Vulnerability Schema (UVS) records.

Tool integrations are intentionally graceful: if the underlying CLI / package
is not installed, the engine logs and returns an empty list rather than
raising — keeping FortKnoxx usable in minimal installs.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class ExternalToolFinding:
    """Normalized finding produced by external-tool wrappers."""

    # Stable identifier from the upstream tool (CVE-id, rule-id, plugin-id, …)
    finding_id: str
    title: str
    description: str

    # Severity values are normalised to one of: critical, high, medium, low, info
    severity: str = "medium"

    # Which engine produced this finding (e.g. "sca", "secrets", "dast.zap")
    source: str = "external"

    # Confidence 0.0–1.0; default 0.85 for well-known tools, 0.6 for heuristics
    confidence: float = 0.85

    # Location
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    url: Optional[str] = None

    # Classification
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

    # Dependency / SCA context
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    ecosystem: Optional[str] = None  # pypi, npm, go, maven, …

    # Remediation
    recommended_fix: Optional[str] = None
    references: List[str] = field(default_factory=list)

    # Free-form tool-specific payload (kept for traceability / SARIF export)
    metadata: Dict[str, Any] = field(default_factory=dict)
