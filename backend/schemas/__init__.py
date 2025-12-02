"""
Universal Vulnerability Schema for FortKnoxx
Standardized vulnerability representation across all scanners
"""

from .uvs import (
    UniversalVulnerability,
    VulnerabilityCategory,
    VulnerabilitySeverity,
    ExploitabilityLevel,
    Remediation,
    OWASPMapping,
    CWEMapping
)

__all__ = [
    "UniversalVulnerability",
    "VulnerabilityCategory",
    "VulnerabilitySeverity",
    "ExploitabilityLevel",
    "Remediation",
    "OWASPMapping",
    "CWEMapping"
]
