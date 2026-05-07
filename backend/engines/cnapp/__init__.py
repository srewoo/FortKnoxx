"""CNAPP-lite — code↔cloud correlation built on top of existing scanners.

Wraps Prowler / ScoutSuite / CloudSploit / Steampipe + Trivy / Grype / Syft
into a single ``cloud_scan()`` job, then correlates cloud findings with
code findings using IaC-extracted resource → service mappings.

Goals:
  • Free (only OSS tools, no SaaS dependencies).
  • Doesn't try to be Wiz; just gives users one report that says
    "service-x has CVE-Y AND its IAM role has *:*".
  • SBOM watch loop: nightly diff of stored SBOMs vs Grype's CVE feed
    so newly-published CVEs surface even without a code re-scan.
"""

from .correlator import correlate_findings
from .iac_resources import extract_iac_resources

__all__ = ["correlate_findings", "extract_iac_resources"]
