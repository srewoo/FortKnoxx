"""Extract resource → service mappings from Terraform / CDK / CloudFormation.

A "resource" is anything cloud-tagged: an IAM role, an S3 bucket, an ECR
image, a Lambda function. A "service" is the code repo / module that
deploys it. The mapping is deliberately heuristic — full IaC graph
parsing is out of scope; this is enough to correlate ``service-x``
finding from a SAST scanner with a Prowler finding on the IAM role
``service-x-task-role``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Match "resource <type> <name> {" in Terraform.
_TF_RESOURCE_RE = re.compile(
    r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE
)
# Match "Type: <something>" in a CloudFormation block.
_CFN_TYPE_RE = re.compile(r"^\s*Type:\s*([A-Za-z0-9:]+::[A-Za-z0-9:]+)", re.MULTILINE)


@dataclass
class IaCResource:
    """A cloud resource declared by IaC."""

    iac_type: str          # terraform | cloudformation | cdk
    resource_type: str     # e.g. aws_iam_role
    name: str              # logical name from IaC
    file: str              # source file path
    service_hint: str      # parent directory; best-effort service label
    tags: dict[str, str] = field(default_factory=dict)


def extract_iac_resources(repo_path: str) -> list[IaCResource]:
    """Walk the repo for IaC files and pull declared resources."""
    root = Path(repo_path)
    if not root.is_dir():
        return []

    resources: list[IaCResource] = []
    for tf_file in root.rglob("*.tf"):
        try:
            text = tf_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rtype, rname in _TF_RESOURCE_RE.findall(text):
            resources.append(IaCResource(
                iac_type="terraform",
                resource_type=rtype,
                name=rname,
                file=str(tf_file.relative_to(root)),
                service_hint=tf_file.parent.name,
            ))

    for cfn_file in list(root.rglob("*.yaml")) + list(root.rglob("*.yml")):
        try:
            text = cfn_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "AWSTemplateFormatVersion" not in text and "Resources:" not in text:
            continue
        for rtype in _CFN_TYPE_RE.findall(text):
            resources.append(IaCResource(
                iac_type="cloudformation",
                resource_type=rtype,
                name=cfn_file.stem,
                file=str(cfn_file.relative_to(root)),
                service_hint=cfn_file.parent.name,
            ))

    if resources:
        logger.info("CNAPP IaC scan: found %d resources across %s", len(resources), repo_path)
    return resources
