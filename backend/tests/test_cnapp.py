"""Unit tests for CNAPP-lite IaC extraction + correlation."""

from __future__ import annotations

from pathlib import Path

from engines.cnapp.correlator import correlate_findings
from engines.cnapp.iac_resources import IaCResource, extract_iac_resources


def test_extract_terraform_resources(tmp_path: Path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_iam_role" "payments_role" {}\n'
        'resource "aws_s3_bucket" "logs" {}\n'
    )
    res = extract_iac_resources(str(tmp_path))
    types = {r.resource_type for r in res}
    names = {r.name for r in res}
    assert types == {"aws_iam_role", "aws_s3_bucket"}
    assert names == {"payments_role", "logs"}


def test_extract_cloudformation_resources(tmp_path: Path):
    (tmp_path / "stack.yaml").write_text(
        "AWSTemplateFormatVersion: 2010-09-09\n"
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
    )
    res = extract_iac_resources(str(tmp_path))
    assert any(r.resource_type == "AWS::S3::Bucket" for r in res)


def test_correlate_exact_resource_match():
    resources = [IaCResource("terraform", "aws_iam_role", "payments_role", "main.tf", "payments")]
    cloud = [{"resource": "payments_role", "title": "wildcard policy"}]
    out = correlate_findings([], cloud, resources)
    assert any(c.correlation == "exact" for c in out)


def test_correlate_service_hint_match():
    resources = [IaCResource("terraform", "aws_iam_role", "task_role", "main.tf", "payments")]
    cloud = [{"resource": "payments-task-role", "title": "wildcard"}]
    out = correlate_findings([], cloud, resources)
    assert any(c.correlation == "service_hint" for c in out)


def test_correlate_no_match_keeps_finding():
    resources = [IaCResource("terraform", "aws_iam_role", "x", "main.tf", "x")]
    cloud = [{"resource": "totally-unrelated", "title": "wildcard"}]
    out = correlate_findings([], cloud, resources)
    assert all(c.correlation in ("none",) for c in out)


def test_correlate_code_finding_links_to_service():
    resources = [IaCResource("terraform", "aws_lambda_function", "fn", "main.tf", "payments")]
    code = [{"package_name": "payments", "title": "CVE-2024-1"}]
    out = correlate_findings(code, [], resources)
    code_corr = [c for c in out if c.finding.get("title") == "CVE-2024-1"]
    assert code_corr and code_corr[0].correlation == "service_hint"
    assert "fn" in code_corr[0].linked_resources
