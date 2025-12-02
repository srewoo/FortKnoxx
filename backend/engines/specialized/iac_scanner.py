"""
Infrastructure as Code (IaC) Security Scanner
Integrates tfsec, terrascan, checkov for Terraform/CloudFormation/Kubernetes security
"""

import asyncio
import subprocess
import json
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class IaCPlatform(str, Enum):
    """Supported IaC platforms"""
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES = "kubernetes"
    DOCKER_COMPOSE = "docker-compose"
    HELM = "helm"


class IaCSeverity(str, Enum):
    """IaC issue severity"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class IaCFinding:
    """IaC security finding"""
    rule_id: str
    title: str
    description: str
    severity: IaCSeverity

    # Location
    file_path: str
    line_start: int
    line_end: Optional[int] = None

    # Resource details
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None

    # Compliance
    compliance_frameworks: List[str] = None
    remediation: Optional[str] = None

    def __post_init__(self):
        if self.compliance_frameworks is None:
            self.compliance_frameworks = []


class IaCScanner:
    """
    Comprehensive Infrastructure as Code security scanner
    Supports Terraform, CloudFormation, Kubernetes, and more
    """

    def __init__(self):
        self.findings: List[IaCFinding] = []

    async def scan_terraform(
        self,
        terraform_dir: str,
        use_tfsec: bool = True,
        use_checkov: bool = True
    ) -> List[IaCFinding]:
        """
        Scan Terraform code for security issues

        Args:
            terraform_dir: Directory containing Terraform files
            use_tfsec: Use tfsec scanner
            use_checkov: Use checkov scanner

        Returns:
            List of findings
        """
        logger.info(f"Scanning Terraform code in {terraform_dir}")

        findings = []

        if use_tfsec:
            findings.extend(await self._scan_with_tfsec(terraform_dir))

        if use_checkov:
            findings.extend(await self._scan_with_checkov(terraform_dir, IaCPlatform.TERRAFORM))

        # Custom Terraform security checks
        findings.extend(await self._custom_terraform_checks(terraform_dir))

        self.findings = findings
        logger.info(f"Terraform scan completed: {len(findings)} findings")
        return findings

    async def scan_kubernetes(
        self,
        k8s_dir: str,
        use_kube_score: bool = True,
        use_checkov: bool = True
    ) -> List[IaCFinding]:
        """
        Scan Kubernetes manifests for security issues

        Args:
            k8s_dir: Directory containing K8s YAML files
            use_kube_score: Use kube-score
            use_checkov: Use checkov

        Returns:
            List of findings
        """
        logger.info(f"Scanning Kubernetes manifests in {k8s_dir}")

        findings = []

        if use_kube_score:
            findings.extend(await self._scan_with_kube_score(k8s_dir))

        if use_checkov:
            findings.extend(await self._scan_with_checkov(k8s_dir, IaCPlatform.KUBERNETES))

        # Custom K8s security checks
        findings.extend(await self._custom_k8s_checks(k8s_dir))

        self.findings = findings
        logger.info(f"Kubernetes scan completed: {len(findings)} findings")
        return findings

    async def scan_cloudformation(
        self,
        cfn_dir: str
    ) -> List[IaCFinding]:
        """
        Scan CloudFormation templates

        Args:
            cfn_dir: Directory containing CloudFormation templates

        Returns:
            List of findings
        """
        logger.info(f"Scanning CloudFormation templates in {cfn_dir}")

        findings = await self._scan_with_checkov(cfn_dir, IaCPlatform.CLOUDFORMATION)

        self.findings = findings
        logger.info(f"CloudFormation scan completed: {len(findings)} findings")
        return findings

    async def _scan_with_tfsec(
        self,
        terraform_dir: str
    ) -> List[IaCFinding]:
        """Scan with tfsec"""

        cmd = [
            "tfsec",
            terraform_dir,
            "--format", "json",
            "--soft-fail"  # Don't exit with error code
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if not stdout:
                return []

            results = json.loads(stdout.decode())
            findings = []

            for result in results.get('results', []):
                severity_map = {
                    "CRITICAL": IaCSeverity.CRITICAL,
                    "HIGH": IaCSeverity.HIGH,
                    "MEDIUM": IaCSeverity.MEDIUM,
                    "LOW": IaCSeverity.LOW
                }

                finding = IaCFinding(
                    rule_id=result.get('rule_id', 'UNKNOWN'),
                    title=result.get('rule_description', 'Unknown issue'),
                    description=result.get('description', ''),
                    severity=severity_map.get(result.get('severity', 'MEDIUM'), IaCSeverity.MEDIUM),
                    file_path=result.get('location', {}).get('filename', ''),
                    line_start=result.get('location', {}).get('start_line', 0),
                    line_end=result.get('location', {}).get('end_line'),
                    resource_type=result.get('resource', ''),
                    remediation=result.get('impact', '')
                )

                findings.append(finding)

            return findings

        except FileNotFoundError:
            logger.warning("tfsec not installed. Install: brew install tfsec")
            return []
        except Exception as e:
            logger.error(f"Error running tfsec: {str(e)}")
            return []

    async def _scan_with_checkov(
        self,
        scan_dir: str,
        platform: IaCPlatform
    ) -> List[IaCFinding]:
        """Scan with Checkov"""

        framework_map = {
            IaCPlatform.TERRAFORM: "terraform",
            IaCPlatform.CLOUDFORMATION: "cloudformation",
            IaCPlatform.KUBERNETES: "kubernetes"
        }

        cmd = [
            "checkov",
            "-d", scan_dir,
            "--framework", framework_map.get(platform, "all"),
            "-o", "json",
            "--quiet"
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if not stdout:
                return []

            results = json.loads(stdout.decode())
            findings = []

            for result in results.get('results', {}).get('failed_checks', []):
                severity_map = {
                    "CRITICAL": IaCSeverity.CRITICAL,
                    "HIGH": IaCSeverity.HIGH,
                    "MEDIUM": IaCSeverity.MEDIUM,
                    "LOW": IaCSeverity.LOW
                }

                finding = IaCFinding(
                    rule_id=result.get('check_id', 'UNKNOWN'),
                    title=result.get('check_name', 'Unknown issue'),
                    description=result.get('check_result', {}).get('result', ''),
                    severity=severity_map.get(result.get('severity', 'MEDIUM'), IaCSeverity.MEDIUM),
                    file_path=result.get('file_path', ''),
                    line_start=result.get('file_line_range', [0])[0],
                    line_end=result.get('file_line_range', [0, 0])[1] if len(result.get('file_line_range', [])) > 1 else None,
                    resource_type=result.get('resource', ''),
                    compliance_frameworks=result.get('guideline', '').split(',') if result.get('guideline') else []
                )

                findings.append(finding)

            return findings

        except FileNotFoundError:
            logger.warning("checkov not installed. Install: pip install checkov")
            return []
        except Exception as e:
            logger.error(f"Error running checkov: {str(e)}")
            return []

    async def _scan_with_kube_score(
        self,
        k8s_dir: str
    ) -> List[IaCFinding]:
        """Scan Kubernetes with kube-score"""

        # Find all YAML files
        yaml_files = list(Path(k8s_dir).rglob("*.yaml")) + list(Path(k8s_dir).rglob("*.yml"))

        findings = []

        for yaml_file in yaml_files:
            cmd = [
                "kube-score", "score",
                str(yaml_file),
                "--output-format", "json"
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await process.communicate()

                if not stdout:
                    continue

                results = json.loads(stdout.decode())

                for obj in results:
                    for check in obj.get('checks', []):
                        if check.get('grade', 0) < 10:  # Issues have grade < 10
                            severity_map = {
                                "critical": IaCSeverity.CRITICAL,
                                "warning": IaCSeverity.MEDIUM,
                                "skipped": IaCSeverity.LOW
                            }

                            finding = IaCFinding(
                                rule_id=check.get('check', {}).get('id', 'UNKNOWN'),
                                title=check.get('check', {}).get('name', 'Unknown'),
                                description=check.get('comment', ''),
                                severity=severity_map.get(check.get('type', 'warning'), IaCSeverity.MEDIUM),
                                file_path=str(yaml_file),
                                line_start=0,
                                resource_type=obj.get('type_meta', {}).get('kind', ''),
                                resource_name=obj.get('object_meta', {}).get('name', '')
                            )

                            findings.append(finding)

            except FileNotFoundError:
                logger.warning("kube-score not installed. Install: brew install kube-score")
                return []
            except Exception as e:
                logger.error(f"Error running kube-score on {yaml_file}: {str(e)}")
                continue

        return findings

    async def _custom_terraform_checks(
        self,
        terraform_dir: str
    ) -> List[IaCFinding]:
        """Custom Terraform security checks"""

        findings = []
        tf_files = list(Path(terraform_dir).rglob("*.tf"))

        for tf_file in tf_files:
            try:
                with open(tf_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')

                # Check 1: Hardcoded secrets
                for line_num, line in enumerate(lines, start=1):
                    if any(keyword in line.lower() for keyword in ['password', 'secret', 'api_key', 'token']):
                        if '=' in line and ('"' in line or "'" in line):
                            findings.append(IaCFinding(
                                rule_id="HARDCODED_SECRET",
                                title="Potential hardcoded secret",
                                description=f"Line contains potential secret: {line.strip()[:50]}",
                                severity=IaCSeverity.CRITICAL,
                                file_path=str(tf_file),
                                line_start=line_num
                            ))

                # Check 2: Public S3 buckets
                if 'resource "aws_s3_bucket"' in content:
                    if 'acl = "public-read"' in content or 'acl = "public-read-write"' in content:
                        findings.append(IaCFinding(
                            rule_id="PUBLIC_S3_BUCKET",
                            title="S3 bucket with public ACL",
                            description="S3 bucket configured with public access",
                            severity=IaCSeverity.CRITICAL,
                            file_path=str(tf_file),
                            line_start=0,
                            resource_type="aws_s3_bucket"
                        ))

                # Check 3: Unrestricted security groups
                if 'resource "aws_security_group"' in content or 'resource "aws_security_group_rule"' in content:
                    if 'cidr_blocks = ["0.0.0.0/0"]' in content:
                        findings.append(IaCFinding(
                            rule_id="UNRESTRICTED_SG",
                            title="Security group allows traffic from 0.0.0.0/0",
                            description="Security group rule allows unrestricted access",
                            severity=IaCSeverity.HIGH,
                            file_path=str(tf_file),
                            line_start=0,
                            resource_type="aws_security_group"
                        ))

            except Exception as e:
                logger.error(f"Error checking {tf_file}: {str(e)}")
                continue

        return findings

    async def _custom_k8s_checks(
        self,
        k8s_dir: str
    ) -> List[IaCFinding]:
        """Custom Kubernetes security checks"""

        findings = []
        yaml_files = list(Path(k8s_dir).rglob("*.yaml")) + list(Path(k8s_dir).rglob("*.yml"))

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r') as f:
                    content = f.read()

                # Check 1: Privileged containers
                if 'privileged: true' in content:
                    findings.append(IaCFinding(
                        rule_id="PRIVILEGED_CONTAINER",
                        title="Privileged container detected",
                        description="Container running in privileged mode",
                        severity=IaCSeverity.CRITICAL,
                        file_path=str(yaml_file),
                        line_start=0
                    ))

                # Check 2: Host network
                if 'hostNetwork: true' in content:
                    findings.append(IaCFinding(
                        rule_id="HOST_NETWORK",
                        title="Pod uses host network",
                        description="Pod configured to use host network namespace",
                        severity=IaCSeverity.HIGH,
                        file_path=str(yaml_file),
                        line_start=0
                    ))

                # Check 3: Root user
                if 'runAsUser: 0' in content:
                    findings.append(IaCFinding(
                        rule_id="RUN_AS_ROOT",
                        title="Container runs as root",
                        description="Container configured to run as root (UID 0)",
                        severity=IaCSeverity.HIGH,
                        file_path=str(yaml_file),
                        line_start=0
                    ))

                # Check 4: No resource limits
                if 'kind: Pod' in content or 'kind: Deployment' in content:
                    if 'resources:' not in content or 'limits:' not in content:
                        findings.append(IaCFinding(
                            rule_id="NO_RESOURCE_LIMITS",
                            title="Missing resource limits",
                            description="Container has no CPU/memory limits",
                            severity=IaCSeverity.MEDIUM,
                            file_path=str(yaml_file),
                            line_start=0
                        ))

            except Exception as e:
                logger.error(f"Error checking {yaml_file}: {str(e)}")
                continue

        return findings

    def generate_report(self) -> Dict[str, Any]:
        """Generate IaC security report"""

        findings_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        findings_by_file = {}
        compliance_frameworks = set()

        for finding in self.findings:
            severity_key = finding.severity.value.lower()
            findings_by_severity[severity_key].append(finding)

            if finding.file_path not in findings_by_file:
                findings_by_file[finding.file_path] = []
            findings_by_file[finding.file_path].append(finding)

            compliance_frameworks.update(finding.compliance_frameworks)

        return {
            "summary": {
                "total_findings": len(self.findings),
                "critical": len(findings_by_severity['critical']),
                "high": len(findings_by_severity['high']),
                "medium": len(findings_by_severity['medium']),
                "low": len(findings_by_severity['low'])
            },
            "files_scanned": len(findings_by_file),
            "compliance_frameworks": list(compliance_frameworks),
            "most_vulnerable_files": sorted(
                findings_by_file.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )[:10],
            "top_issues": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "file": f.file_path,
                    "line": f.line_start,
                    "resource": f.resource_type
                }
                for f in sorted(
                    self.findings,
                    key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}[x.severity.value]
                )[:10]
            ]
        }
