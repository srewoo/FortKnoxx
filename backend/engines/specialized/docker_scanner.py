"""
Docker & Container Security Scanner
Integrates docker-bench-security, Trivy, and Clair for container scanning
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


class ContainerVulnerabilitySeverity(str, Enum):
    """Container vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class ContainerVulnerability:
    """Container vulnerability finding"""
    vulnerability_id: str  # CVE-ID or check ID
    title: str
    description: str
    severity: ContainerVulnerabilitySeverity

    # Location
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None

    # Docker-specific
    dockerfile_line: Optional[int] = None
    layer: Optional[str] = None

    # Metadata
    references: List[str] = None
    cvss_score: Optional[float] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []


class DockerSecurityScanner:
    """
    Comprehensive Docker and container security scanner
    Integrates multiple tools for complete coverage
    """

    def __init__(self):
        self.vulnerabilities: List[ContainerVulnerability] = []

    async def scan_dockerfile(
        self,
        dockerfile_path: str
    ) -> List[ContainerVulnerability]:
        """
        Scan Dockerfile for security issues

        Args:
            dockerfile_path: Path to Dockerfile

        Returns:
            List of vulnerabilities
        """
        logger.info(f"Scanning Dockerfile: {dockerfile_path}")

        findings = []

        # Scan with hadolint (Dockerfile linter)
        findings.extend(await self._scan_with_hadolint(dockerfile_path))

        # Custom Dockerfile security checks
        findings.extend(await self._check_dockerfile_best_practices(dockerfile_path))

        return findings

    async def scan_container_image(
        self,
        image_name: str,
        use_trivy: bool = True
    ) -> List[ContainerVulnerability]:
        """
        Scan container image for vulnerabilities

        Args:
            image_name: Docker image name (e.g., "nginx:latest")
            use_trivy: Use Trivy for scanning (requires installation)

        Returns:
            List of vulnerabilities
        """
        logger.info(f"Scanning container image: {image_name}")

        self.vulnerabilities = []

        if use_trivy:
            # Scan with Trivy
            self.vulnerabilities.extend(await self._scan_with_trivy(image_name))
        else:
            # Basic Docker image inspection
            self.vulnerabilities.extend(await self._inspect_docker_image(image_name))

        logger.info(f"Container scan completed: {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

    async def run_docker_bench_security(
        self,
        output_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run Docker Bench for Security
        Tests Docker host configuration against CIS benchmarks

        Args:
            output_file: Optional file to save results

        Returns:
            Security benchmark results
        """
        logger.info("Running Docker Bench Security...")

        cmd = [
            "docker", "run", "--rm",
            "--net=host",
            "--pid=host",
            "--userns=host",
            "--cap-add=audit_control",
            "-v", "/etc:/etc:ro",
            "-v", "/usr/bin/containerd:/usr/bin/containerd:ro",
            "-v", "/usr/bin/runc:/usr/bin/runc:ro",
            "-v", "/usr/lib/systemd:/usr/lib/systemd:ro",
            "-v", "/var/lib:/var/lib:ro",
            "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
            "docker/docker-bench-security"
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            output = stdout.decode()

            # Parse results
            results = self._parse_docker_bench_output(output)

            if output_file:
                with open(output_file, 'w') as f:
                    f.write(output)

            logger.info("Docker Bench Security completed")
            return results

        except Exception as e:
            logger.error(f"Error running Docker Bench: {str(e)}")
            return {"error": str(e)}

    async def _scan_with_hadolint(
        self,
        dockerfile_path: str
    ) -> List[ContainerVulnerability]:
        """Scan Dockerfile with hadolint"""

        cmd = ["hadolint", "--format", "json", dockerfile_path]

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
            vulnerabilities = []

            for issue in results:
                severity_map = {
                    "error": ContainerVulnerabilitySeverity.HIGH,
                    "warning": ContainerVulnerabilitySeverity.MEDIUM,
                    "info": ContainerVulnerabilitySeverity.LOW
                }

                vuln = ContainerVulnerability(
                    vulnerability_id=issue.get('code', 'UNKNOWN'),
                    title=f"Dockerfile issue: {issue.get('code', 'Unknown')}",
                    description=issue.get('message', ''),
                    severity=severity_map.get(issue.get('level', 'info'), ContainerVulnerabilitySeverity.UNKNOWN),
                    dockerfile_line=issue.get('line'),
                    references=[issue.get('code', '')]
                )

                vulnerabilities.append(vuln)

            return vulnerabilities

        except FileNotFoundError:
            logger.warning("hadolint not installed, skipping Dockerfile linting")
            return []
        except Exception as e:
            logger.error(f"Error running hadolint: {str(e)}")
            return []

    async def _check_dockerfile_best_practices(
        self,
        dockerfile_path: str
    ) -> List[ContainerVulnerability]:
        """Check Dockerfile for security best practices"""

        vulnerabilities = []

        try:
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, start=1):
                line_upper = line.strip().upper()

                # Check 1: Running as root
                if line_upper.startswith('FROM ') and 'USER' not in ''.join(lines).upper():
                    vulnerabilities.append(ContainerVulnerability(
                        vulnerability_id="NO_USER",
                        title="Container runs as root",
                        description="No USER instruction found. Container will run as root by default.",
                        severity=ContainerVulnerabilitySeverity.HIGH,
                        dockerfile_line=line_num,
                        references=["CIS Docker Benchmark 4.1"]
                    ))

                # Check 2: Using latest tag
                if 'FROM' in line_upper and ':LATEST' in line_upper:
                    vulnerabilities.append(ContainerVulnerability(
                        vulnerability_id="LATEST_TAG",
                        title="Using :latest tag",
                        description="Base image uses :latest tag. Use specific version tags for reproducibility.",
                        severity=ContainerVulnerabilitySeverity.MEDIUM,
                        dockerfile_line=line_num
                    ))

                # Check 3: Secrets in ENV
                if 'ENV' in line_upper and any(secret in line_upper for secret in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                    vulnerabilities.append(ContainerVulnerability(
                        vulnerability_id="SECRET_IN_ENV",
                        title="Potential secret in ENV variable",
                        description="Environment variable may contain hardcoded secrets.",
                        severity=ContainerVulnerabilitySeverity.CRITICAL,
                        dockerfile_line=line_num
                    ))

                # Check 4: HEALTHCHECK missing
                if line_upper.startswith('FROM ') and 'HEALTHCHECK' not in ''.join(lines).upper():
                    vulnerabilities.append(ContainerVulnerability(
                        vulnerability_id="NO_HEALTHCHECK",
                        title="Missing HEALTHCHECK",
                        description="No HEALTHCHECK instruction. Add health monitoring.",
                        severity=ContainerVulnerabilitySeverity.LOW,
                        dockerfile_line=line_num
                    ))

            return vulnerabilities

        except Exception as e:
            logger.error(f"Error checking Dockerfile best practices: {str(e)}")
            return []

    async def _scan_with_trivy(
        self,
        image_name: str
    ) -> List[ContainerVulnerability]:
        """Scan image with Trivy vulnerability scanner"""

        cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            image_name
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
            vulnerabilities = []

            for result in results.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    vulnerability = ContainerVulnerability(
                        vulnerability_id=vuln.get('VulnerabilityID', 'UNKNOWN'),
                        title=vuln.get('Title', vuln.get('VulnerabilityID', 'Unknown vulnerability')),
                        description=vuln.get('Description', ''),
                        severity=ContainerVulnerabilitySeverity(vuln.get('Severity', 'UNKNOWN')),
                        package_name=vuln.get('PkgName'),
                        installed_version=vuln.get('InstalledVersion'),
                        fixed_version=vuln.get('FixedVersion'),
                        references=vuln.get('References', []),
                        cvss_score=vuln.get('CVSS', {}).get('nvd', {}).get('V3Score')
                    )

                    vulnerabilities.append(vulnerability)

            return vulnerabilities

        except FileNotFoundError:
            logger.warning("Trivy not installed. Install: https://aquasecurity.github.io/trivy")
            return []
        except Exception as e:
            logger.error(f"Error running Trivy: {str(e)}")
            return []

    async def _inspect_docker_image(
        self,
        image_name: str
    ) -> List[ContainerVulnerability]:
        """Basic Docker image inspection"""

        cmd = ["docker", "inspect", image_name]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Docker inspect failed: {stderr.decode()}")
                return []

            inspection = json.loads(stdout.decode())[0]
            vulnerabilities = []

            # Check if running as root
            config = inspection.get('Config', {})
            if config.get('User', '') == '' or config.get('User') == 'root':
                vulnerabilities.append(ContainerVulnerability(
                    vulnerability_id="RUNS_AS_ROOT",
                    title="Container runs as root",
                    description="Image configured to run as root user",
                    severity=ContainerVulnerabilitySeverity.HIGH,
                    references=["CIS Docker Benchmark 4.1"]
                ))

            # Check for exposed ports
            exposed_ports = config.get('ExposedPorts', {})
            if exposed_ports:
                vulnerabilities.append(ContainerVulnerability(
                    vulnerability_id="EXPOSED_PORTS",
                    title=f"Exposed ports: {', '.join(exposed_ports.keys())}",
                    description="Review if all exposed ports are necessary",
                    severity=ContainerVulnerabilitySeverity.LOW
                ))

            return vulnerabilities

        except Exception as e:
            logger.error(f"Error inspecting Docker image: {str(e)}")
            return []

    def _parse_docker_bench_output(self, output: str) -> Dict[str, Any]:
        """Parse Docker Bench Security output"""

        results = {
            "passed": 0,
            "warnings": 0,
            "failed": 0,
            "info": 0,
            "issues": []
        }

        for line in output.split('\n'):
            if '[PASS]' in line:
                results["passed"] += 1
            elif '[WARN]' in line:
                results["warnings"] += 1
                results["issues"].append({"level": "warning", "message": line})
            elif '[INFO]' in line:
                results["info"] += 1
            elif '[NOTE]' in line or '[FAIL]' in line:
                results["failed"] += 1
                results["issues"].append({"level": "failed", "message": line})

        return results

    def generate_report(self) -> Dict[str, Any]:
        """Generate container security report"""

        vulns_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'unknown': []
        }

        vulns_by_package = {}

        for vuln in self.vulnerabilities:
            severity_key = vuln.severity.value.lower()
            vulns_by_severity[severity_key].append(vuln)

            if vuln.package_name:
                if vuln.package_name not in vulns_by_package:
                    vulns_by_package[vuln.package_name] = []
                vulns_by_package[vuln.package_name].append(vuln)

        return {
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": len(vulns_by_severity['critical']),
                "high": len(vulns_by_severity['high']),
                "medium": len(vulns_by_severity['medium']),
                "low": len(vulns_by_severity['low']),
                "unknown": len(vulns_by_severity['unknown'])
            },
            "packages_affected": len(vulns_by_package),
            "top_vulnerable_packages": sorted(
                vulns_by_package.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )[:10],
            "critical_issues": [
                {
                    "id": v.vulnerability_id,
                    "title": v.title,
                    "package": v.package_name,
                    "installed": v.installed_version,
                    "fixed": v.fixed_version,
                    "cvss": v.cvss_score
                }
                for v in vulns_by_severity['critical']
            ][:10]
        }
