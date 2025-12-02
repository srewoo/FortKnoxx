"""
OWASP ZAP DAST Scanner - Dynamic Application Security Testing
Runs ZAP against live applications using Docker for complete DAST scanning

Features:
- Spider/crawl endpoints
- Active scanning for vulnerabilities
- API scanning (OpenAPI/Swagger)
- Authentication support
- Docker-based (no local ZAP install needed)
"""

import asyncio
import logging
import subprocess
import json
import os
import tempfile
import time
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ZAPDastScanner:
    """OWASP ZAP Dynamic Application Security Testing Scanner"""

    def __init__(self):
        self.docker_image = "ghcr.io/zaproxy/zaproxy:stable"
        self.timeout = 300  # 5 minutes max scan time

    async def scan_target(
        self,
        target_url: str,
        scan_type: str = "baseline",
        api_spec_path: Optional[str] = None,
        auth_config: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Scan a live application with ZAP

        Args:
            target_url: URL of the running application
            scan_type: 'baseline', 'full', or 'api'
            api_spec_path: Path to OpenAPI/Swagger spec (for API scans)
            auth_config: Authentication configuration

        Returns:
            List of vulnerabilities found
        """
        try:
            if not await self._is_docker_available():
                logger.warning("Docker not available. ZAP DAST requires Docker.")
                return []

            # Pull latest ZAP image if needed
            await self._ensure_zap_image()

            # Choose scan method
            if scan_type == "api" and api_spec_path:
                return await self._scan_api(target_url, api_spec_path, auth_config)
            elif scan_type == "full":
                return await self._full_scan(target_url, auth_config)
            else:
                return await self._baseline_scan(target_url)

        except Exception as e:
            logger.error(f"ZAP DAST scan failed: {str(e)}")
            return []

    async def _baseline_scan(self, target_url: str) -> List[Dict]:
        """
        Run ZAP baseline scan (fast, passive scanning)
        Best for: CI/CD pipelines, quick security checks
        """
        logger.info(f"Running ZAP baseline scan on {target_url}")

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "zap-report.json")

            # Run ZAP baseline scan in Docker
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmpdir}:/zap/wrk:rw",
                self.docker_image,
                "zap-baseline.py",
                "-t", target_url,
                "-J", "zap-report.json",  # JSON report
                "-I",  # Don't update add-ons
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    logger.warning("ZAP baseline scan timed out")
                    return []

                # Parse results
                return self._parse_zap_report(report_path)

            except Exception as e:
                logger.error(f"ZAP baseline scan failed: {str(e)}")
                return []

    async def _full_scan(self, target_url: str, auth_config: Optional[Dict] = None) -> List[Dict]:
        """
        Run ZAP full scan (spider + active scan)
        Best for: Comprehensive security testing, pre-production
        """
        logger.info(f"Running ZAP full scan on {target_url}")

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "zap-report.json")

            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmpdir}:/zap/wrk:rw",
                self.docker_image,
                "zap-full-scan.py",
                "-t", target_url,
                "-J", "zap-report.json",
                "-I",
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.timeout * 2  # Full scans take longer
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    logger.warning("ZAP full scan timed out")
                    return []

                return self._parse_zap_report(report_path)

            except Exception as e:
                logger.error(f"ZAP full scan failed: {str(e)}")
                return []

    async def _scan_api(
        self,
        target_url: str,
        api_spec_path: str,
        auth_config: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Run ZAP API scan using OpenAPI/Swagger specification
        Best for: REST APIs, GraphQL endpoints
        """
        logger.info(f"Running ZAP API scan on {target_url}")

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "zap-report.json")

            # Copy API spec to temp dir
            spec_filename = os.path.basename(api_spec_path)
            temp_spec = os.path.join(tmpdir, spec_filename)

            try:
                import shutil
                shutil.copy(api_spec_path, temp_spec)
            except Exception as e:
                logger.error(f"Failed to copy API spec: {str(e)}")
                return []

            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmpdir}:/zap/wrk:rw",
                self.docker_image,
                "zap-api-scan.py",
                "-t", target_url,
                "-f", "openapi",
                "-d", spec_filename,
                "-J", "zap-report.json",
                "-I",
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    logger.warning("ZAP API scan timed out")
                    return []

                return self._parse_zap_report(report_path)

            except Exception as e:
                logger.error(f"ZAP API scan failed: {str(e)}")
                return []

    def _parse_zap_report(self, report_path: str) -> List[Dict]:
        """Parse ZAP JSON report into our vulnerability format"""
        vulnerabilities = []

        try:
            if not os.path.exists(report_path):
                logger.warning(f"ZAP report not found: {report_path}")
                return []

            with open(report_path, 'r') as f:
                zap_data = json.load(f)

            # ZAP report structure
            site = zap_data.get('site', [])
            if not site:
                return []

            alerts = site[0].get('alerts', []) if len(site) > 0 else []

            for alert in alerts:
                risk = alert.get('riskcode', '0')
                severity_map = {
                    '3': 'critical',  # High in ZAP
                    '2': 'high',      # Medium in ZAP
                    '1': 'medium',    # Low in ZAP
                    '0': 'low'        # Informational
                }

                severity = severity_map.get(risk, 'info')

                # Get OWASP category from CWE/tags
                owasp_category = self._map_to_owasp(alert)

                # Get instances (specific occurrences)
                instances = alert.get('instances', [])
                for instance in instances[:5]:  # Limit to 5 instances per alert
                    url = instance.get('url', alert.get('url', 'Unknown'))
                    method = instance.get('method', 'GET')
                    param = instance.get('param', '')

                    vuln = {
                        'title': alert.get('name', 'Unknown Vulnerability'),
                        'description': alert.get('desc', 'No description'),
                        'severity': severity,
                        'file_path': url,
                        'line_start': 1,
                        'line_end': 1,
                        'detected_by': 'zap_dast',
                        'category': 'DAST',
                        'type': alert.get('alert', 'web_vulnerability'),
                        'owasp_category': owasp_category,
                        'cwe': alert.get('cweid', 'CWE-Unknown'),
                        'confidence': alert.get('confidence', 'Medium'),
                        'solution': alert.get('solution', 'Review and remediate'),
                        'reference': alert.get('reference', ''),
                        'method': method,
                        'param': param,
                        'evidence': instance.get('evidence', '')[:200],
                    }

                    vulnerabilities.append(vuln)

            logger.info(f"ZAP DAST found {len(vulnerabilities)} issues")
            return vulnerabilities

        except Exception as e:
            logger.error(f"Failed to parse ZAP report: {str(e)}")
            return []

    def _map_to_owasp(self, alert: Dict) -> str:
        """Map ZAP alert to OWASP Top 10 category"""
        name = alert.get('name', '').lower()
        cwe = alert.get('cweid', '')

        # Map common vulnerabilities to OWASP 2021
        mappings = {
            'injection': 'A03:2021 - Injection',
            'sql': 'A03:2021 - Injection',
            'xss': 'A03:2021 - Injection',
            'authentication': 'A07:2021 - Identification and Authentication Failures',
            'session': 'A07:2021 - Identification and Authentication Failures',
            'access control': 'A01:2021 - Broken Access Control',
            'authorization': 'A01:2021 - Broken Access Control',
            'csrf': 'A01:2021 - Broken Access Control',
            'cryptographic': 'A02:2021 - Cryptographic Failures',
            'ssl': 'A02:2021 - Cryptographic Failures',
            'tls': 'A02:2021 - Cryptographic Failures',
            'misconfiguration': 'A05:2021 - Security Misconfiguration',
            'header': 'A05:2021 - Security Misconfiguration',
            'component': 'A06:2021 - Vulnerable and Outdated Components',
            'logging': 'A09:2021 - Security Logging and Monitoring Failures',
            'ssrf': 'A10:2021 - Server-Side Request Forgery',
        }

        for keyword, category in mappings.items():
            if keyword in name:
                return category

        return 'A05:2021 - Security Misconfiguration'

    async def _is_docker_available(self) -> bool:
        """Check if Docker is installed and running"""
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    async def _ensure_zap_image(self):
        """Pull ZAP Docker image if not present"""
        try:
            # Check if image exists
            process = await asyncio.create_subprocess_exec(
                "docker", "image", "inspect", self.docker_image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()

            if process.returncode != 0:
                # Pull image
                logger.info(f"Pulling ZAP Docker image: {self.docker_image}")
                pull_process = await asyncio.create_subprocess_exec(
                    "docker", "pull", self.docker_image,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await pull_process.communicate()

        except Exception as e:
            logger.warning(f"Failed to check/pull ZAP image: {str(e)}")


# Async wrapper for backward compatibility
async def scan(repo_path: str) -> List[Dict]:
    """
    Static analysis fallback (for code repositories without running apps)
    For DAST, use ZAPDastScanner.scan_target() with a live URL
    """
    logger.info("ZAP DAST is for running applications. Use scan_target() with a URL.")

    # Import the original static scanner
    try:
        from . import zap_scanner as static_zap
        return await static_zap.scan(repo_path)
    except Exception as e:
        logger.error(f"Static ZAP scan failed: {str(e)}")
        return []
