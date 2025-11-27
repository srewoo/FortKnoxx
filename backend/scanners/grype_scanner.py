"""
Grype Scanner - Container and Dependency Vulnerability Scanner
Free and open-source vulnerability scanner from Anchore
"""

import subprocess
import json
import os
import shutil
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class GrypeScanner:
    """
    Grype - Vulnerability scanner for containers and filesystems (FREE)

    Detects:
    - OS package vulnerabilities
    - Language-specific package vulnerabilities
    - Container image vulnerabilities
    - Works with: Python, JavaScript, Java, Go, Ruby, Rust, etc.

    Installation:
    macOS: brew install grype
    Linux: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
    """

    def __init__(self):
        self.grype_path = shutil.which("grype")

    async def is_available(self) -> bool:
        """Check if Grype is installed"""
        return self.grype_path is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Scan directory for dependency vulnerabilities

        Args:
            repo_path: Path to repository

        Returns:
            List of vulnerabilities found
        """
        if not await self.is_available():
            logger.warning("Grype not installed. See: https://github.com/anchore/grype#installation")
            return []

        try:
            cmd = [
                self.grype_path,
                f"dir:{repo_path}",
                "-o", "json",
                "--quiet"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode == 0 or result.returncode == 1:  # 1 means vulnerabilities found
                data = json.loads(result.stdout)
                vulnerabilities = self._parse_results(data)
                logger.info(f"Grype found {len(vulnerabilities)} vulnerabilities")
                return vulnerabilities

            return []

        except subprocess.TimeoutExpired:
            logger.error("Grype scan timed out")
            return []
        except json.JSONDecodeError:
            logger.error("Failed to parse Grype output")
            return []
        except Exception as e:
            logger.error(f"Grype scan error: {str(e)}")
            return []

    def _parse_results(self, data: Dict) -> List[Dict]:
        """Parse Grype JSON output to vulnerability format"""
        vulnerabilities = []

        for match in data.get('matches', []):
            vuln_data = match.get('vulnerability', {})
            artifact = match.get('artifact', {})

            vuln = {
                'file_path': self._get_package_file(artifact),
                'line_start': 0,
                'line_end': 0,
                'severity': self._map_severity(vuln_data.get('severity', 'Unknown')),
                'category': 'vulnerable-dependency',
                'owasp_category': 'A06',  # Vulnerable and Outdated Components
                'title': f"Vulnerable Package: {artifact.get('name', 'Unknown')}",
                'description': self._build_description(vuln_data, artifact),
                'code_snippet': f"{artifact.get('name', 'unknown')}@{artifact.get('version', 'unknown')}",
                'cwe': self._extract_cwe(vuln_data),
                'cvss_score': self._get_cvss_score(vuln_data),
                'detected_by': 'Grype',
                'cve_id': vuln_data.get('id', 'N/A'),
                'fixed_in': self._get_fixed_version(vuln_data),
                'package_info': {
                    'name': artifact.get('name'),
                    'version': artifact.get('version'),
                    'type': artifact.get('type'),
                    'language': artifact.get('language'),
                    'purl': artifact.get('purl')
                }
            }

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_package_file(self, artifact: Dict) -> str:
        """Determine which dependency file contains this package"""
        package_type = artifact.get('type', '').lower()
        name = artifact.get('name', '')

        # Map package types to files
        if package_type in ['python', 'wheel']:
            return 'requirements.txt'
        elif package_type in ['npm', 'node-pkg']:
            return 'package.json'
        elif package_type in ['gem', 'ruby-gem']:
            return 'Gemfile'
        elif package_type in ['java-archive', 'jar']:
            return 'pom.xml'
        elif package_type == 'go-module':
            return 'go.mod'
        elif package_type == 'rust':
            return 'Cargo.toml'
        else:
            return f"dependencies ({package_type})"

    def _build_description(self, vuln_data: Dict, artifact: Dict) -> str:
        """Build detailed vulnerability description"""
        vuln_id = vuln_data.get('id', 'Unknown')
        description = vuln_data.get('description', 'No description available')
        fixed_in = self._get_fixed_version(vuln_data)

        desc = f"""**Vulnerability**: {vuln_id}

**Package**: {artifact.get('name')} v{artifact.get('version')}
**Type**: {artifact.get('type')}

**Description**: {description}

**Fixed In**: {fixed_in if fixed_in else 'No fix available yet'}

**Remediation**:
"""

        if fixed_in:
            desc += f"Update {artifact.get('name')} to version {fixed_in} or higher.\\n"
        else:
            desc += "No fix is currently available. Monitor for updates or consider alternative packages.\\n"

        # Add links
        urls = vuln_data.get('dataSource', '')
        if urls:
            desc += f"\\n**References**: {urls}"

        return desc

    def _map_severity(self, grype_severity: str) -> str:
        """Map Grype severity to standard format"""
        mapping = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Negligible': 'low',
            'Unknown': 'medium'
        }
        return mapping.get(grype_severity, 'medium')

    def _get_cvss_score(self, vuln_data: Dict) -> float:
        """Extract CVSS score"""
        # Try to get CVSS v3 score first, then v2
        cvss_list = vuln_data.get('cvss', [])

        for cvss in cvss_list:
            if cvss.get('version') == '3.0' or cvss.get('version') == '3.1':
                return cvss.get('metrics', {}).get('baseScore', 0.0)

        # Fallback to v2
        for cvss in cvss_list:
            if cvss.get('version') == '2.0':
                return cvss.get('metrics', {}).get('baseScore', 0.0)

        return 0.0

    def _extract_cwe(self, vuln_data: Dict) -> str:
        """Extract CWE from vulnerability data"""
        # Look for CWE in references or description
        refs = vuln_data.get('references', [])
        for ref in refs:
            if 'CWE' in ref:
                # Extract CWE number
                import re
                match = re.search(r'CWE-(\d+)', ref)
                if match:
                    return f"CWE-{match.group(1)}"

        return None

    def _get_fixed_version(self, vuln_data: Dict) -> str:
        """Get the version where vulnerability is fixed"""
        fix = vuln_data.get('fix', {})
        versions = fix.get('versions', [])

        if versions:
            return versions[0]

        return None
