"""
Bandit Scanner - Python Security Linter
Free and open-source tool for finding common security issues in Python code
"""

import subprocess
import json
import os
import shutil
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class BanditScanner:
    """
    Bandit - Python security linter (FREE)

    Detects:
    - Hardcoded passwords
    - SQL injection
    - Shell injection
    - Insecure deserialization
    - Weak cryptography
    - Path traversal
    - And 40+ other security issues

    Installation: pip install bandit
    """

    def __init__(self):
        self.bandit_path = shutil.which("bandit")

    async def is_available(self) -> bool:
        """Check if Bandit is installed"""
        return self.bandit_path is not None

    async def scan(self, repo_path: str, confidence_level: str = "LOW") -> List[Dict]:
        """
        Scan Python files for security issues

        Args:
            repo_path: Path to repository
            confidence_level: LOW, MEDIUM, or HIGH

        Returns:
            List of vulnerabilities found
        """
        if not await self.is_available():
            logger.warning("Bandit not installed. Run: pip install bandit")
            return []

        try:
            # Find Python files
            python_files = self._find_python_files(repo_path)

            if not python_files:
                logger.info("No Python files found")
                return []

            output_file = os.path.join(repo_path, '.bandit_results.json')

            cmd = [
                self.bandit_path,
                "-r", repo_path,
                "-f", "json",
                "-o", output_file,
                "-ll",  # Report from LOW level up
                "--exclude", "**/venv/**,**/node_modules/**,**/.git/**,**/__pycache__/**"
            ]

            # Bandit returns non-zero when issues found, which is expected
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)

                vulnerabilities = self._parse_results(data)

                # Cleanup
                os.remove(output_file)

                logger.info(f"Bandit found {len(vulnerabilities)} issues")
                return vulnerabilities

            return []

        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
            return []
        except Exception as e:
            logger.error(f"Bandit scan error: {str(e)}")
            return []

    def _find_python_files(self, repo_path: str) -> List[str]:
        """Find all Python files in repository"""
        python_files = []

        for root, dirs, files in os.walk(repo_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['venv', '.git', '__pycache__', 'node_modules']]

            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))

        return python_files

    def _parse_results(self, data: Dict) -> List[Dict]:
        """Parse Bandit JSON output to vulnerability format"""
        vulnerabilities = []

        for result in data.get('results', []):
            vuln = {
                'file_path': result.get('filename', 'unknown'),
                'line_start': result.get('line_number', 0),
                'line_end': result.get('line_number', 0),
                'severity': self._map_severity(result.get('issue_severity', 'MEDIUM')),
                'category': f"bandit-{result.get('test_id', 'unknown')}",
                'owasp_category': self._map_to_owasp(result.get('test_id', ''), result.get('issue_text', '')),
                'title': result.get('issue_text', 'Security Issue'),
                'description': f"{result.get('issue_text', '')}\\n\\n{result.get('more_info', '')}",
                'code_snippet': result.get('code', ''),
                'cwe': self._get_cwe(result.get('test_id', '')),
                'confidence': result.get('issue_confidence', 'MEDIUM'),
                'detected_by': 'Bandit'
            }
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _map_severity(self, bandit_severity: str) -> str:
        """Map Bandit severity to standard format"""
        mapping = {
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return mapping.get(bandit_severity, 'medium')

    def _map_to_owasp(self, test_id: str, issue_text: str) -> str:
        """Map Bandit finding to OWASP Top 10"""
        text = f"{test_id} {issue_text}".lower()

        if 'sql' in text or 'injection' in text:
            return 'A03'  # Injection
        elif 'password' in text or 'hardcoded' in text or 'secret' in text:
            return 'A07'  # Identification and Authentication Failures
        elif 'crypto' in text or 'hash' in text or 'weak' in text:
            return 'A02'  # Cryptographic Failures
        elif 'pickle' in text or 'deserial' in text:
            return 'A08'  # Software and Data Integrity Failures
        elif 'shell' in text or 'exec' in text or 'eval' in text:
            return 'A03'  # Injection
        elif 'assert' in text or 'debug' in text:
            return 'A05'  # Security Misconfiguration
        else:
            return 'A05'  # Default to Security Misconfiguration

    def _get_cwe(self, test_id: str) -> Optional[str]:
        """Map Bandit test ID to CWE"""
        cwe_map = {
            'B201': 'CWE-78',   # Flask debug mode
            'B301': 'CWE-502',  # Pickle
            'B302': 'CWE-327',  # Insecure hash function
            'B303': 'CWE-327',  # MD5 or SHA1
            'B304': 'CWE-327',  # Insecure cipher
            'B305': 'CWE-327',  # Insecure cipher mode
            'B306': 'CWE-327',  # mktemp
            'B307': 'CWE-327',  # eval
            'B308': 'CWE-94',   # Mark safe
            'B310': 'CWE-22',   # Open with variable
            'B311': 'CWE-330',  # Random
            'B312': 'CWE-330',  # Telnet
            'B313': 'CWE-327',  # XML parsing
            'B314': 'CWE-611',  # XML etree
            'B315': 'CWE-611',  # XML expatreader
            'B316': 'CWE-611',  # XML expatbuilder
            'B317': 'CWE-611',  # XML sax
            'B318': 'CWE-611',  # XML mini dom
            'B319': 'CWE-611',  # XML pulldom
            'B320': 'CWE-611',  # XML etree c
            'B321': 'CWE-502',  # FTP
            'B322': 'CWE-79',   # Input
            'B323': 'CWE-327',  # Unverified context
            'B324': 'CWE-327',  # Insecure hash functions
            'B325': 'CWE-327',  # Insecure temp file
            'B401': 'CWE-89',   # Import telnetlib
            'B402': 'CWE-319',  # Import FTP
            'B403': 'CWE-502',  # Import pickle
            'B404': 'CWE-78',   # Import subprocess
            'B405': 'CWE-611',  # Import xml etree
            'B406': 'CWE-611',  # Import xml sax
            'B407': 'CWE-611',  # Import xml expat
            'B408': 'CWE-611',  # Import xml minidom
            'B409': 'CWE-611',  # Import xml pulldom
            'B410': 'CWE-611',  # Import lxml
            'B411': 'CWE-327',  # Import random
            'B501': 'CWE-295',  # Request without cert verification
            'B502': 'CWE-295',  # SSL with bad version
            'B503': 'CWE-295',  # SSL with bad defaults
            'B504': 'CWE-295',  # SSL with no version
            'B505': 'CWE-327',  # Weak cryptographic key
            'B506': 'CWE-522',  # YAML load
            'B507': 'CWE-295',  # SSH no host key verification
            'B601': 'CWE-78',   # Shell injection
            'B602': 'CWE-78',   # Shell injection
            'B603': 'CWE-78',   # Shell injection
            'B604': 'CWE-78',   # Shell injection
            'B605': 'CWE-78',   # Shell injection
            'B606': 'CWE-78',   # Shell injection without shell
            'B607': 'CWE-78',   # Partial path
            'B608': 'CWE-89',   # SQL injection
            'B609': 'CWE-78',   # Linux commands wildcards
            'B610': 'CWE-89',   # SQL injection
            'B611': 'CWE-89',   # SQL injection
            'B701': 'CWE-117',  # Jinja2 autoescape
            'B702': 'CWE-117',  # Mako templates
            'B703': 'CWE-614',  # Django extra
        }

        return cwe_map.get(test_id)
