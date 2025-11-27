"""
TruffleHog Scanner - Git History Secret Detection
Free and open-source tool for finding secrets in git history
"""

import subprocess
import json
import os
import shutil
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class TruffleHogScanner:
    """
    TruffleHog - Find secrets in git history (FREE)

    Detects:
    - API keys (AWS, GitHub, Stripe, etc.)
    - Private keys (SSH, PGP, etc.)
    - Database credentials
    - OAuth tokens
    - High entropy strings
    - Custom regex patterns

    Installation: pip install trufflehog
    Or: brew install trufflehog (macOS)
    """

    def __init__(self):
        self.trufflehog_path = shutil.which("trufflehog")

    async def is_available(self) -> bool:
        """Check if TruffleHog is installed"""
        return self.trufflehog_path is not None

    async def scan(self, repo_path: str, scan_history: bool = True) -> List[Dict]:
        """
        Scan for secrets in repository

        Args:
            repo_path: Path to git repository
            scan_history: If True, scan entire git history

        Returns:
            List of secrets found
        """
        if not await self.is_available():
            logger.warning("TruffleHog not installed. Run: pip install trufflehog")
            return []

        if not self._is_git_repo(repo_path):
            logger.info("Not a git repository, skipping TruffleHog scan")
            return []

        try:
            cmd = [
                self.trufflehog_path,
                "filesystem",
                repo_path,
                "--json",
                "--no-update"  # Don't check for updates
            ]

            if scan_history:
                # Scan git history
                cmd = [
                    self.trufflehog_path,
                    "git",
                    f"file://{repo_path}",
                    "--json",
                    "--no-update"
                ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )

            # Parse JSON output (one JSON object per line)
            vulnerabilities = []

            for line in result.stdout.strip().split('\\n'):
                if not line:
                    continue

                try:
                    finding = json.loads(line)
                    vuln = self._parse_finding(finding, repo_path)
                    if vuln:
                        vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    continue

            logger.info(f"TruffleHog found {len(vulnerabilities)} secrets")
            return vulnerabilities

        except subprocess.TimeoutExpired:
            logger.error("TruffleHog scan timed out")
            return []
        except Exception as e:
            logger.error(f"TruffleHog scan error: {str(e)}")
            return []

    def _is_git_repo(self, path: str) -> bool:
        """Check if directory is a git repository"""
        git_dir = os.path.join(path, '.git')
        return os.path.isdir(git_dir)

    def _parse_finding(self, finding: Dict, repo_path: str) -> Dict:
        """Parse TruffleHog finding to vulnerability format"""
        try:
            source_metadata = finding.get('SourceMetadata', {})
            data = source_metadata.get('Data', {})

            # Get file information
            file_path = data.get('Filesystem', {}).get('file', 'unknown')
            if not file_path or file_path == 'unknown':
                file_path = data.get('Git', {}).get('file', 'unknown')

            # Get detector info
            detector_name = finding.get('DetectorName', 'Unknown')
            raw_secret = finding.get('Raw', '')

            # Determine severity based on verification
            verified = finding.get('Verified', False)
            severity = 'critical' if verified else 'high'

            # Get secret type
            secret_type = self._identify_secret_type(detector_name, raw_secret)

            vuln = {
                'file_path': file_path,
                'line_start': data.get('line', 0),
                'line_end': data.get('line', 0),
                'severity': severity,
                'category': f"secret-{secret_type}",
                'owasp_category': 'A07',  # Identification and Authentication Failures
                'title': f"Secret Detected: {detector_name}",
                'description': self._build_description(detector_name, verified),
                'code_snippet': self._redact_secret(raw_secret),
                'cwe': 'CWE-798',  # Use of Hard-coded Credentials
                'detected_by': 'TruffleHog',
                'verified': verified,
                'secret_type': secret_type,
                'extra_data': {
                    'commit': data.get('Git', {}).get('commit', ''),
                    'author': data.get('Git', {}).get('email', ''),
                    'timestamp': data.get('Git', {}).get('timestamp', '')
                }
            }

            return vuln

        except Exception as e:
            logger.error(f"Error parsing TruffleHog finding: {str(e)}")
            return None

    def _identify_secret_type(self, detector_name: str, secret: str) -> str:
        """Identify the type of secret"""
        detector_lower = detector_name.lower()

        if 'aws' in detector_lower:
            return 'aws_credentials'
        elif 'github' in detector_lower:
            return 'github_token'
        elif 'slack' in detector_lower:
            return 'slack_token'
        elif 'stripe' in detector_lower:
            return 'stripe_key'
        elif 'private key' in detector_lower or 'ssh' in detector_lower:
            return 'private_key'
        elif 'password' in detector_lower:
            return 'password'
        elif 'api' in detector_lower or 'key' in detector_lower:
            return 'api_key'
        elif 'token' in detector_lower:
            return 'auth_token'
        elif 'database' in detector_lower or 'connection' in detector_lower:
            return 'database_credentials'
        else:
            return 'unknown_secret'

    def _build_description(self, detector_name: str, verified: bool) -> str:
        """Build detailed description for secret finding"""
        status = "VERIFIED AND ACTIVE" if verified else "UNVERIFIED"

        description = f"""A secret was detected using the {detector_name} detector.

**Status**: {status}

**Risk Level**: {'CRITICAL - This secret has been verified to be valid and active' if verified else 'HIGH - This appears to be a valid secret but has not been verified'}

**Immediate Actions Required**:
1. Rotate the compromised credential immediately
2. Review access logs for unauthorized usage
3. Update all systems using this credential
4. Add the secret to .gitignore or use a secret manager
5. Consider using environment variables or AWS Secrets Manager

**Prevention**:
- Use pre-commit hooks to prevent secret commits
- Implement secret scanning in CI/CD pipeline
- Use secret management tools (HashiCorp Vault, AWS Secrets Manager)
- Regular secret rotation policy
"""
        return description

    def _redact_secret(self, secret: str) -> str:
        """Redact secret for display (show first/last few chars only)"""
        if len(secret) <= 10:
            return '*' * len(secret)

        # Show first 3 and last 3 characters
        return f"{secret[:3]}{'*' * (len(secret) - 6)}{secret[-3:]}"
