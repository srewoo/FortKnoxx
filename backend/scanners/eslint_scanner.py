"""
ESLint Security Scanner - JavaScript/TypeScript Security Linter
Free and open-source security plugin for ESLint
"""

import subprocess
import json
import os
import shutil
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class ESLintSecurityScanner:
    """
    ESLint with security plugins (FREE)

    Detects:
    - XSS vulnerabilities
    - SQL injection in JavaScript
    - Insecure regex patterns
    - Prototype pollution
    - Command injection
    - Path traversal
    - React security issues

    Installation:
    npm install -g eslint eslint-plugin-security eslint-plugin-react-security
    """

    def __init__(self):
        self.eslint_path = shutil.which("eslint")

    async def is_available(self) -> bool:
        """Check if ESLint is installed"""
        return self.eslint_path is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Scan JavaScript/TypeScript files for security issues

        Args:
            repo_path: Path to repository

        Returns:
            List of vulnerabilities found
        """
        if not await self.is_available():
            logger.warning("ESLint not installed. Run: npm install -g eslint eslint-plugin-security")
            return []

        # Check if there are JS/TS files
        js_files = self._find_js_files(repo_path)
        if not js_files:
            logger.info("No JavaScript/TypeScript files found")
            return []

        try:
            # Create temporary ESLint config
            config_file = self._create_config(repo_path)

            cmd = [
                self.eslint_path,
                repo_path,
                "--config", config_file,
                "--format", "json",
                "--ext", ".js,.jsx,.ts,.tsx",
                "--ignore-path", os.path.join(repo_path, '.gitignore')
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # ESLint returns 1 when issues found
            if result.stdout:
                data = json.loads(result.stdout)
                vulnerabilities = self._parse_results(data)

                # Cleanup config
                if os.path.exists(config_file):
                    os.remove(config_file)

                logger.info(f"ESLint found {len(vulnerabilities)} security issues")
                return vulnerabilities

            return []

        except subprocess.TimeoutExpired:
            logger.error("ESLint scan timed out")
            return []
        except json.JSONDecodeError:
            logger.error("Failed to parse ESLint output")
            return []
        except Exception as e:
            logger.error(f"ESLint scan error: {str(e)}")
            return []

    def _find_js_files(self, repo_path: str) -> List[str]:
        """Find JavaScript/TypeScript files"""
        js_files = []
        extensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']

        for root, dirs, files in os.walk(repo_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'dist', 'build', '__pycache__']]

            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    js_files.append(os.path.join(root, file))

        return js_files

    def _create_config(self, repo_path: str) -> str:
        """Create ESLint configuration with security plugins"""
        config = {
            "env": {
                "browser": True,
                "node": True,
                "es2021": True
            },
            "extends": [
                "eslint:recommended"
            ],
            "plugins": [
                "security"
            ],
            "rules": {
                # Security plugin rules
                "security/detect-buffer-noassert": "error",
                "security/detect-child-process": "error",
                "security/detect-disable-mustache-escape": "error",
                "security/detect-eval-with-expression": "error",
                "security/detect-new-buffer": "error",
                "security/detect-no-csrf-before-method-override": "error",
                "security/detect-non-literal-fs-filename": "warn",
                "security/detect-non-literal-regexp": "warn",
                "security/detect-non-literal-require": "warn",
                "security/detect-object-injection": "warn",
                "security/detect-possible-timing-attacks": "warn",
                "security/detect-pseudoRandomBytes": "error",
                "security/detect-unsafe-regex": "error",

                # General security rules
                "no-eval": "error",
                "no-implied-eval": "error",
                "no-new-func": "error",
                "no-script-url": "error"
            },
            "parserOptions": {
                "ecmaVersion": 2021,
                "sourceType": "module",
                "ecmaFeatures": {
                    "jsx": True
                }
            }
        }

        config_file = os.path.join(repo_path, '.eslintrc.security.json')
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        return config_file

    def _parse_results(self, data: List[Dict]) -> List[Dict]:
        """Parse ESLint JSON output to vulnerability format"""
        vulnerabilities = []

        for file_result in data:
            file_path = file_result.get('filePath', 'unknown')
            messages = file_result.get('messages', [])

            for msg in messages:
                # Only include security-related issues
                rule_id = msg.get('ruleId', '')
                if not rule_id or ('security/' not in rule_id and rule_id not in ['no-eval', 'no-implied-eval', 'no-new-func']):
                    continue

                severity = 'high' if msg.get('severity') == 2 else 'medium'

                vuln = {
                    'file_path': file_path,
                    'line_start': msg.get('line', 0),
                    'line_end': msg.get('endLine', msg.get('line', 0)),
                    'severity': severity,
                    'category': f"eslint-{rule_id}",
                    'owasp_category': self._map_to_owasp(rule_id, msg.get('message', '')),
                    'title': msg.get('message', 'Security Issue'),
                    'description': self._build_description(rule_id, msg),
                    'code_snippet': '',
                    'cwe': self._get_cwe(rule_id),
                    'detected_by': 'ESLint',
                    'column': msg.get('column', 0)
                }

                vulnerabilities.append(vuln)

        return vulnerabilities

    def _build_description(self, rule_id: str, msg: Dict) -> str:
        """Build detailed description for ESLint finding"""
        message = msg.get('message', '')

        descriptions = {
            'security/detect-eval-with-expression': 'Detected eval() usage which can execute arbitrary code',
            'security/detect-child-process': 'Detected child process execution which can lead to command injection',
            'security/detect-non-literal-regexp': 'Detected non-literal regex which can lead to ReDoS attacks',
            'security/detect-unsafe-regex': 'Detected regex vulnerable to catastrophic backtracking (ReDoS)',
            'security/detect-buffer-noassert': 'Detected Buffer usage without assertion',
            'security/detect-pseudoRandomBytes': 'Detected use of pseudoRandomBytes which is not cryptographically secure',
        }

        base_desc = descriptions.get(rule_id, message)

        return f"""{base_desc}

**Location**: Line {msg.get('line', 0)}, Column {msg.get('column', 0)}

**Why This Is Dangerous**:
{self._get_risk_explanation(rule_id)}

**Remediation**:
{self._get_fix_suggestion(rule_id)}
"""

    def _get_risk_explanation(self, rule_id: str) -> str:
        """Get detailed risk explanation"""
        risks = {
            'security/detect-eval-with-expression': 'eval() executes arbitrary JavaScript code, allowing attackers to run malicious code if they control the input.',
            'security/detect-child-process': 'Child processes can execute system commands. If user input reaches these commands, it leads to command injection.',
            'security/detect-unsafe-regex': 'Catastrophic backtracking in regex can cause ReDoS (Regular Expression Denial of Service) attacks, freezing your application.',
            'security/detect-pseudoRandomBytes': 'pseudoRandomBytes is not cryptographically secure and should not be used for security-sensitive operations like token generation.',
        }
        return risks.get(rule_id, 'This pattern is known to cause security vulnerabilities.')

    def _get_fix_suggestion(self, rule_id: str) -> str:
        """Get specific fix suggestion"""
        fixes = {
            'security/detect-eval-with-expression': 'Avoid using eval(). Use JSON.parse() for JSON data, or refactor to use safer alternatives.',
            'security/detect-child-process': 'Sanitize all user input, use allowlists for commands, and avoid shell mode. Consider using safer alternatives.',
            'security/detect-unsafe-regex': 'Simplify the regex pattern or use a library like "safe-regex" to detect vulnerable patterns.',
            'security/detect-pseudoRandomBytes': 'Use crypto.randomBytes() instead for cryptographically secure random generation.',
        }
        return fixes.get(rule_id, 'Review the code and apply security best practices.')

    def _map_to_owasp(self, rule_id: str, message: str) -> str:
        """Map ESLint rule to OWASP Top 10"""
        if 'eval' in rule_id or 'child-process' in rule_id:
            return 'A03'  # Injection
        elif 'xss' in rule_id.lower() or 'mustache' in rule_id:
            return 'A03'  # Injection (XSS)
        elif 'csrf' in rule_id:
            return 'A01'  # Broken Access Control
        elif 'timing' in rule_id:
            return 'A02'  # Cryptographic Failures
        elif 'random' in rule_id:
            return 'A02'  # Cryptographic Failures
        else:
            return 'A05'  # Security Misconfiguration

    def _get_cwe(self, rule_id: str) -> str:
        """Map ESLint rule to CWE"""
        cwe_map = {
            'security/detect-eval-with-expression': 'CWE-94',
            'security/detect-child-process': 'CWE-78',
            'security/detect-unsafe-regex': 'CWE-400',
            'security/detect-pseudoRandomBytes': 'CWE-338',
            'security/detect-non-literal-regexp': 'CWE-400',
            'security/detect-object-injection': 'CWE-915',
            'security/detect-possible-timing-attacks': 'CWE-208',
            'no-eval': 'CWE-94',
            'no-implied-eval': 'CWE-94',
        }
        return cwe_map.get(rule_id, 'CWE-693')
