"""
Static Authentication & Authorization Analyzer
Analyzes code for auth vulnerabilities without execution
"""

import re
import ast
from typing import List, Dict, Set, Optional
from pathlib import Path
from pydantic import BaseModel, Field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AuthVulnerabilityType(str, Enum):
    """Types of auth vulnerabilities"""
    MISSING_AUTHENTICATION = "missing_authentication"
    MISSING_AUTHORIZATION = "missing_authorization"
    WEAK_PASSWORD_POLICY = "weak_password_policy"
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_JWT = "insecure_jwt"
    SESSION_FIXATION = "session_fixation"
    INSECURE_COOKIE = "insecure_cookie"
    OAUTH_MISCONFIGURATION = "oauth_misconfiguration"
    MFA_BYPASS = "mfa_bypass"
    ROLE_CONFUSION = "role_confusion"


class AuthVulnerability(BaseModel):
    """Authentication/Authorization vulnerability"""
    type: AuthVulnerabilityType
    title: str
    description: str
    severity: str
    confidence: float

    file_path: str
    line_number: int
    code_snippet: Optional[str] = None

    attack_scenario: str
    remediation: str

    metadata: Dict = Field(default_factory=dict)


class AuthStaticAnalyzer:
    """Static analysis for auth vulnerabilities"""

    def __init__(self):
        self.vulnerabilities: List[AuthVulnerability] = []

    async def analyze_repository(self, repo_path: str) -> List[AuthVulnerability]:
        """
        Analyze repository for auth vulnerabilities

        Args:
            repo_path: Path to repository

        Returns:
            List of detected auth vulnerabilities
        """
        logger.info(f"Running auth static analysis on {repo_path}")

        self.vulnerabilities = []
        repo_path_obj = Path(repo_path)

        # Analyze Python files
        for py_file in repo_path_obj.rglob("*.py"):
            await self._analyze_python_auth(str(py_file))

        # Analyze JavaScript/TypeScript files
        for js_file in list(repo_path_obj.rglob("*.js")) + list(repo_path_obj.rglob("*.ts")):
            await self._analyze_javascript_auth(str(js_file))

        # Analyze config files
        await self._analyze_config_files(repo_path)

        logger.info(f"Found {len(self.vulnerabilities)} auth vulnerabilities")
        return self.vulnerabilities

    async def _analyze_python_auth(self, file_path: str):
        """Analyze Python file for auth issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check for hardcoded secrets
            await self._check_hardcoded_secrets(file_path, content)

            # Check for weak password policies
            await self._check_password_policies(file_path, content)

            # Check for insecure JWT usage
            await self._check_jwt_security(file_path, content)

            # Check for missing auth on endpoints
            await self._check_missing_auth_python(file_path, content)

            # Check for role confusion
            await self._check_role_confusion(file_path, content)

        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {str(e)}")

    async def _check_hardcoded_secrets(self, file_path: str, content: str):
        """Detect hardcoded secrets"""
        secret_patterns = [
            (r'password\s*=\s*["\']([^"\']{4,})["\']', "Hardcoded password"),
            (r'api[_-]?key\s*=\s*["\']([^"\']{4,})["\']', "Hardcoded API key"),
            (r'secret[_-]?key\s*=\s*["\']([^"\']{4,})["\']', "Hardcoded secret key"),
            (r'token\s*=\s*["\']([^"\']{10,})["\']', "Hardcoded token"),
            (r'aws[_-]?access[_-]?key\s*=\s*["\']([^"\']+)["\']', "Hardcoded AWS key"),
        ]

        for pattern, desc in secret_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[:match.start()].count('\n') + 1

                # Skip if it's a placeholder or example
                secret_value = match.group(1)
                if any(placeholder in secret_value.lower() for placeholder in ['example', 'placeholder', 'your_', 'xxx', '***']):
                    continue

                self.vulnerabilities.append(AuthVulnerability(
                    type=AuthVulnerabilityType.HARDCODED_SECRETS,
                    title=f"{desc} in code",
                    description=f"Found hardcoded secret: {desc}",
                    severity="critical",
                    confidence=0.9,
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=match.group(0),
                    attack_scenario=(
                        "Hardcoded secrets in source code can be extracted by anyone with access to the repository"
                    ),
                    remediation=(
                        "1. Remove hardcoded secrets from code\n"
                        "2. Use environment variables or secret management systems\n"
                        "3. Rotate compromised credentials immediately\n"
                        "4. Add secrets to .gitignore"
                    )
                ))

    async def _check_password_policies(self, file_path: str, content: str):
        """Check for weak password policies"""
        # Look for password validation
        if 'password' in content.lower():
            # Check for minimum length validation
            has_length_check = bool(re.search(r'len\([^)]*password[^)]*\)\s*[<>=]+\s*\d+', content, re.IGNORECASE))

            # Check for complexity requirements
            has_complexity = any(pattern in content for pattern in [
                'uppercase', 'lowercase', 'digit', 'special', 're.match', 'regex'
            ])

            if not has_length_check or not has_complexity:
                # Find password-related function
                password_functions = re.finditer(r'def\s+(\w*password\w*)\s*\(', content, re.IGNORECASE)

                for match in password_functions:
                    line_number = content[:match.start()].count('\n') + 1

                    self.vulnerabilities.append(AuthVulnerability(
                        type=AuthVulnerabilityType.WEAK_PASSWORD_POLICY,
                        title="Weak password policy",
                        description="Password validation appears insufficient",
                        severity="medium",
                        confidence=0.6,
                        file_path=file_path,
                        line_number=line_number,
                        attack_scenario=(
                            "Weak passwords can be brute-forced or guessed easily"
                        ),
                        remediation=(
                            "Implement strong password policy:\n"
                            "1. Minimum 12 characters\n"
                            "2. Require uppercase, lowercase, digits, special chars\n"
                            "3. Check against common password lists\n"
                            "4. Implement rate limiting on login attempts"
                        )
                    ))
                    break

    async def _check_jwt_security(self, file_path: str, content: str):
        """Check for insecure JWT usage"""
        # Check for JWT without expiration
        if 'jwt.encode' in content or 'create_access_token' in content:
            has_expiration = 'exp' in content or 'expires' in content

            if not has_expiration:
                jwt_matches = re.finditer(r'jwt\.encode|create_access_token', content)
                for match in jwt_matches:
                    line_number = content[:match.start()].count('\n') + 1

                    self.vulnerabilities.append(AuthVulnerability(
                        type=AuthVulnerabilityType.INSECURE_JWT,
                        title="JWT without expiration",
                        description="JWT tokens are created without expiration time",
                        severity="high",
                        confidence=0.7,
                        file_path=file_path,
                        line_number=line_number,
                        attack_scenario=(
                            "Stolen JWTs without expiration remain valid indefinitely"
                        ),
                        remediation=(
                            "Add expiration to JWT tokens:\n"
                            "1. Include 'exp' claim in payload\n"
                            "2. Use short expiration times (15-60 minutes)\n"
                            "3. Implement refresh token mechanism\n"
                            "4. Add token revocation support"
                        )
                    ))
                    break

        # Check for algorithm="none" vulnerability
        if re.search(r'algorithm\s*=\s*["\']none["\']', content, re.IGNORECASE):
            match = re.search(r'algorithm\s*=\s*["\']none["\']', content, re.IGNORECASE)
            line_number = content[:match.start()].count('\n') + 1

            self.vulnerabilities.append(AuthVulnerability(
                type=AuthVulnerabilityType.INSECURE_JWT,
                title="JWT algorithm set to 'none'",
                description="JWT configured with algorithm='none', disabling signature verification",
                severity="critical",
                confidence=1.0,
                file_path=file_path,
                line_number=line_number,
                attack_scenario=(
                    "Attacker can forge arbitrary JWT tokens without signature"
                ),
                remediation=(
                    "1. Use strong algorithms (HS256, RS256)\n"
                    "2. Never allow algorithm='none'\n"
                    "3. Validate algorithm in verification"
                )
            ))

    async def _check_missing_auth_python(self, file_path: str, content: str):
        """Check for endpoints without authentication"""
        # Look for route decorators
        route_pattern = r'@app\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']'

        for match in re.finditer(route_pattern, content):
            method = match.group(1).upper()
            path = match.group(2)
            line_number = content[:match.start()].count('\n') + 1

            # Skip public endpoints
            if any(public in path for public in ['/login', '/register', '/public', '/health']):
                continue

            # Check if protected by auth decorator
            # Look ahead for Depends or auth decorators
            context = content[match.start():match.start() + 500]

            has_auth = any(auth in context for auth in [
                'Depends(get_current_user)',
                'require_auth',
                'require_role',
                '@login_required'
            ])

            if not has_auth and method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                self.vulnerabilities.append(AuthVulnerability(
                    type=AuthVulnerabilityType.MISSING_AUTHENTICATION,
                    title=f"Unprotected endpoint: {method} {path}",
                    description=f"Endpoint {path} lacks authentication",
                    severity="high",
                    confidence=0.7,
                    file_path=file_path,
                    line_number=line_number,
                    attack_scenario=(
                        "Unauthenticated users can access sensitive functionality"
                    ),
                    remediation=(
                        "Add authentication:\n"
                        "1. Use Depends(get_current_user) for FastAPI\n"
                        "2. Add @login_required for Flask\n"
                        "3. Implement proper authorization checks"
                    )
                ))

    async def _check_role_confusion(self, file_path: str, content: str):
        """Check for role confusion vulnerabilities"""
        # Look for role checks
        role_checks = re.finditer(r'(role|permission)\s*==\s*["\'](\w+)["\']', content, re.IGNORECASE)

        for match in role_checks:
            # Check if using string comparison instead of enum
            context = content[max(0, match.start() - 200):match.start() + 200]

            if 'UserRole' not in context and 'Role.' not in context:
                line_number = content[:match.start()].count('\n') + 1

                self.vulnerabilities.append(AuthVulnerability(
                    type=AuthVulnerabilityType.ROLE_CONFUSION,
                    title="String-based role comparison",
                    description="Role checks using string comparison instead of enums",
                    severity="medium",
                    confidence=0.6,
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=match.group(0),
                    attack_scenario=(
                        "String-based role checks are prone to typos and manipulation"
                    ),
                    remediation=(
                        "1. Use enum-based role definitions\n"
                        "2. Implement centralized role checking\n"
                        "3. Use type-safe role comparisons"
                    )
                ))

    async def _analyze_javascript_auth(self, file_path: str):
        """Analyze JavaScript/TypeScript for auth issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check for hardcoded secrets
            await self._check_hardcoded_secrets(file_path, content)

            # Check for insecure cookies
            if 'setCookie' in content or 'cookie' in content:
                if 'httpOnly' not in content or 'secure' not in content:
                    self.vulnerabilities.append(AuthVulnerability(
                        type=AuthVulnerabilityType.INSECURE_COOKIE,
                        title="Insecure cookie configuration",
                        description="Cookies without httpOnly or secure flags",
                        severity="high",
                        confidence=0.6,
                        file_path=file_path,
                        line_number=1,
                        attack_scenario=(
                            "Cookies without httpOnly can be stolen via XSS. "
                            "Cookies without secure flag sent over HTTP."
                        ),
                        remediation=(
                            "Set cookie flags:\n"
                            "httpOnly: true (prevent XSS access)\n"
                            "secure: true (HTTPS only)\n"
                            "sameSite: 'strict' (CSRF protection)"
                        )
                    ))

        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {str(e)}")

    async def _analyze_config_files(self, repo_path: str):
        """Analyze configuration files for auth issues"""
        repo_path_obj = Path(repo_path)

        # Check .env files (shouldn't be in repo)
        for env_file in repo_path_obj.rglob(".env*"):
            if env_file.name != ".env.example":
                self.vulnerabilities.append(AuthVulnerability(
                    type=AuthVulnerabilityType.HARDCODED_SECRETS,
                    title=f"Environment file in repository: {env_file.name}",
                    description="Environment file containing secrets committed to repository",
                    severity="critical",
                    confidence=1.0,
                    file_path=str(env_file),
                    line_number=1,
                    attack_scenario=(
                        "Anyone with repository access can view all secrets"
                    ),
                    remediation=(
                        "1. Remove .env file from repository immediately\n"
                        "2. Add .env to .gitignore\n"
                        "3. Rotate all exposed credentials\n"
                        "4. Use .env.example with placeholders"
                    )
                ))
