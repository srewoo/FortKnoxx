"""
OAuth 2.0 Security Runtime Tester
Tests OAuth implementations for common vulnerabilities
"""

import asyncio
import aiohttp
import time
import logging
import secrets
import hashlib
import base64
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)


class OAuthVulnerabilityType(Enum):
    """Types of OAuth vulnerabilities"""
    REDIRECT_URI_MANIPULATION = "redirect_uri_manipulation"
    CSRF_NO_STATE = "csrf_no_state"
    AUTHORIZATION_CODE_INTERCEPTION = "authorization_code_interception"
    OPEN_REDIRECT = "open_redirect"
    TOKEN_LEAKAGE_REFERRER = "token_leakage_referrer"
    PKCE_NOT_ENFORCED = "pkce_not_enforced"
    SCOPE_ESCALATION = "scope_escalation"
    IMPLICIT_FLOW_USED = "implicit_flow_used"


@dataclass
class OAuthTestResult:
    """Result of OAuth security test"""
    vulnerability_type: OAuthVulnerabilityType
    is_vulnerable: bool

    # Test details
    test_url: str
    malicious_parameter: Optional[str]
    response_url: Optional[str]

    # Response analysis
    status_code: int
    vulnerability_confirmed: bool

    # Metadata
    severity: str
    description: str
    remediation: str


class OAuth2SecurityTester:
    """
    Tests OAuth 2.0 implementations for security vulnerabilities
    Focuses on authorization endpoint security
    """

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[OAuthTestResult] = []

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            allow_redirects=False  # Don't follow redirects automatically
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def test_oauth_endpoint(
        self,
        authorization_url: str,
        client_id: str,
        legitimate_redirect_uri: str,
        token_url: Optional[str] = None
    ) -> List[OAuthTestResult]:
        """
        Test OAuth 2.0 endpoint for vulnerabilities

        Args:
            authorization_url: OAuth authorization endpoint
            client_id: OAuth client ID
            legitimate_redirect_uri: Known valid redirect URI
            token_url: Optional token endpoint URL

        Returns:
            List of test results
        """
        logger.info(f"Testing OAuth 2.0 security for: {authorization_url}")

        self.results = []

        # Test 1: Redirect URI manipulation
        await self._test_redirect_uri_manipulation(
            authorization_url, client_id, legitimate_redirect_uri
        )

        # Test 2: CSRF protection (state parameter)
        await self._test_csrf_state_parameter(
            authorization_url, client_id, legitimate_redirect_uri
        )

        # Test 3: Open redirect
        await self._test_open_redirect(
            authorization_url, client_id, legitimate_redirect_uri
        )

        # Test 4: PKCE enforcement
        await self._test_pkce_enforcement(
            authorization_url, client_id, legitimate_redirect_uri
        )

        # Test 5: Scope escalation
        await self._test_scope_escalation(
            authorization_url, client_id, legitimate_redirect_uri
        )

        # Test 6: Implicit flow detection
        await self._test_implicit_flow_usage(
            authorization_url, client_id, legitimate_redirect_uri
        )

        logger.info(
            f"OAuth testing completed: {len(self.results)} tests, "
            f"{sum(1 for r in self.results if r.is_vulnerable)} vulnerabilities"
        )

        return self.results

    async def _test_redirect_uri_manipulation(
        self,
        auth_url: str,
        client_id: str,
        legit_redirect: str
    ):
        """Test redirect_uri parameter manipulation"""

        # Parse legitimate redirect for variations
        parsed = urlparse(legit_redirect)

        malicious_redirects = [
            # Open redirect attempts
            "https://attacker.com/callback",
            "https://evil.com",

            # Subdomain takeover
            f"https://attacker.{parsed.netloc}/callback",

            # Path traversal
            f"{parsed.scheme}://{parsed.netloc}/../attacker/callback",

            # Double encoding
            f"{parsed.scheme}://{parsed.netloc}@attacker.com/callback",

            # Parameter pollution
            f"{legit_redirect}?redirect=https://attacker.com",

            # Fragment manipulation
            f"{legit_redirect}#https://attacker.com",

            # Case sensitivity bypass
            legit_redirect.upper(),
            legit_redirect.lower(),
        ]

        for malicious_redirect in malicious_redirects:
            try:
                # Build OAuth authorization URL
                params = {
                    "client_id": client_id,
                    "redirect_uri": malicious_redirect,
                    "response_type": "code",
                    "scope": "read",
                    "state": secrets.token_urlsafe(32)
                }

                test_url = f"{auth_url}?{urlencode(params)}"

                is_vulnerable, status_code, location = await self._make_oauth_request(test_url)

                if is_vulnerable:
                    self.results.append(OAuthTestResult(
                        vulnerability_type=OAuthVulnerabilityType.REDIRECT_URI_MANIPULATION,
                        is_vulnerable=True,
                        test_url=test_url,
                        malicious_parameter=f"redirect_uri={malicious_redirect}",
                        response_url=location,
                        status_code=status_code,
                        vulnerability_confirmed=True,
                        severity="critical",
                        description=f"OAuth accepts malicious redirect_uri: {malicious_redirect}",
                        remediation=(
                            "1. Validate redirect_uri against exact whitelist\n"
                            "2. No substring or pattern matching\n"
                            "3. Enforce HTTPS for redirect URIs\n"
                            "4. Reject redirects to other domains"
                        )
                    ))
                    logger.warning(f"Redirect URI manipulation successful: {malicious_redirect}")
                    break  # Found vulnerability

            except Exception as e:
                logger.debug(f"Error testing redirect manipulation: {str(e)}")

    async def _test_csrf_state_parameter(
        self,
        auth_url: str,
        client_id: str,
        redirect_uri: str
    ):
        """Test if state parameter is enforced for CSRF protection"""

        try:
            # Request without state parameter
            params = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "read"
                # No 'state' parameter
            }

            test_url = f"{auth_url}?{urlencode(params)}"

            is_vulnerable, status_code, location = await self._make_oauth_request(test_url)

            # Check if authorization proceeds without state
            # Vulnerable if: 200 OK (shows consent screen) or 302 redirect (grants code)
            vulnerability_confirmed = status_code in [200, 302]

            self.results.append(OAuthTestResult(
                vulnerability_type=OAuthVulnerabilityType.CSRF_NO_STATE,
                is_vulnerable=vulnerability_confirmed,
                test_url=test_url,
                malicious_parameter="state=<missing>",
                response_url=location,
                status_code=status_code,
                vulnerability_confirmed=vulnerability_confirmed,
                severity="high" if vulnerability_confirmed else "info",
                description="OAuth flow proceeds without state parameter (CSRF risk)",
                remediation=(
                    "1. Require state parameter in all authorization requests\n"
                    "2. Validate state matches client-generated value\n"
                    "3. Use cryptographically random state values\n"
                    "4. Tie state to user session"
                )
            ))

        except Exception as e:
            logger.debug(f"Error testing CSRF state: {str(e)}")

    async def _test_open_redirect(
        self,
        auth_url: str,
        client_id: str,
        redirect_uri: str
    ):
        """Test for open redirect vulnerabilities"""

        # Common open redirect payloads
        open_redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "http://evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]

        for payload in open_redirect_payloads:
            try:
                params = {
                    "client_id": client_id,
                    "redirect_uri": payload,
                    "response_type": "code",
                    "scope": "read",
                    "state": secrets.token_urlsafe(32)
                }

                test_url = f"{auth_url}?{urlencode(params)}"

                is_vulnerable, status_code, location = await self._make_oauth_request(test_url)

                # Check if redirected to malicious domain
                if location and "evil.com" in location.lower():
                    self.results.append(OAuthTestResult(
                        vulnerability_type=OAuthVulnerabilityType.OPEN_REDIRECT,
                        is_vulnerable=True,
                        test_url=test_url,
                        malicious_parameter=f"redirect_uri={payload}",
                        response_url=location,
                        status_code=status_code,
                        vulnerability_confirmed=True,
                        severity="critical",
                        description=f"Open redirect to malicious URL: {payload}",
                        remediation=(
                            "1. Never allow arbitrary redirect URLs\n"
                            "2. Whitelist specific redirect URIs per client\n"
                            "3. Reject javascript: and data: URIs\n"
                            "4. Validate URL scheme (https only)"
                        )
                    ))
                    logger.warning(f"Open redirect found with payload: {payload}")
                    break

            except Exception as e:
                logger.debug(f"Error testing open redirect: {str(e)}")

    async def _test_pkce_enforcement(
        self,
        auth_url: str,
        client_id: str,
        redirect_uri: str
    ):
        """Test if PKCE is enforced for public clients"""

        try:
            # Request without PKCE parameters
            params = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "read",
                "state": secrets.token_urlsafe(32)
                # No code_challenge or code_challenge_method
            }

            test_url = f"{auth_url}?{urlencode(params)}"

            is_vulnerable, status_code, location = await self._make_oauth_request(test_url)

            # PKCE should be enforced (request should fail without it)
            vulnerability_confirmed = status_code in [200, 302]

            self.results.append(OAuthTestResult(
                vulnerability_type=OAuthVulnerabilityType.PKCE_NOT_ENFORCED,
                is_vulnerable=vulnerability_confirmed,
                test_url=test_url,
                malicious_parameter="code_challenge=<missing>",
                response_url=location,
                status_code=status_code,
                vulnerability_confirmed=vulnerability_confirmed,
                severity="high" if vulnerability_confirmed else "info",
                description="PKCE not enforced - vulnerable to authorization code interception",
                remediation=(
                    "1. Enforce PKCE for all public clients (mobile, SPA)\n"
                    "2. Require code_challenge parameter\n"
                    "3. Validate code_verifier in token exchange\n"
                    "4. Use S256 challenge method (not 'plain')"
                )
            ))

        except Exception as e:
            logger.debug(f"Error testing PKCE: {str(e)}")

    async def _test_scope_escalation(
        self,
        auth_url: str,
        client_id: str,
        redirect_uri: str
    ):
        """Test if excessive scopes can be requested"""

        # Try requesting administrative/sensitive scopes
        excessive_scopes = [
            "admin",
            "write delete admin",
            "read write delete admin superuser",
            "*",
            "all",
        ]

        for scope in excessive_scopes:
            try:
                params = {
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "scope": scope,
                    "state": secrets.token_urlsafe(32)
                }

                test_url = f"{auth_url}?{urlencode(params)}"

                is_vulnerable, status_code, location = await self._make_oauth_request(test_url)

                # If server accepts excessive scopes (200/302), it's vulnerable
                if status_code in [200, 302]:
                    self.results.append(OAuthTestResult(
                        vulnerability_type=OAuthVulnerabilityType.SCOPE_ESCALATION,
                        is_vulnerable=True,
                        test_url=test_url,
                        malicious_parameter=f"scope={scope}",
                        response_url=location,
                        status_code=status_code,
                        vulnerability_confirmed=True,
                        severity="high",
                        description=f"OAuth accepts excessive scope: '{scope}'",
                        remediation=(
                            "1. Validate requested scopes against client allowlist\n"
                            "2. Reject requests with unauthorized scopes\n"
                            "3. Implement scope-based access control\n"
                            "4. Log scope escalation attempts"
                        )
                    ))
                    logger.warning(f"Scope escalation possible with scope: {scope}")
                    break

            except Exception as e:
                logger.debug(f"Error testing scope escalation: {str(e)}")

    async def _test_implicit_flow_usage(
        self,
        auth_url: str,
        client_id: str,
        redirect_uri: str
    ):
        """Test if deprecated implicit flow is still enabled"""

        try:
            # Request using implicit flow (response_type=token)
            params = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "token",  # Implicit flow
                "scope": "read",
                "state": secrets.token_urlsafe(32)
            }

            test_url = f"{auth_url}?{urlencode(params)}"

            is_vulnerable, status_code, location = await self._make_oauth_request(test_url)

            # Implicit flow is deprecated and insecure
            vulnerability_confirmed = status_code in [200, 302]

            self.results.append(OAuthTestResult(
                vulnerability_type=OAuthVulnerabilityType.IMPLICIT_FLOW_USED,
                is_vulnerable=vulnerability_confirmed,
                test_url=test_url,
                malicious_parameter="response_type=token",
                response_url=location,
                status_code=status_code,
                vulnerability_confirmed=vulnerability_confirmed,
                severity="medium" if vulnerability_confirmed else "info",
                description="Implicit flow (response_type=token) is enabled - deprecated and insecure",
                remediation=(
                    "1. Disable implicit flow entirely\n"
                    "2. Use authorization code flow with PKCE for SPAs\n"
                    "3. Never return access tokens in URL fragments\n"
                    "4. Migrate clients to secure flows"
                )
            ))

        except Exception as e:
            logger.debug(f"Error testing implicit flow: {str(e)}")

    async def _make_oauth_request(
        self,
        url: str
    ) -> Tuple[bool, int, Optional[str]]:
        """
        Make OAuth authorization request

        Returns:
            (is_vulnerable, status_code, location_header)
        """

        if not self.session:
            self.session = aiohttp.ClientSession(allow_redirects=False)

        try:
            async with self.session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                status_code = response.status
                location = response.headers.get('Location')

                # Vulnerability indicators:
                # - 200: Shows consent screen (accepts parameters)
                # - 302/301: Redirects (may include auth code/token)
                is_vulnerable = status_code in [200, 301, 302]

                return is_vulnerable, status_code, location

        except asyncio.TimeoutError:
            return False, 0, None
        except Exception as e:
            logger.debug(f"Error making OAuth request: {str(e)}")
            return False, 0, None

    def generate_oauth_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive OAuth security report"""

        vulnerabilities = [r for r in self.results if r.is_vulnerable]

        report = {
            "summary": {
                "total_tests": len(self.results),
                "vulnerabilities_found": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.severity == "critical"),
                "high": sum(1 for v in vulnerabilities if v.severity == "high"),
                "medium": sum(1 for v in vulnerabilities if v.severity == "medium"),
            },
            "vulnerabilities": [],
            "recommendations": []
        }

        # Add vulnerability details
        for vuln in vulnerabilities:
            report["vulnerabilities"].append({
                "type": vuln.vulnerability_type.value,
                "severity": vuln.severity,
                "description": vuln.description,
                "remediation": vuln.remediation,
                "test_url": vuln.test_url[:100] + "...",
                "status_code": vuln.status_code
            })

        # Add recommendations
        if vulnerabilities:
            report["recommendations"] = [
                "Validate redirect_uri against exact whitelist",
                "Enforce state parameter for CSRF protection",
                "Require PKCE for public clients (mobile, SPA)",
                "Disable implicit flow (use authorization code + PKCE)",
                "Validate scopes against client allowlist",
                "Use HTTPS for all OAuth endpoints",
                "Implement rate limiting on authorization endpoint",
                "Log and monitor OAuth security events",
                "Regularly audit OAuth client configurations"
            ]

        return report
