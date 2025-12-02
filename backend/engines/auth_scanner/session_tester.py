"""
Session Security Runtime Tester
Tests session management implementations for vulnerabilities
"""

import asyncio
import aiohttp
import time
import logging
import secrets
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
from http.cookies import SimpleCookie

logger = logging.getLogger(__name__)


class SessionVulnerabilityType(Enum):
    """Types of session vulnerabilities"""
    SESSION_FIXATION = "session_fixation"
    NO_HTTPONLY_FLAG = "no_httponly_flag"
    NO_SECURE_FLAG = "no_secure_flag"
    NO_SAMESITE = "no_samesite"
    WEAK_SESSION_ID = "weak_session_id"
    NO_REGENERATION_ON_LOGIN = "no_regeneration_on_login"
    LONG_EXPIRY = "long_expiry"
    SESSION_NOT_INVALIDATED_ON_LOGOUT = "session_not_invalidated_on_logout"


@dataclass
class SessionTestResult:
    """Result of session security test"""
    vulnerability_type: SessionVulnerabilityType
    is_vulnerable: bool

    # Test details
    test_url: str
    session_cookie: Optional[str]

    # Cookie analysis
    cookie_flags: Dict[str, Any]

    # Metadata
    severity: str
    description: str
    remediation: str


class SessionSecurityTester:
    """
    Tests session management for security vulnerabilities
    """

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[SessionTestResult] = []

    async def __aenter__(self):
        """Async context manager entry"""
        # Create session that doesn't automatically handle cookies
        self.session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def test_session_security(
        self,
        login_url: str,
        credentials: Dict[str, str],
        protected_url: str,
        logout_url: Optional[str] = None
    ) -> List[SessionTestResult]:
        """
        Test session management security

        Args:
            login_url: Login endpoint URL
            credentials: Login credentials (username, password)
            protected_url: Protected endpoint to test access
            logout_url: Optional logout endpoint

        Returns:
            List of test results
        """
        logger.info(f"Testing session security for: {login_url}")

        self.results = []

        # Test 1: Perform login and analyze session cookie
        session_cookie = await self._perform_login(login_url, credentials)

        if not session_cookie:
            logger.warning("Could not obtain session cookie")
            return []

        # Test 2: Check cookie flags
        await self._test_cookie_flags(login_url, credentials, session_cookie)

        # Test 3: Session fixation
        await self._test_session_fixation(login_url, credentials, protected_url)

        # Test 4: Session ID strength
        await self._test_session_id_strength(session_cookie)

        # Test 5: Session regeneration on login
        await self._test_session_regeneration(login_url, credentials)

        # Test 6: Session invalidation on logout
        if logout_url:
            await self._test_logout_invalidation(
                login_url, credentials, logout_url, protected_url
            )

        logger.info(
            f"Session testing completed: {len(self.results)} tests, "
            f"{sum(1 for r in self.results if r.is_vulnerable)} vulnerabilities"
        )

        return self.results

    async def _perform_login(
        self,
        login_url: str,
        credentials: Dict[str, str]
    ) -> Optional[str]:
        """Perform login and extract session cookie"""

        if not self.session:
            self.session = aiohttp.ClientSession()

        try:
            async with self.session.post(
                login_url,
                json=credentials,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:

                # Look for session cookie in Set-Cookie headers
                set_cookie_headers = response.headers.getall('Set-Cookie', [])

                for cookie_header in set_cookie_headers:
                    cookie = SimpleCookie()
                    cookie.load(cookie_header)

                    # Common session cookie names
                    session_names = ['sessionid', 'session', 'sid', 'JSESSIONID', 'connect.sid']

                    for name in session_names:
                        if name.lower() in [k.lower() for k in cookie.keys()]:
                            return cookie_header

                # If no common session cookie found, return first cookie
                if set_cookie_headers:
                    return set_cookie_headers[0]

                return None

        except Exception as e:
            logger.error(f"Error performing login: {str(e)}")
            return None

    async def _test_cookie_flags(
        self,
        login_url: str,
        credentials: Dict[str, str],
        session_cookie_header: str
    ):
        """Test session cookie security flags"""

        try:
            cookie = SimpleCookie()
            cookie.load(session_cookie_header)

            # Get first cookie
            cookie_name = list(cookie.keys())[0]
            morsel = cookie[cookie_name]

            # Check flags
            flags = {
                'httponly': morsel.get('httponly', False),
                'secure': morsel.get('secure', False),
                'samesite': morsel.get('samesite', None),
                'max_age': morsel.get('max-age', None),
                'expires': morsel.get('expires', None)
            }

            # Test: HttpOnly flag
            if not flags['httponly']:
                self.results.append(SessionTestResult(
                    vulnerability_type=SessionVulnerabilityType.NO_HTTPONLY_FLAG,
                    is_vulnerable=True,
                    test_url=login_url,
                    session_cookie=str(morsel)[:100],
                    cookie_flags=flags,
                    severity="high",
                    description="Session cookie missing HttpOnly flag - vulnerable to XSS theft",
                    remediation=(
                        "Set HttpOnly flag on session cookies to prevent JavaScript access.\n"
                        "Example: Set-Cookie: sessionid=...; HttpOnly"
                    )
                ))

            # Test: Secure flag
            if not flags['secure']:
                self.results.append(SessionTestResult(
                    vulnerability_type=SessionVulnerabilityType.NO_SECURE_FLAG,
                    is_vulnerable=True,
                    test_url=login_url,
                    session_cookie=str(morsel)[:100],
                    cookie_flags=flags,
                    severity="high",
                    description="Session cookie missing Secure flag - can be transmitted over HTTP",
                    remediation=(
                        "Set Secure flag on session cookies to enforce HTTPS-only transmission.\n"
                        "Example: Set-Cookie: sessionid=...; Secure"
                    )
                ))

            # Test: SameSite attribute
            if not flags['samesite'] or flags['samesite'].lower() == 'none':
                self.results.append(SessionTestResult(
                    vulnerability_type=SessionVulnerabilityType.NO_SAMESITE,
                    is_vulnerable=True,
                    test_url=login_url,
                    session_cookie=str(morsel)[:100],
                    cookie_flags=flags,
                    severity="medium",
                    description="Session cookie missing SameSite attribute - vulnerable to CSRF",
                    remediation=(
                        "Set SameSite attribute to 'Lax' or 'Strict'.\n"
                        "Example: Set-Cookie: sessionid=...; SameSite=Lax"
                    )
                ))

            # Test: Long expiry
            max_age = flags.get('max_age')
            if max_age and int(max_age) > 86400:  # More than 24 hours
                self.results.append(SessionTestResult(
                    vulnerability_type=SessionVulnerabilityType.LONG_EXPIRY,
                    is_vulnerable=True,
                    test_url=login_url,
                    session_cookie=str(morsel)[:100],
                    cookie_flags=flags,
                    severity="low",
                    description=f"Session cookie has long expiry ({max_age}s / {int(max_age)//3600}h)",
                    remediation=(
                        "Use shorter session expiry times (15-60 minutes for sensitive apps).\n"
                        "Implement idle timeout and absolute timeout."
                    )
                ))

        except Exception as e:
            logger.error(f"Error testing cookie flags: {str(e)}")

    async def _test_session_fixation(
        self,
        login_url: str,
        credentials: Dict[str, str],
        protected_url: str
    ):
        """Test for session fixation vulnerability"""

        if not self.session:
            return

        try:
            # Step 1: Get a session ID before login (attacker's session)
            attacker_session = f"attacker_{secrets.token_urlsafe(16)}"

            # Step 2: Try to login with pre-set session ID
            cookies = {'sessionid': attacker_session}

            async with self.session.post(
                login_url,
                json=credentials,
                cookies=cookies,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as login_response:

                # Check if server accepted our session ID
                new_cookies = login_response.headers.getall('Set-Cookie', [])

                # Step 3: Check if we can access protected resource with our fixed session
                async with self.session.get(
                    protected_url,
                    cookies=cookies,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as protected_response:

                    # If access granted with our pre-set session, it's vulnerable
                    is_vulnerable = protected_response.status == 200

                    if is_vulnerable:
                        self.results.append(SessionTestResult(
                            vulnerability_type=SessionVulnerabilityType.SESSION_FIXATION,
                            is_vulnerable=True,
                            test_url=login_url,
                            session_cookie=attacker_session,
                            cookie_flags={},
                            severity="high",
                            description="Session ID not regenerated on login - vulnerable to session fixation",
                            remediation=(
                                "1. Generate new session ID upon successful login\n"
                                "2. Invalidate old session ID\n"
                                "3. Never accept session IDs from URL parameters\n"
                                "4. Reject externally-supplied session IDs"
                            )
                        ))

        except Exception as e:
            logger.debug(f"Error testing session fixation: {str(e)}")

    async def _test_session_id_strength(self, session_cookie_header: str):
        """Test session ID randomness and strength"""

        try:
            cookie = SimpleCookie()
            cookie.load(session_cookie_header)

            cookie_name = list(cookie.keys())[0]
            session_id = cookie[cookie_name].value

            # Check session ID length
            if len(session_id) < 16:
                self.results.append(SessionTestResult(
                    vulnerability_type=SessionVulnerabilityType.WEAK_SESSION_ID,
                    is_vulnerable=True,
                    test_url="N/A",
                    session_cookie=session_id,
                    cookie_flags={},
                    severity="critical",
                    description=f"Weak session ID (length: {len(session_id)}) - easily brute-forced",
                    remediation=(
                        "Use cryptographically random session IDs with 128+ bits of entropy.\n"
                        "Example: secrets.token_urlsafe(32)"
                    )
                ))

            # Check for sequential or predictable patterns
            if session_id.isdigit():
                self.results.append(SessionTestResult(
                    vulnerability_type=SessionVulnerabilityType.WEAK_SESSION_ID,
                    is_vulnerable=True,
                    test_url="N/A",
                    session_cookie=session_id,
                    cookie_flags={},
                    severity="critical",
                    description="Session ID is numeric-only - highly predictable",
                    remediation="Use alphanumeric random session IDs with high entropy."
                ))

            # Check for simple incremental IDs
            if session_id.isdigit() and int(session_id) < 1000000:
                self.results.append(SessionTestResult(
                    vulnerability_type=SessionVulnerabilityType.WEAK_SESSION_ID,
                    is_vulnerable=True,
                    test_url="N/A",
                    session_cookie=session_id,
                    cookie_flags={},
                    severity="critical",
                    description="Session ID appears to be sequential/incremental",
                    remediation="Never use sequential session IDs. Use cryptographically random values."
                ))

        except Exception as e:
            logger.debug(f"Error testing session ID strength: {str(e)}")

    async def _test_session_regeneration(
        self,
        login_url: str,
        credentials: Dict[str, str]
    ):
        """Test if session ID is regenerated on privilege change"""

        if not self.session:
            return

        try:
            # Login twice and compare session IDs
            session_id_1 = await self._perform_login(login_url, credentials)

            await asyncio.sleep(0.5)

            session_id_2 = await self._perform_login(login_url, credentials)

            if session_id_1 and session_id_2:
                # Extract session ID values
                cookie1 = SimpleCookie()
                cookie1.load(session_id_1)
                id1 = list(cookie1.values())[0].value

                cookie2 = SimpleCookie()
                cookie2.load(session_id_2)
                id2 = list(cookie2.values())[0].value

                # Session IDs should be different
                if id1 == id2:
                    self.results.append(SessionTestResult(
                        vulnerability_type=SessionVulnerabilityType.NO_REGENERATION_ON_LOGIN,
                        is_vulnerable=True,
                        test_url=login_url,
                        session_cookie=id1,
                        cookie_flags={},
                        severity="high",
                        description="Session ID not regenerated between logins",
                        remediation=(
                            "Generate new session ID on:\n"
                            "1. Successful login\n"
                            "2. Privilege escalation\n"
                            "3. Password change\n"
                            "4. Any authentication state change"
                        )
                    ))

        except Exception as e:
            logger.debug(f"Error testing session regeneration: {str(e)}")

    async def _test_logout_invalidation(
        self,
        login_url: str,
        credentials: Dict[str, str],
        logout_url: str,
        protected_url: str
    ):
        """Test if logout properly invalidates session"""

        if not self.session:
            return

        try:
            # Step 1: Login and get session
            session_cookie_header = await self._perform_login(login_url, credentials)

            if not session_cookie_header:
                return

            cookie = SimpleCookie()
            cookie.load(session_cookie_header)
            cookie_name = list(cookie.keys())[0]
            session_id = cookie[cookie_name].value

            cookies = {cookie_name: session_id}

            # Step 2: Logout
            async with self.session.post(
                logout_url,
                cookies=cookies,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as logout_response:
                pass

            # Step 3: Try to access protected resource with old session
            await asyncio.sleep(0.5)

            async with self.session.get(
                protected_url,
                cookies=cookies,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as protected_response:

                # If still granted access, session wasn't invalidated
                is_vulnerable = protected_response.status == 200

                if is_vulnerable:
                    self.results.append(SessionTestResult(
                        vulnerability_type=SessionVulnerabilityType.SESSION_NOT_INVALIDATED_ON_LOGOUT,
                        is_vulnerable=True,
                        test_url=logout_url,
                        session_cookie=session_id,
                        cookie_flags={},
                        severity="high",
                        description="Session not invalidated on logout - old session still valid",
                        remediation=(
                            "1. Invalidate session server-side on logout\n"
                            "2. Remove session from database/cache\n"
                            "3. Clear session cookie\n"
                            "4. Implement session revocation mechanism"
                        )
                    ))

        except Exception as e:
            logger.debug(f"Error testing logout invalidation: {str(e)}")

    def generate_session_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive session security report"""

        vulnerabilities = [r for r in self.results if r.is_vulnerable]

        report = {
            "summary": {
                "total_tests": len(self.results),
                "vulnerabilities_found": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.severity == "critical"),
                "high": sum(1 for v in vulnerabilities if v.severity == "high"),
                "medium": sum(1 for v in vulnerabilities if v.severity == "medium"),
                "low": sum(1 for v in vulnerabilities if v.severity == "low"),
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
                "remediation": vuln.remediation
            })

        # Add recommendations
        if vulnerabilities:
            report["recommendations"] = [
                "Use cryptographically random session IDs (128+ bits)",
                "Set HttpOnly flag on session cookies",
                "Set Secure flag to enforce HTTPS",
                "Set SameSite=Lax or Strict for CSRF protection",
                "Regenerate session ID on login and privilege changes",
                "Implement idle timeout (15-30 minutes)",
                "Invalidate sessions on logout",
                "Use short session expiry times",
                "Implement concurrent session limiting",
                "Log and monitor suspicious session activity"
            ]

        return report
