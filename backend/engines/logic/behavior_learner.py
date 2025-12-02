"""
API Behavior Learner
Learns normal API behavior patterns to detect business logic flaws
"""

import asyncio
import aiohttp
import time
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
import numpy as np
from sklearn.ensemble import IsolationForest
import json

logger = logging.getLogger(__name__)


@dataclass
class APIBehavior:
    """Captured API behavior metrics"""
    response_time: float
    status_code: int
    response_size: int
    headers: Dict[str, str]
    auth_checked: bool
    rate_limited: bool
    timestamp: float


@dataclass
class BehaviorProfile:
    """Statistical profile of normal API behavior"""
    endpoint: str
    avg_response_time: float
    std_response_time: float
    common_status_codes: List[int]
    avg_response_size: int
    always_requires_auth: bool
    has_rate_limiting: bool
    behaviors: List[APIBehavior] = field(default_factory=list)


class APIBehaviorLearner:
    """
    Learn normal API behavior patterns
    Detect deviations that indicate logic flaws
    """

    def __init__(self, contamination: float = 0.1):
        """
        Initialize behavior learner

        Args:
            contamination: Expected proportion of outliers (default 10%)
        """
        self.behavior_profiles: Dict[str, BehaviorProfile] = {}
        self.anomaly_detector = IsolationForest(contamination=contamination, random_state=42)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def learn_endpoint_behavior(
        self,
        endpoint_url: str,
        test_requests: List[Dict],
        headers: Optional[Dict[str, str]] = None
    ) -> BehaviorProfile:
        """
        Send test requests and learn normal behavior

        Args:
            endpoint_url: Full URL to endpoint
            test_requests: List of request payloads to test
            headers: Optional headers to include

        Returns:
            BehaviorProfile with statistical baseline
        """
        logger.info(f"Learning behavior for endpoint: {endpoint_url}")

        behaviors = []

        for i, request_data in enumerate(test_requests):
            try:
                behavior = await self._send_request_and_capture(
                    endpoint_url,
                    request_data,
                    headers
                )
                behaviors.append(behavior)

                # Rate limiting to avoid overwhelming the endpoint
                if i < len(test_requests) - 1:
                    await asyncio.sleep(0.1)

            except Exception as e:
                logger.warning(f"Error sending test request: {str(e)}")

        if not behaviors:
            logger.warning(f"No behaviors captured for {endpoint_url}")
            return BehaviorProfile(
                endpoint=endpoint_url,
                avg_response_time=0,
                std_response_time=0,
                common_status_codes=[],
                avg_response_size=0,
                always_requires_auth=False,
                has_rate_limiting=False
            )

        # Build statistical profile
        profile = self._create_profile(endpoint_url, behaviors)
        self.behavior_profiles[endpoint_url] = profile

        logger.info(
            f"Learned behavior profile: "
            f"avg_response_time={profile.avg_response_time:.3f}s, "
            f"status_codes={profile.common_status_codes}"
        )

        return profile

    async def _send_request_and_capture(
        self,
        url: str,
        request_data: Dict,
        headers: Optional[Dict[str, str]] = None
    ) -> APIBehavior:
        """Send request and capture behavior metrics"""

        if not self.session:
            self.session = aiohttp.ClientSession()

        method = request_data.get('method', 'GET').upper()
        payload = request_data.get('data', {})
        req_headers = {**(headers or {}), **request_data.get('headers', {})}

        start_time = time.time()

        try:
            async with self.session.request(
                method,
                url,
                json=payload if method in ['POST', 'PUT', 'PATCH'] else None,
                params=payload if method == 'GET' else None,
                headers=req_headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                response_time = time.time() - start_time
                content = await response.read()

                # Extract behavior metrics
                behavior = APIBehavior(
                    response_time=response_time,
                    status_code=response.status,
                    response_size=len(content),
                    headers=dict(response.headers),
                    auth_checked=self._detect_auth_check(response),
                    rate_limited=self._detect_rate_limiting(response),
                    timestamp=time.time()
                )

                return behavior

        except asyncio.TimeoutError:
            logger.warning(f"Request to {url} timed out")
            return APIBehavior(
                response_time=10.0,
                status_code=0,
                response_size=0,
                headers={},
                auth_checked=False,
                rate_limited=False,
                timestamp=time.time()
            )

    def _detect_auth_check(self, response: aiohttp.ClientResponse) -> bool:
        """Detect if endpoint performed authentication check"""

        # Check for auth-related headers
        auth_headers = [
            'www-authenticate',
            'authorization',
            'x-auth-token',
            'x-api-key'
        ]

        for header in auth_headers:
            if header in response.headers:
                return True

        # 401 Unauthorized indicates auth was checked
        if response.status == 401:
            return True

        # 403 Forbidden might indicate authorization check
        if response.status == 403:
            return True

        return False

    def _detect_rate_limiting(self, response: aiohttp.ClientResponse) -> bool:
        """Detect if endpoint has rate limiting"""

        # Check for rate limit headers
        rate_limit_headers = [
            'x-ratelimit-limit',
            'x-ratelimit-remaining',
            'x-rate-limit-limit',
            'ratelimit-limit',
            'retry-after'
        ]

        for header in rate_limit_headers:
            if header in response.headers:
                return True

        # 429 Too Many Requests
        if response.status == 429:
            return True

        return False

    def _create_profile(self, endpoint: str, behaviors: List[APIBehavior]) -> BehaviorProfile:
        """Create statistical profile from captured behaviors"""

        response_times = [b.response_time for b in behaviors]
        status_codes = [b.status_code for b in behaviors]
        response_sizes = [b.response_size for b in behaviors]
        auth_checks = [b.auth_checked for b in behaviors]
        rate_limits = [b.rate_limited for b in behaviors]

        profile = BehaviorProfile(
            endpoint=endpoint,
            avg_response_time=np.mean(response_times),
            std_response_time=np.std(response_times),
            common_status_codes=list(set(status_codes)),
            avg_response_size=int(np.mean(response_sizes)),
            always_requires_auth=all(auth_checks),
            has_rate_limiting=any(rate_limits),
            behaviors=behaviors
        )

        return profile

    async def detect_anomalies(
        self,
        endpoint_url: str,
        test_request: Dict,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, float, str]:
        """
        Test if request triggers anomalous behavior

        Args:
            endpoint_url: URL to test
            test_request: Request payload
            headers: Optional headers

        Returns:
            (is_anomaly, anomaly_score, reason)
        """

        # Get baseline profile
        profile = self.behavior_profiles.get(endpoint_url)
        if not profile:
            logger.warning(f"No baseline profile for {endpoint_url}")
            return False, 0.0, "No baseline profile"

        # Send test request
        behavior = await self._send_request_and_capture(
            endpoint_url,
            test_request,
            headers
        )

        # Calculate anomaly score
        anomaly_score, reason = self._calculate_anomaly_score(behavior, profile)

        is_anomaly = anomaly_score > 0.7  # Threshold

        return is_anomaly, anomaly_score, reason

    def _calculate_anomaly_score(
        self,
        behavior: APIBehavior,
        profile: BehaviorProfile
    ) -> Tuple[float, str]:
        """Calculate how anomalous a behavior is compared to profile"""

        reasons = []
        scores = []

        # Response time deviation
        if profile.std_response_time > 0:
            z_score = abs(
                (behavior.response_time - profile.avg_response_time) /
                profile.std_response_time
            )
            if z_score > 3:  # More than 3 standard deviations
                scores.append(0.8)
                reasons.append(f"Response time anomaly (z={z_score:.2f})")

        # Unexpected status code
        if behavior.status_code not in profile.common_status_codes:
            scores.append(0.6)
            reasons.append(f"Unexpected status code: {behavior.status_code}")

        # Auth bypass
        if profile.always_requires_auth and not behavior.auth_checked:
            scores.append(0.9)
            reasons.append("Potential auth bypass - no auth check detected")

        # Size anomaly
        size_ratio = behavior.response_size / max(profile.avg_response_size, 1)
        if size_ratio > 5 or size_ratio < 0.2:
            scores.append(0.5)
            reasons.append(f"Response size anomaly: {behavior.response_size} bytes")

        # Rate limit bypass
        if profile.has_rate_limiting and not behavior.rate_limited:
            # This alone isn't necessarily anomalous
            pass

        # Calculate overall score
        if scores:
            anomaly_score = max(scores)
            reason = "; ".join(reasons)
        else:
            anomaly_score = 0.0
            reason = "Normal behavior"

        return anomaly_score, reason

    def export_profile(self, endpoint_url: str) -> Optional[Dict]:
        """Export behavior profile as JSON"""
        profile = self.behavior_profiles.get(endpoint_url)
        if not profile:
            return None

        return {
            "endpoint": profile.endpoint,
            "avg_response_time": profile.avg_response_time,
            "std_response_time": profile.std_response_time,
            "common_status_codes": profile.common_status_codes,
            "avg_response_size": profile.avg_response_size,
            "always_requires_auth": profile.always_requires_auth,
            "has_rate_limiting": profile.has_rate_limiting,
            "sample_count": len(profile.behaviors)
        }

    def import_profile(self, profile_data: Dict):
        """Import behavior profile from JSON"""
        endpoint = profile_data["endpoint"]

        profile = BehaviorProfile(
            endpoint=endpoint,
            avg_response_time=profile_data["avg_response_time"],
            std_response_time=profile_data["std_response_time"],
            common_status_codes=profile_data["common_status_codes"],
            avg_response_size=profile_data["avg_response_size"],
            always_requires_auth=profile_data["always_requires_auth"],
            has_rate_limiting=profile_data["has_rate_limiting"]
        )

        self.behavior_profiles[endpoint] = profile
        logger.info(f"Imported profile for {endpoint}")
