"""
Race Condition Tester
Detects race conditions and concurrent access vulnerabilities
"""

import asyncio
import aiohttp
import time
import logging
from typing import List, Dict, Tuple, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import json

logger = logging.getLogger(__name__)


class RaceConditionType(Enum):
    """Types of race condition vulnerabilities"""
    DOUBLE_SPENDING = "double_spending"  # Spend same resource twice
    TOCTOU = "toctou"  # Time-of-check to time-of-use
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # Deplete resources
    STATE_CORRUPTION = "state_corruption"  # Corrupt shared state
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Gain unauthorized access


@dataclass
class RaceTest:
    """Configuration for a race condition test"""
    test_name: str
    description: str
    race_type: RaceConditionType

    # Request configuration
    endpoint_url: str
    request_template: Dict
    headers: Optional[Dict[str, str]] = None

    # Concurrency settings
    num_concurrent_requests: int = 10
    delay_between_batches_ms: float = 0  # Delay between batches

    # Validation
    expected_successful_requests: int = 1  # How many should succeed
    state_validator: Optional[Callable] = None  # Optional state check


@dataclass
class RaceTestResult:
    """Result of a race condition test"""
    test: RaceTest

    # Execution results
    total_requests: int
    successful_requests: int  # Status 2xx
    failed_requests: int  # Status 4xx/5xx
    error_requests: int  # Network/timeout errors

    # Timing analysis
    avg_response_time: float
    min_response_time: float
    max_response_time: float

    # Response analysis
    status_codes: Dict[int, int]  # status_code -> count
    response_bodies: List[Dict]  # Sample responses

    # Vulnerability detection
    is_vulnerable: bool
    vulnerability_description: str
    severity: str

    # State validation
    state_check_passed: Optional[bool] = None
    state_check_details: Optional[str] = None


class RaceConditionTester:
    """
    Tests for race conditions by sending concurrent requests
    Detects vulnerabilities like double-spending, TOCTOU, etc.
    """

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def test_race_condition(
        self,
        test: RaceTest
    ) -> RaceTestResult:
        """
        Execute a race condition test

        Args:
            test: Race test configuration

        Returns:
            Test result with vulnerability analysis
        """
        logger.info(
            f"Testing race condition: {test.test_name} "
            f"({test.num_concurrent_requests} concurrent requests)"
        )

        if not self.session:
            self.session = aiohttp.ClientSession()

        # Execute concurrent requests
        start_time = time.time()
        responses = await self._send_concurrent_requests(test)
        total_time = time.time() - start_time

        # Analyze results
        result = self._analyze_race_results(test, responses, total_time)

        logger.info(
            f"Race test completed: {result.successful_requests}/{result.total_requests} succeeded, "
            f"vulnerable={result.is_vulnerable}"
        )

        return result

    async def _send_concurrent_requests(
        self,
        test: RaceTest
    ) -> List[Dict]:
        """Send requests concurrently to trigger race condition"""

        tasks = []

        for i in range(test.num_concurrent_requests):
            # Create request from template
            request_data = test.request_template.copy()

            # Add unique identifier if needed
            if 'data' in request_data and isinstance(request_data['data'], dict):
                request_data['data'] = request_data['data'].copy()
                request_data['data']['_test_id'] = i

            task = self._send_single_request(
                test.endpoint_url,
                request_data,
                test.headers,
                request_id=i
            )
            tasks.append(task)

        # Execute all requests concurrently
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error responses
        processed_responses = []
        for i, resp in enumerate(responses):
            if isinstance(resp, Exception):
                processed_responses.append({
                    'request_id': i,
                    'status_code': 0,
                    'error': str(resp),
                    'response_time': 0,
                    'body': None
                })
            else:
                processed_responses.append(resp)

        return processed_responses

    async def _send_single_request(
        self,
        endpoint_url: str,
        request_data: Dict,
        headers: Optional[Dict[str, str]],
        request_id: int
    ) -> Dict:
        """Send a single request and capture response"""

        method = request_data.get('method', 'POST').upper()
        payload = request_data.get('data', {})

        start_time = time.time()

        try:
            async with self.session.request(
                method,
                endpoint_url,
                json=payload if method in ['POST', 'PUT', 'PATCH'] else None,
                params=payload if method == 'GET' else None,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                response_time = time.time() - start_time
                content = await response.read()

                try:
                    body = json.loads(content) if content else {}
                except:
                    body = {'raw': content.decode('utf-8', errors='ignore')[:200]}

                return {
                    'request_id': request_id,
                    'status_code': response.status,
                    'response_time': response_time,
                    'body': body,
                    'error': None
                }

        except asyncio.TimeoutError:
            return {
                'request_id': request_id,
                'status_code': 0,
                'response_time': time.time() - start_time,
                'body': None,
                'error': 'Timeout'
            }
        except Exception as e:
            return {
                'request_id': request_id,
                'status_code': 0,
                'response_time': time.time() - start_time,
                'body': None,
                'error': str(e)
            }

    def _analyze_race_results(
        self,
        test: RaceTest,
        responses: List[Dict],
        total_time: float
    ) -> RaceTestResult:
        """Analyze race test results to detect vulnerabilities"""

        # Count outcomes
        successful = sum(1 for r in responses if 200 <= r['status_code'] < 300)
        failed = sum(1 for r in responses if 400 <= r['status_code'] < 600)
        errors = sum(1 for r in responses if r['status_code'] == 0)

        # Status code distribution
        status_codes = {}
        for resp in responses:
            code = resp['status_code']
            status_codes[code] = status_codes.get(code, 0) + 1

        # Response time statistics
        response_times = [r['response_time'] for r in responses if r['response_time'] > 0]
        avg_time = sum(response_times) / len(response_times) if response_times else 0
        min_time = min(response_times) if response_times else 0
        max_time = max(response_times) if response_times else 0

        # Sample response bodies
        sample_bodies = [r['body'] for r in responses[:5] if r['body']]

        # Detect vulnerability
        is_vulnerable, vuln_desc, severity = self._detect_race_vulnerability(
            test, successful, failed, responses
        )

        # State validation (if provided)
        state_check_passed = None
        state_check_details = None
        if test.state_validator:
            try:
                state_check_passed = test.state_validator()
                state_check_details = "State validation passed" if state_check_passed else "State validation failed"
            except Exception as e:
                state_check_passed = False
                state_check_details = f"State validation error: {str(e)}"

        return RaceTestResult(
            test=test,
            total_requests=len(responses),
            successful_requests=successful,
            failed_requests=failed,
            error_requests=errors,
            avg_response_time=avg_time,
            min_response_time=min_time,
            max_response_time=max_time,
            status_codes=status_codes,
            response_bodies=sample_bodies,
            is_vulnerable=is_vulnerable,
            vulnerability_description=vuln_desc,
            severity=severity,
            state_check_passed=state_check_passed,
            state_check_details=state_check_details
        )

    def _detect_race_vulnerability(
        self,
        test: RaceTest,
        successful_count: int,
        failed_count: int,
        responses: List[Dict]
    ) -> Tuple[bool, str, str]:
        """
        Detect if race condition vulnerability exists

        Returns:
            (is_vulnerable, description, severity)
        """

        expected_success = test.expected_successful_requests

        # Double-spending / Resource exhaustion
        if test.race_type == RaceConditionType.DOUBLE_SPENDING:
            if successful_count > expected_success:
                return (
                    True,
                    f"Double-spending detected: {successful_count} requests succeeded, "
                    f"expected only {expected_success}. Same resource may have been used multiple times.",
                    "critical"
                )

        # TOCTOU (Time-of-check to time-of-use)
        elif test.race_type == RaceConditionType.TOCTOU:
            if successful_count > expected_success:
                return (
                    True,
                    f"TOCTOU race condition: {successful_count} requests succeeded between "
                    f"check and use, expected {expected_success}",
                    "high"
                )

        # Resource exhaustion
        elif test.race_type == RaceConditionType.RESOURCE_EXHAUSTION:
            if successful_count > expected_success:
                return (
                    True,
                    f"Resource exhaustion possible: {successful_count} concurrent requests "
                    f"succeeded, may allow resource depletion",
                    "high"
                )

        # State corruption
        elif test.race_type == RaceConditionType.STATE_CORRUPTION:
            # Check if responses have inconsistent data
            unique_responses = set()
            for resp in responses:
                if resp['body'] and isinstance(resp['body'], dict):
                    # Look for state fields
                    state_fields = {k: v for k, v in resp['body'].items()
                                   if k in ['balance', 'quantity', 'count', 'total']}
                    if state_fields:
                        unique_responses.add(json.dumps(state_fields, sort_keys=True))

            if len(unique_responses) > 1:
                return (
                    True,
                    f"State corruption detected: {len(unique_responses)} different states observed "
                    f"from concurrent requests",
                    "high"
                )

        # Privilege escalation
        elif test.race_type == RaceConditionType.PRIVILEGE_ESCALATION:
            # Check if any unauthorized actions succeeded
            unauthorized_success = sum(
                1 for r in responses
                if 200 <= r['status_code'] < 300 and
                r['body'] and 'admin' in str(r['body']).lower()
            )
            if unauthorized_success > 0:
                return (
                    True,
                    f"Privilege escalation via race condition: {unauthorized_success} "
                    f"unauthorized requests succeeded",
                    "critical"
                )

        # No vulnerability detected
        return (
            False,
            f"No race condition detected: {successful_count}/{test.num_concurrent_requests} succeeded as expected",
            "info"
        )

    async def test_double_spending(
        self,
        endpoint_url: str,
        payment_request: Dict,
        headers: Optional[Dict[str, str]] = None,
        concurrent_attempts: int = 10
    ) -> RaceTestResult:
        """
        Test for double-spending vulnerability

        Args:
            endpoint_url: Payment/transaction endpoint
            payment_request: Payment request template
            headers: Optional headers
            concurrent_attempts: Number of concurrent payment attempts

        Returns:
            Race test result
        """
        test = RaceTest(
            test_name="double_spending_test",
            description="Test if same payment/transaction can be processed multiple times",
            race_type=RaceConditionType.DOUBLE_SPENDING,
            endpoint_url=endpoint_url,
            request_template=payment_request,
            headers=headers,
            num_concurrent_requests=concurrent_attempts,
            expected_successful_requests=1
        )

        return await self.test_race_condition(test)

    async def test_toctou(
        self,
        check_endpoint: str,
        use_endpoint: str,
        check_request: Dict,
        use_request: Dict,
        headers: Optional[Dict[str, str]] = None
    ) -> RaceTestResult:
        """
        Test for Time-of-Check to Time-of-Use race condition

        Args:
            check_endpoint: Endpoint that checks permission/resource
            use_endpoint: Endpoint that uses the resource
            check_request: Check request template
            use_request: Use request template
            headers: Optional headers

        Returns:
            Race test result
        """

        async def check_then_use():
            """Execute check followed by use"""
            # First check
            await self._send_single_request(check_endpoint, check_request, headers, 0)
            # Then use
            await asyncio.sleep(0.001)  # Tiny delay
            return await self._send_single_request(use_endpoint, use_request, headers, 0)

        # Execute check-then-use multiple times concurrently
        tasks = [check_then_use() for _ in range(10)]
        responses = await asyncio.gather(*tasks)

        test = RaceTest(
            test_name="toctou_test",
            description="Test Time-of-Check to Time-of-Use race condition",
            race_type=RaceConditionType.TOCTOU,
            endpoint_url=use_endpoint,
            request_template=use_request,
            headers=headers,
            num_concurrent_requests=10,
            expected_successful_requests=1
        )

        return self._analyze_race_results(test, responses, 0)

    async def test_counter_race(
        self,
        endpoint_url: str,
        increment_request: Dict,
        headers: Optional[Dict[str, str]] = None,
        num_increments: int = 100
    ) -> RaceTestResult:
        """
        Test for counter race condition (lost updates)

        Args:
            endpoint_url: Endpoint that increments a counter
            increment_request: Increment request template
            headers: Optional headers
            num_increments: Number of concurrent increments

        Returns:
            Race test result
        """
        test = RaceTest(
            test_name="counter_race_test",
            description="Test if concurrent counter increments cause lost updates",
            race_type=RaceConditionType.STATE_CORRUPTION,
            endpoint_url=endpoint_url,
            request_template=increment_request,
            headers=headers,
            num_concurrent_requests=num_increments,
            expected_successful_requests=num_increments
        )

        return await self.test_race_condition(test)

    async def test_rate_limit_bypass(
        self,
        endpoint_url: str,
        request_template: Dict,
        headers: Optional[Dict[str, str]] = None,
        rate_limit: int = 10,
        burst_size: int = 50
    ) -> RaceTestResult:
        """
        Test if rate limiting can be bypassed with concurrent requests

        Args:
            endpoint_url: Rate-limited endpoint
            request_template: Request template
            headers: Optional headers
            rate_limit: Expected rate limit
            burst_size: Number of requests to send in burst

        Returns:
            Race test result
        """
        test = RaceTest(
            test_name="rate_limit_bypass_test",
            description="Test if concurrent requests can bypass rate limiting",
            race_type=RaceConditionType.RESOURCE_EXHAUSTION,
            endpoint_url=endpoint_url,
            request_template=request_template,
            headers=headers,
            num_concurrent_requests=burst_size,
            expected_successful_requests=rate_limit
        )

        return await self.test_race_condition(test)
