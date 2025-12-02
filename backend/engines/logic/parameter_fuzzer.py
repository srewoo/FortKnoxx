"""
Smart Parameter Fuzzer
Learns valid parameter ranges and tests boundaries to detect business logic flaws
"""

import asyncio
import aiohttp
import time
import logging
from typing import List, Dict, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
import json
import re
from decimal import Decimal

logger = logging.getLogger(__name__)


class ParameterType(Enum):
    """Detected parameter types"""
    INTEGER = "integer"
    FLOAT = "float"
    STRING = "string"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    EMAIL = "email"
    URL = "url"
    UUID = "uuid"
    DATETIME = "datetime"
    ENUM = "enum"


@dataclass
class ParameterProfile:
    """Statistical profile of a parameter's valid range"""
    name: str
    param_type: ParameterType

    # Numeric parameters
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    avg_value: Optional[float] = None

    # String parameters
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None

    # Enum parameters
    valid_values: Set[Any] = field(default_factory=set)

    # Observed metadata
    required: bool = True
    samples: List[Any] = field(default_factory=list)


@dataclass
class FuzzTest:
    """A single fuzz test case"""
    test_name: str
    description: str
    original_value: Any
    fuzz_value: Any
    expected_behavior: str  # "reject", "accept", "unknown"


@dataclass
class FuzzResult:
    """Result of a fuzz test"""
    test: FuzzTest
    status_code: int
    response_time: float
    response_size: int
    error_message: Optional[str]

    is_vulnerability: bool
    vulnerability_type: str
    severity: str
    description: str


class SmartParameterFuzzer:
    """
    Intelligent parameter fuzzer that:
    1. Learns valid parameter ranges from legitimate requests
    2. Generates boundary test cases
    3. Detects business logic flaws (price tampering, negative quantities, etc.)
    """

    def __init__(self):
        self.parameter_profiles: Dict[str, ParameterProfile] = {}
        self.session: Optional[aiohttp.ClientSession] = None

        # Fuzz value generators
        self.integer_fuzzes = [
            ("zero", 0),
            ("negative", -1),
            ("large_negative", -999999),
            ("max_int", 2147483647),
            ("overflow", 2147483648),
        ]

        self.float_fuzzes = [
            ("zero", 0.0),
            ("negative", -1.0),
            ("very_small", 0.000001),
            ("very_large", 999999999.99),
            ("negative_large", -999999999.99),
        ]

        self.string_fuzzes = [
            ("empty", ""),
            ("sql_injection", "' OR '1'='1"),
            ("xss", "<script>alert('xss')</script>"),
            ("path_traversal", "../../etc/passwd"),
            ("null_byte", "test\x00.txt"),
            ("unicode", "\u202e\u202d"),
            ("long_string", "A" * 10000),
        ]

        self.array_fuzzes = [
            ("empty_array", []),
            ("single_element", [1]),
            ("large_array", list(range(10000))),
            ("negative_values", [-1, -2, -3]),
        ]

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def learn_parameters(
        self,
        endpoint_url: str,
        legitimate_requests: List[Dict],
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, ParameterProfile]:
        """
        Learn valid parameter ranges from legitimate requests

        Args:
            endpoint_url: API endpoint to test
            legitimate_requests: List of valid request payloads
            headers: Optional headers

        Returns:
            Dictionary of parameter profiles
        """
        logger.info(f"Learning parameter profiles for {endpoint_url}")

        parameter_samples: Dict[str, List[Any]] = {}

        # Collect samples from all requests
        for request_data in legitimate_requests:
            payload = request_data.get('data', {})
            self._collect_samples(payload, parameter_samples)

        # Build profiles from samples
        for param_name, samples in parameter_samples.items():
            profile = self._create_parameter_profile(param_name, samples)
            self.parameter_profiles[param_name] = profile

            logger.info(
                f"Learned parameter '{param_name}': "
                f"type={profile.param_type.value}, "
                f"samples={len(samples)}"
            )

        return self.parameter_profiles

    def _collect_samples(self, payload: Dict, parameter_samples: Dict[str, List[Any]], prefix: str = ""):
        """Recursively collect parameter samples from nested payloads"""
        for key, value in payload.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                # Nested object
                self._collect_samples(value, parameter_samples, prefix=full_key)
            else:
                # Leaf parameter
                if full_key not in parameter_samples:
                    parameter_samples[full_key] = []
                parameter_samples[full_key].append(value)

    def _create_parameter_profile(self, param_name: str, samples: List[Any]) -> ParameterProfile:
        """Create statistical profile from samples"""

        # Detect parameter type
        param_type = self._detect_type(samples)

        profile = ParameterProfile(
            name=param_name,
            param_type=param_type,
            samples=samples[:10]  # Keep first 10 samples
        )

        # Type-specific profiling
        if param_type == ParameterType.INTEGER:
            numeric_samples = [int(s) for s in samples if self._is_numeric(s)]
            if numeric_samples:
                profile.min_value = min(numeric_samples)
                profile.max_value = max(numeric_samples)
                profile.avg_value = np.mean(numeric_samples)

        elif param_type == ParameterType.FLOAT:
            numeric_samples = [float(s) for s in samples if self._is_numeric(s)]
            if numeric_samples:
                profile.min_value = min(numeric_samples)
                profile.max_value = max(numeric_samples)
                profile.avg_value = np.mean(numeric_samples)

        elif param_type == ParameterType.STRING:
            string_samples = [str(s) for s in samples]
            profile.min_length = min(len(s) for s in string_samples)
            profile.max_length = max(len(s) for s in string_samples)

            # Detect pattern (email, URL, etc.)
            if all(self._is_email(s) for s in string_samples):
                profile.param_type = ParameterType.EMAIL
            elif all(self._is_url(s) for s in string_samples):
                profile.param_type = ParameterType.URL
            elif all(self._is_uuid(s) for s in string_samples):
                profile.param_type = ParameterType.UUID

        elif param_type == ParameterType.ENUM:
            profile.valid_values = set(samples)

        return profile

    def _detect_type(self, samples: List[Any]) -> ParameterType:
        """Detect parameter type from samples"""

        if not samples:
            return ParameterType.STRING

        # Check if all samples are same type
        first_type = type(samples[0])

        if all(isinstance(s, bool) for s in samples):
            return ParameterType.BOOLEAN

        if all(isinstance(s, int) for s in samples):
            return ParameterType.INTEGER

        if all(isinstance(s, (int, float)) for s in samples):
            return ParameterType.FLOAT

        if all(isinstance(s, list) for s in samples):
            return ParameterType.ARRAY

        if all(isinstance(s, dict) for s in samples):
            return ParameterType.OBJECT

        # Check for enum (limited set of values)
        unique_values = set(samples)
        if len(unique_values) <= 10 and len(samples) > 3:
            return ParameterType.ENUM

        return ParameterType.STRING

    def _is_numeric(self, value: Any) -> bool:
        """Check if value is numeric"""
        try:
            float(value)
            return True
        except (ValueError, TypeError):
            return False

    def _is_email(self, value: str) -> bool:
        """Check if value is email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, str(value)))

    def _is_url(self, value: str) -> bool:
        """Check if value is URL format"""
        pattern = r'^https?://'
        return bool(re.match(pattern, str(value)))

    def _is_uuid(self, value: str) -> bool:
        """Check if value is UUID format"""
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(pattern, str(value).lower()))

    def generate_fuzz_tests(self, parameter_name: str) -> List[FuzzTest]:
        """
        Generate boundary and anomalous test cases for a parameter

        Args:
            parameter_name: Name of parameter to fuzz

        Returns:
            List of fuzz test cases
        """
        profile = self.parameter_profiles.get(parameter_name)
        if not profile:
            logger.warning(f"No profile found for parameter '{parameter_name}'")
            return []

        tests = []
        original_value = profile.samples[0] if profile.samples else None

        # Type-specific fuzz generation
        if profile.param_type == ParameterType.INTEGER:
            tests.extend(self._generate_integer_fuzzes(profile, original_value))

        elif profile.param_type == ParameterType.FLOAT:
            tests.extend(self._generate_float_fuzzes(profile, original_value))

        elif profile.param_type in [ParameterType.STRING, ParameterType.EMAIL, ParameterType.URL]:
            tests.extend(self._generate_string_fuzzes(profile, original_value))

        elif profile.param_type == ParameterType.BOOLEAN:
            tests.extend(self._generate_boolean_fuzzes(profile, original_value))

        elif profile.param_type == ParameterType.ARRAY:
            tests.extend(self._generate_array_fuzzes(profile, original_value))

        elif profile.param_type == ParameterType.ENUM:
            tests.extend(self._generate_enum_fuzzes(profile, original_value))

        logger.info(f"Generated {len(tests)} fuzz tests for '{parameter_name}'")
        return tests

    def _generate_integer_fuzzes(self, profile: ParameterProfile, original: Any) -> List[FuzzTest]:
        """Generate integer boundary tests"""
        tests = []

        # Boundary tests
        if profile.min_value is not None:
            tests.append(FuzzTest(
                test_name="boundary_below_min",
                description=f"Test value below minimum ({profile.min_value})",
                original_value=original,
                fuzz_value=int(profile.min_value - 1),
                expected_behavior="reject"
            ))

        if profile.max_value is not None:
            tests.append(FuzzTest(
                test_name="boundary_above_max",
                description=f"Test value above maximum ({profile.max_value})",
                original_value=original,
                fuzz_value=int(profile.max_value + 1),
                expected_behavior="reject"
            ))

        # Common integer fuzzes
        for fuzz_name, fuzz_value in self.integer_fuzzes:
            tests.append(FuzzTest(
                test_name=fuzz_name,
                description=f"Test {fuzz_name} value",
                original_value=original,
                fuzz_value=fuzz_value,
                expected_behavior="reject" if fuzz_value < 0 else "unknown"
            ))

        return tests

    def _generate_float_fuzzes(self, profile: ParameterProfile, original: Any) -> List[FuzzTest]:
        """Generate float boundary tests"""
        tests = []

        # Boundary tests
        if profile.min_value is not None:
            tests.append(FuzzTest(
                test_name="boundary_below_min",
                description=f"Test value below minimum ({profile.min_value})",
                original_value=original,
                fuzz_value=float(profile.min_value - 0.01),
                expected_behavior="reject"
            ))

        if profile.max_value is not None:
            tests.append(FuzzTest(
                test_name="boundary_above_max",
                description=f"Test value above maximum ({profile.max_value})",
                original_value=original,
                fuzz_value=float(profile.max_value + 0.01),
                expected_behavior="reject"
            ))

        # Common float fuzzes
        for fuzz_name, fuzz_value in self.float_fuzzes:
            tests.append(FuzzTest(
                test_name=fuzz_name,
                description=f"Test {fuzz_name} value",
                original_value=original,
                fuzz_value=fuzz_value,
                expected_behavior="reject" if fuzz_value < 0 else "unknown"
            ))

        return tests

    def _generate_string_fuzzes(self, profile: ParameterProfile, original: Any) -> List[FuzzTest]:
        """Generate string fuzz tests"""
        tests = []

        # Length boundary tests
        if profile.max_length is not None and profile.max_length > 0:
            tests.append(FuzzTest(
                test_name="length_exceeds_max",
                description=f"String longer than max length ({profile.max_length})",
                original_value=original,
                fuzz_value="A" * (profile.max_length + 100),
                expected_behavior="reject"
            ))

        # Common string fuzzes
        for fuzz_name, fuzz_value in self.string_fuzzes:
            tests.append(FuzzTest(
                test_name=fuzz_name,
                description=f"Test {fuzz_name}",
                original_value=original,
                fuzz_value=fuzz_value,
                expected_behavior="reject"
            ))

        return tests

    def _generate_boolean_fuzzes(self, profile: ParameterProfile, original: Any) -> List[FuzzTest]:
        """Generate boolean fuzz tests"""
        return [
            FuzzTest(
                test_name="type_confusion_string",
                description="Test string instead of boolean",
                original_value=original,
                fuzz_value="true",
                expected_behavior="unknown"
            ),
            FuzzTest(
                test_name="type_confusion_integer",
                description="Test integer instead of boolean",
                original_value=original,
                fuzz_value=1,
                expected_behavior="unknown"
            )
        ]

    def _generate_array_fuzzes(self, profile: ParameterProfile, original: Any) -> List[FuzzTest]:
        """Generate array fuzz tests"""
        tests = []

        for fuzz_name, fuzz_value in self.array_fuzzes:
            tests.append(FuzzTest(
                test_name=fuzz_name,
                description=f"Test {fuzz_name}",
                original_value=original,
                fuzz_value=fuzz_value,
                expected_behavior="unknown"
            ))

        return tests

    def _generate_enum_fuzzes(self, profile: ParameterProfile, original: Any) -> List[FuzzTest]:
        """Generate enum fuzz tests"""
        return [
            FuzzTest(
                test_name="invalid_enum_value",
                description="Value not in valid enum set",
                original_value=original,
                fuzz_value="INVALID_VALUE_XYZ",
                expected_behavior="reject"
            ),
            FuzzTest(
                test_name="case_sensitivity",
                description="Test case sensitivity",
                original_value=original,
                fuzz_value=str(original).lower() if isinstance(original, str) else original,
                expected_behavior="unknown"
            )
        ]

    async def execute_fuzz_tests(
        self,
        endpoint_url: str,
        base_request: Dict,
        parameter_name: str,
        headers: Optional[Dict[str, str]] = None
    ) -> List[FuzzResult]:
        """
        Execute all fuzz tests for a parameter

        Args:
            endpoint_url: API endpoint
            base_request: Base request payload
            parameter_name: Parameter to fuzz
            headers: Optional headers

        Returns:
            List of fuzz results
        """
        logger.info(f"Executing fuzz tests for parameter '{parameter_name}'")

        fuzz_tests = self.generate_fuzz_tests(parameter_name)
        results = []

        for test in fuzz_tests:
            result = await self._execute_single_fuzz(
                endpoint_url,
                base_request,
                parameter_name,
                test,
                headers
            )
            results.append(result)

            # Rate limiting
            await asyncio.sleep(0.1)

        # Analyze results for vulnerabilities
        vulnerabilities = self._analyze_fuzz_results(results)

        logger.info(
            f"Completed {len(results)} fuzz tests, "
            f"found {vulnerabilities} potential vulnerabilities"
        )

        return results

    async def _execute_single_fuzz(
        self,
        endpoint_url: str,
        base_request: Dict,
        parameter_name: str,
        test: FuzzTest,
        headers: Optional[Dict[str, str]] = None
    ) -> FuzzResult:
        """Execute a single fuzz test"""

        if not self.session:
            self.session = aiohttp.ClientSession()

        # Create modified request
        modified_request = base_request.copy()
        payload = modified_request.get('data', {}).copy()

        # Set fuzz value (handle nested parameters)
        self._set_nested_value(payload, parameter_name, test.fuzz_value)
        modified_request['data'] = payload

        method = modified_request.get('method', 'POST').upper()

        try:
            start_time = time.time()

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
                error_msg = None

                try:
                    response_json = await response.json() if content else {}
                    error_msg = response_json.get('error') or response_json.get('message')
                except:
                    pass

                # Determine if this is a vulnerability
                is_vuln, vuln_type, severity, description = self._evaluate_fuzz_result(
                    test, response.status, error_msg
                )

                return FuzzResult(
                    test=test,
                    status_code=response.status,
                    response_time=response_time,
                    response_size=len(content),
                    error_message=error_msg,
                    is_vulnerability=is_vuln,
                    vulnerability_type=vuln_type,
                    severity=severity,
                    description=description
                )

        except Exception as e:
            logger.warning(f"Error executing fuzz test {test.test_name}: {str(e)}")
            return FuzzResult(
                test=test,
                status_code=0,
                response_time=0,
                response_size=0,
                error_message=str(e),
                is_vulnerability=False,
                vulnerability_type="",
                severity="info",
                description="Test execution failed"
            )

    def _set_nested_value(self, payload: Dict, key_path: str, value: Any):
        """Set value in nested dictionary using dot notation"""
        keys = key_path.split('.')
        current = payload

        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    def _evaluate_fuzz_result(
        self,
        test: FuzzTest,
        status_code: int,
        error_message: Optional[str]
    ) -> Tuple[bool, str, str, str]:
        """
        Evaluate if a fuzz result indicates a vulnerability

        Returns:
            (is_vulnerability, vuln_type, severity, description)
        """

        # Expected reject but got success
        if test.expected_behavior == "reject" and status_code in [200, 201, 204]:
            if "negative" in test.test_name:
                return (
                    True,
                    "price_manipulation",
                    "high",
                    f"Negative value accepted: {test.fuzz_value}"
                )
            elif "boundary" in test.test_name:
                return (
                    True,
                    "boundary_bypass",
                    "medium",
                    f"Out-of-bounds value accepted: {test.fuzz_value}"
                )
            elif any(x in test.test_name for x in ["sql_injection", "xss", "path_traversal"]):
                return (
                    True,
                    "injection_vulnerability",
                    "critical",
                    f"Injection payload not rejected: {test.test_name}"
                )
            else:
                return (
                    True,
                    "input_validation_missing",
                    "medium",
                    f"Invalid input accepted: {test.test_name}"
                )

        # Server error on fuzz (potential DoS)
        if status_code >= 500:
            return (
                True,
                "denial_of_service",
                "medium",
                f"Fuzz value caused server error: {test.fuzz_value}"
            )

        return (False, "", "info", "Test passed normally")

    def _analyze_fuzz_results(self, results: List[FuzzResult]) -> int:
        """Count vulnerabilities in fuzz results"""
        return sum(1 for r in results if r.is_vulnerability)
