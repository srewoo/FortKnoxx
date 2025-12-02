"""
Strix-Inspired Intelligent Fuzzing Engine
Advanced fuzzing with mutation strategies and feedback loops
"""

import asyncio
import logging
import random
import string
from typing import List, Dict, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import aiohttp

logger = logging.getLogger(__name__)


class MutationStrategy(str, Enum):
    """Fuzzing mutation strategies"""
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    ARITHMETIC = "arithmetic"
    INTERESTING_VALUES = "interesting_values"
    BOUNDARY_VALUES = "boundary_values"
    DICTIONARY = "dictionary"
    SPLICE = "splice"
    REPEAT = "repeat"
    TRUNCATE = "truncate"
    APPEND = "append"


@dataclass
class FuzzResult:
    """Result from a fuzz test"""
    input_data: str
    mutation_strategy: MutationStrategy
    response_code: Optional[int] = None
    response_time_ms: float = 0.0
    response_body: Optional[str] = None
    error_triggered: bool = False
    anomaly_detected: bool = False
    crash_detected: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzTarget:
    """Target for fuzzing"""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    param_name: Optional[str] = None
    body_template: Optional[Dict[str, Any]] = None


class StrixFuzzer:
    """
    Intelligent fuzzing engine inspired by Strix
    Implements coverage-guided fuzzing and mutation strategies
    """

    # Interesting values for different data types
    INTERESTING_INTEGERS = [
        -1, 0, 1,
        127, 128, 255, 256,  # Byte boundaries
        32767, 32768, 65535, 65536,  # Short boundaries
        2147483647, 2147483648,  # Int boundaries
        -2147483648, -2147483647,
    ]

    INTERESTING_STRINGS = [
        "",  # Empty
        " ",  # Space
        "\n", "\r\n", "\t",  # Whitespace
        "A" * 1000,  # Long string
        "A" * 10000,  # Very long string
        "🚀" * 100,  # Unicode
        "\x00",  # Null byte
        "../../../",  # Path traversal
        "<script>",  # XSS
        "' OR '1'='1",  # SQLi
    ]

    BOUNDARY_VALUES = [
        -2**31, -2**31 + 1,  # Int32 min
        2**31 - 1, 2**31,  # Int32 max
        -2**63, 2**63 - 1,  # Int64 boundaries
        0, 1, -1,
        0.0, -0.0, float('inf'), float('-inf'), float('nan'),
    ]

    def __init__(
        self,
        max_iterations: int = 1000,
        timeout_seconds: int = 5,
        enable_coverage_tracking: bool = True
    ):
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds
        self.enable_coverage_tracking = enable_coverage_tracking
        self.coverage_map: Set[str] = set()
        self.corpus: List[str] = []  # Interesting inputs that increased coverage

    async def fuzz_target(
        self,
        target: FuzzTarget,
        seed_inputs: Optional[List[str]] = None,
        strategies: Optional[List[MutationStrategy]] = None
    ) -> List[FuzzResult]:
        """
        Fuzz a target endpoint with various mutation strategies

        Args:
            target: Target configuration
            seed_inputs: Initial inputs to mutate
            strategies: Mutation strategies to use

        Returns:
            List of fuzz results
        """
        if seed_inputs is None:
            seed_inputs = self._generate_seed_inputs()

        if strategies is None:
            strategies = list(MutationStrategy)

        results = []
        interesting_results = []

        logger.info(f"Starting fuzzing of {target.url}")
        logger.info(f"Seed inputs: {len(seed_inputs)}, Max iterations: {self.max_iterations}")

        iteration = 0
        current_corpus = seed_inputs.copy()

        while iteration < self.max_iterations:
            # Select input from corpus
            if current_corpus:
                seed = random.choice(current_corpus)
            else:
                seed = self._generate_random_input()

            # Select mutation strategy
            strategy = random.choice(strategies)

            # Mutate input
            mutated = self._mutate(seed, strategy)

            # Test mutated input
            result = await self._test_input(target, mutated, strategy)
            results.append(result)

            # Check if result is interesting (new coverage, error, anomaly)
            if self._is_interesting(result):
                interesting_results.append(result)
                current_corpus.append(mutated)
                logger.info(f"Interesting result found: {strategy.value} - {result.response_code}")

            iteration += 1

            # Log progress
            if iteration % 100 == 0:
                logger.info(f"Fuzz iteration {iteration}/{self.max_iterations}, Interesting: {len(interesting_results)}")

        logger.info(f"Fuzzing complete. Total tests: {len(results)}, Interesting: {len(interesting_results)}")

        return interesting_results if interesting_results else results[:50]  # Return top 50 if no interesting

    def _generate_seed_inputs(self) -> List[str]:
        """Generate initial seed inputs"""
        seeds = []

        # Add interesting strings
        seeds.extend(self.INTERESTING_STRINGS)

        # Add interesting integers as strings
        seeds.extend([str(i) for i in self.INTERESTING_INTEGERS])

        # Add random strings
        for _ in range(10):
            seeds.append(self._generate_random_input())

        return seeds

    def _generate_random_input(self, max_length: int = 100) -> str:
        """Generate random input string"""
        length = random.randint(1, max_length)
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    def _mutate(self, input_data: str, strategy: MutationStrategy) -> str:
        """Apply mutation strategy to input"""
        if not input_data:
            return self._generate_random_input()

        if strategy == MutationStrategy.BIT_FLIP:
            return self._bit_flip(input_data)
        elif strategy == MutationStrategy.BYTE_FLIP:
            return self._byte_flip(input_data)
        elif strategy == MutationStrategy.ARITHMETIC:
            return self._arithmetic_mutation(input_data)
        elif strategy == MutationStrategy.INTERESTING_VALUES:
            return random.choice([str(v) for v in self.INTERESTING_INTEGERS + self.INTERESTING_STRINGS])
        elif strategy == MutationStrategy.BOUNDARY_VALUES:
            return str(random.choice(self.BOUNDARY_VALUES))
        elif strategy == MutationStrategy.DICTIONARY:
            return self._dictionary_mutation(input_data)
        elif strategy == MutationStrategy.SPLICE:
            return self._splice_mutation(input_data)
        elif strategy == MutationStrategy.REPEAT:
            return input_data * random.randint(2, 100)
        elif strategy == MutationStrategy.TRUNCATE:
            return input_data[:random.randint(0, len(input_data))]
        elif strategy == MutationStrategy.APPEND:
            return input_data + random.choice(self.INTERESTING_STRINGS)
        else:
            return input_data

    def _bit_flip(self, data: str) -> str:
        """Flip random bit in data"""
        if not data:
            return data

        data_bytes = bytearray(data.encode('utf-8', errors='ignore'))
        if data_bytes:
            byte_idx = random.randint(0, len(data_bytes) - 1)
            bit_idx = random.randint(0, 7)
            data_bytes[byte_idx] ^= (1 << bit_idx)

        return data_bytes.decode('utf-8', errors='ignore')

    def _byte_flip(self, data: str) -> str:
        """Flip random byte in data"""
        if not data:
            return data

        data_bytes = bytearray(data.encode('utf-8', errors='ignore'))
        if data_bytes:
            byte_idx = random.randint(0, len(data_bytes) - 1)
            data_bytes[byte_idx] = random.randint(0, 255)

        return data_bytes.decode('utf-8', errors='ignore')

    def _arithmetic_mutation(self, data: str) -> str:
        """Apply arithmetic mutation (for numeric values)"""
        try:
            num = int(data)
            operations = [
                num + 1,
                num - 1,
                num * 2,
                num // 2 if num != 0 else 0,
                -num,
                num + random.randint(-100, 100)
            ]
            return str(random.choice(operations))
        except ValueError:
            return data

    def _dictionary_mutation(self, data: str) -> str:
        """Replace part of data with dictionary word"""
        dictionary_words = ["admin", "root", "test", "null", "undefined", "true", "false"]

        if len(data) > 3:
            start = random.randint(0, len(data) - 3)
            end = random.randint(start + 1, len(data))
            replacement = random.choice(dictionary_words)
            return data[:start] + replacement + data[end:]

        return random.choice(dictionary_words)

    def _splice_mutation(self, data: str) -> str:
        """Splice two parts of input together"""
        if len(self.corpus) > 1:
            other = random.choice(self.corpus)
            cut_point1 = random.randint(0, len(data))
            cut_point2 = random.randint(0, len(other))
            return data[:cut_point1] + other[cut_point2:]

        return data

    async def _test_input(
        self,
        target: FuzzTarget,
        input_data: str,
        strategy: MutationStrategy
    ) -> FuzzResult:
        """Test an input against the target"""
        result = FuzzResult(
            input_data=input_data,
            mutation_strategy=strategy
        )

        try:
            # Prepare request
            if target.method == "GET":
                url = f"{target.url}?{target.param_name}={input_data}" if target.param_name else target.url
                body = None
            else:
                url = target.url
                if target.body_template:
                    body = target.body_template.copy()
                    if target.param_name:
                        body[target.param_name] = input_data
                else:
                    body = {target.param_name: input_data} if target.param_name else {"data": input_data}

            # Make request
            async with aiohttp.ClientSession() as session:
                start_time = asyncio.get_event_loop().time()

                async with session.request(
                    target.method,
                    url,
                    json=body if target.method in ["POST", "PUT", "PATCH"] else None,
                    headers=target.headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
                ) as response:
                    end_time = asyncio.get_event_loop().time()

                    result.response_code = response.status
                    result.response_time_ms = (end_time - start_time) * 1000

                    # Read response body (limited)
                    try:
                        body_text = await response.text()
                        result.response_body = body_text[:1000]  # Limit to 1KB
                    except:
                        result.response_body = None

                    # Detect anomalies
                    result.anomaly_detected = self._detect_anomaly(result)
                    result.error_triggered = response.status >= 500

        except asyncio.TimeoutError:
            result.metadata['error'] = 'timeout'
            result.anomaly_detected = True
        except aiohttp.ClientError as e:
            result.metadata['error'] = str(e)
            result.crash_detected = True
        except Exception as e:
            result.metadata['error'] = str(e)
            result.error_triggered = True

        return result

    def _detect_anomaly(self, result: FuzzResult) -> bool:
        """Detect if result is anomalous"""
        # Check response code
        if result.response_code in [500, 501, 502, 503]:
            return True

        # Check response time (timeout-like behavior)
        if result.response_time_ms > (self.timeout_seconds * 1000 * 0.9):
            return True

        # Check for error messages in response
        if result.response_body:
            error_indicators = [
                "error", "exception", "stack trace", "warning",
                "sql", "database", "syntax error", "undefined",
                "null pointer", "segmentation fault"
            ]
            body_lower = result.response_body.lower()
            if any(indicator in body_lower for indicator in error_indicators):
                return True

        return False

    def _is_interesting(self, result: FuzzResult) -> bool:
        """Determine if result is interesting (increases coverage or finds bugs)"""
        # Error or crash
        if result.error_triggered or result.crash_detected:
            return True

        # Anomaly detected
        if result.anomaly_detected:
            return True

        # New response code
        if self.enable_coverage_tracking:
            coverage_key = f"{result.response_code}_{len(result.response_body or '')}"
            if coverage_key not in self.coverage_map:
                self.coverage_map.add(coverage_key)
                return True

        # Unusual response time
        if result.response_time_ms > 1000:  # > 1 second
            return True

        return False

    async def fuzz_multiple_targets(
        self,
        targets: List[FuzzTarget],
        seed_inputs: Optional[List[str]] = None
    ) -> Dict[str, List[FuzzResult]]:
        """Fuzz multiple targets concurrently"""
        tasks = []
        for target in targets:
            task = self.fuzz_target(target, seed_inputs)
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = {}
        for i, target in enumerate(targets):
            if isinstance(results[i], Exception):
                logger.error(f"Fuzzing failed for {target.url}: {results[i]}")
                output[target.url] = []
            else:
                output[target.url] = results[i]

        return output


class PropertyBasedTester:
    """
    Property-based testing inspired by QuickCheck/Hypothesis
    """

    def __init__(self):
        self.properties: List[Callable] = []

    def add_property(self, property_func: Callable):
        """Add a property to test"""
        self.properties.append(property_func)

    async def test_property(
        self,
        property_func: Callable,
        num_tests: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Test a property with random inputs

        Args:
            property_func: Function that returns True if property holds
            num_tests: Number of random tests to run

        Returns:
            List of failing test cases
        """
        failures = []

        for i in range(num_tests):
            # Generate random input
            test_input = self._generate_test_input()

            # Test property
            try:
                result = await property_func(test_input) if asyncio.iscoroutinefunction(property_func) else property_func(test_input)

                if not result:
                    failures.append({
                        "test_number": i,
                        "input": test_input,
                        "result": result
                    })
            except Exception as e:
                failures.append({
                    "test_number": i,
                    "input": test_input,
                    "error": str(e)
                })

        return failures

    def _generate_test_input(self) -> Any:
        """Generate random test input"""
        input_types = [
            lambda: random.randint(-1000, 1000),
            lambda: random.random(),
            lambda: ''.join(random.choices(string.ascii_letters, k=random.randint(0, 100))),
            lambda: random.choice([True, False]),
            lambda: None,
            lambda: [],
            lambda: {},
        ]

        return random.choice(input_types)()
