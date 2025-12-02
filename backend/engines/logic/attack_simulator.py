"""
Logic Attack Simulator
Simulates business logic attacks to verify vulnerabilities
Enhanced with runtime testing capabilities
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel
import asyncio
import logging
from .flow_analyzer import FlowGraph, APIEndpoint
from .rule_engine import LogicViolation, LogicViolationType
from .behavior_learner import APIBehaviorLearner
from .parameter_fuzzer import SmartParameterFuzzer, FuzzResult
from .race_condition_tester import RaceConditionTester, RaceTest, RaceConditionType

logger = logging.getLogger(__name__)


class AttackResult(BaseModel):
    """Result of an attack simulation"""
    violation_type: LogicViolationType
    endpoint: str
    success: bool
    attack_payload: str
    response: Optional[str] = None
    impact: str
    confidence: float


class LogicAttackSimulator:
    """
    Simulates logic attacks to verify vulnerabilities
    Enhanced with:
    - Runtime API testing
    - Parameter fuzzing
    - Race condition testing
    - Behavior learning
    """

    def __init__(self, enable_runtime_testing: bool = True):
        self.results: List[AttackResult] = []
        self.enable_runtime_testing = enable_runtime_testing

        # Runtime testing components
        self.behavior_learner: Optional[APIBehaviorLearner] = None
        self.parameter_fuzzer: Optional[SmartParameterFuzzer] = None
        self.race_tester: Optional[RaceConditionTester] = None

        if enable_runtime_testing:
            logger.info("Runtime testing enabled for Business Logic Scanner")

    async def simulate_attacks(
        self,
        flow_graph: FlowGraph,
        violations: List[LogicViolation],
        base_url: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None
    ) -> List[AttackResult]:
        """
        Generate attack simulations for detected violations

        Args:
            flow_graph: Application flow graph
            violations: Detected logic violations
            base_url: Optional base URL for runtime testing
            auth_headers: Optional authentication headers

        Returns:
            List of attack simulation results
        """
        logger.info(f"Simulating logic attacks (runtime_testing={self.enable_runtime_testing})")

        self.results = []

        # Initialize runtime testing components if enabled and base_url provided
        if self.enable_runtime_testing and base_url:
            self.behavior_learner = APIBehaviorLearner()
            self.parameter_fuzzer = SmartParameterFuzzer()
            self.race_tester = RaceConditionTester()

            async with self.behavior_learner, self.parameter_fuzzer, self.race_tester:
                await self._run_with_runtime_tests(
                    flow_graph, violations, base_url, auth_headers
                )
        else:
            # Static simulation only
            for violation in violations:
                if violation.type == LogicViolationType.IDOR:
                    await self._simulate_idor(violation, flow_graph)

                elif violation.type == LogicViolationType.WORKFLOW_BYPASS:
                    await self._simulate_workflow_bypass(violation, flow_graph)

                elif violation.type == LogicViolationType.PRICE_TAMPERING:
                    await self._simulate_price_tampering(violation, flow_graph)

                elif violation.type == LogicViolationType.RACE_CONDITION:
                    await self._simulate_race_condition(violation, flow_graph)

        logger.info(f"Generated {len(self.results)} attack simulations")
        return self.results

    async def _run_with_runtime_tests(
        self,
        flow_graph: FlowGraph,
        violations: List[LogicViolation],
        base_url: str,
        auth_headers: Optional[Dict[str, str]]
    ):
        """Run simulations with actual runtime testing"""

        for violation in violations:
            endpoint_key = violation.endpoint
            endpoint = flow_graph.endpoints.get(endpoint_key)

            if not endpoint:
                continue

            endpoint_url = f"{base_url.rstrip('/')}{endpoint.path}"

            # Run type-specific runtime tests
            if violation.type == LogicViolationType.IDOR:
                await self._test_idor_runtime(
                    violation, endpoint, endpoint_url, auth_headers
                )

            elif violation.type == LogicViolationType.PRICE_TAMPERING:
                await self._test_price_tampering_runtime(
                    violation, endpoint, endpoint_url, auth_headers
                )

            elif violation.type == LogicViolationType.RACE_CONDITION:
                await self._test_race_condition_runtime(
                    violation, endpoint, endpoint_url, auth_headers
                )

            else:
                # Fallback to static simulation
                if violation.type == LogicViolationType.WORKFLOW_BYPASS:
                    await self._simulate_workflow_bypass(violation, flow_graph)

    async def _simulate_idor(self, violation: LogicViolation, flow_graph: FlowGraph):
        """Simulate IDOR attack"""
        endpoint_key = violation.endpoint
        endpoint = flow_graph.endpoints.get(endpoint_key)

        if not endpoint:
            return

        # Generate attack payloads
        attack_scenarios = [
            {
                "description": "Sequential ID enumeration",
                "payload": f"curl -X {endpoint.method} http://api.example.com{self._replace_id(endpoint.path, '1')}",
                "impact": "Access to user ID 1's data"
            },
            {
                "description": "Backward enumeration",
                "payload": f"curl -X {endpoint.method} http://api.example.com{self._replace_id(endpoint.path, '-1')}",
                "impact": "Potential access to admin/system resources"
            },
            {
                "description": "High value ID targeting",
                "payload": f"curl -X {endpoint.method} http://api.example.com{self._replace_id(endpoint.path, '99999')}",
                "impact": "Access to arbitrary user data"
            }
        ]

        for scenario in attack_scenarios:
            self.results.append(AttackResult(
                violation_type=LogicViolationType.IDOR,
                endpoint=endpoint_key,
                success=True,  # Simulated success
                attack_payload=scenario["payload"],
                response="Simulation: Would return unauthorized data",
                impact=scenario["impact"],
                confidence=violation.confidence
            ))

    async def _simulate_workflow_bypass(self, violation: LogicViolation, flow_graph: FlowGraph):
        """Simulate workflow bypass attack"""
        if not violation.affected_workflow:
            return

        endpoint_key = violation.endpoint
        endpoint = flow_graph.endpoints.get(endpoint_key)

        if not endpoint:
            return

        workflow = violation.affected_workflow
        skipped_steps = workflow[:-1]

        newline = '\n'
        steps_joined = ' -> '.join(skipped_steps)
        attack_payload = (
            f"# Attack: Skip steps {steps_joined}{newline}"
            f"# Directly call final step:{newline}"
            f"curl -X {endpoint.method} http://api.example.com{endpoint.path}{newline}"
            f"  -H 'Content-Type: application/json'{newline}"
            f"  -d '{{\"direct_access\": true}}'"
        )

        self.results.append(AttackResult(
            violation_type=LogicViolationType.WORKFLOW_BYPASS,
            endpoint=endpoint_key,
            success=True,
            attack_payload=attack_payload,
            response=f"Simulation: Successfully bypassed {len(skipped_steps)} prerequisite steps",
            impact=f"Completed workflow without {', '.join(skipped_steps)}",
            confidence=violation.confidence
        ))

    async def _simulate_price_tampering(self, violation: LogicViolation, flow_graph: FlowGraph):
        """Simulate price tampering attack"""
        endpoint_key = violation.endpoint
        endpoint = flow_graph.endpoints.get(endpoint_key)

        if not endpoint:
            return

        attack_scenarios = [
            {
                "price": 0.01,
                "impact": "Purchase $1000 item for $0.01"
            },
            {
                "price": -100,
                "impact": "Negative price could credit attacker's account"
            },
            {
                "price": 999999999,
                "impact": "Integer overflow attack"
            }
        ]

        for scenario in attack_scenarios:
            newline = '\n'
            price_val = scenario["price"]
            attack_payload = (
                f"curl -X POST http://api.example.com{endpoint.path}{newline}"
                f"  -H 'Content-Type: application/json'{newline}"
                f"  -d '{{{newline}"
                f'    "item_id": "premium_product",{newline}'
                f'    "quantity": 1,{newline}'
                f'    "price": {price_val}{newline}'
                f"  }}'"
            )

            self.results.append(AttackResult(
                violation_type=LogicViolationType.PRICE_TAMPERING,
                endpoint=endpoint_key,
                success=True,
                attack_payload=attack_payload,
                response="Simulation: Order accepted with tampered price",
                impact=scenario["impact"],
                confidence=violation.confidence
            ))

    async def _simulate_race_condition(self, violation: LogicViolation, flow_graph: FlowGraph):
        """Simulate race condition attack"""
        endpoint_key = violation.endpoint
        endpoint = flow_graph.endpoints.get(endpoint_key)

        if not endpoint:
            return

        newline = '\n'
        backslash = '\\'
        attack_payload = (
            f"# Race condition attack: Send 100 concurrent requests{newline}"
            f"for i in {{1..100}}; do{newline}"
            f"  curl -X {endpoint.method} http://api.example.com{endpoint.path} {backslash}{newline}"
            f"    -H 'Content-Type: application/json' {backslash}{newline}"
            f"    -d '{{\"action\": \"withdraw\", \"amount\": 100}}' &{newline}"
            f"done{newline}"
            f"wait"
        )

        self.results.append(AttackResult(
            violation_type=LogicViolationType.RACE_CONDITION,
            endpoint=endpoint_key,
            success=True,
            attack_payload=attack_payload,
            response="Simulation: Multiple requests processed before balance update",
            impact="Double-spending: Withdraw $100 multiple times with $100 balance",
            confidence=violation.confidence
        ))

    def _replace_id(self, path: str, new_id: str) -> str:
        """Replace ID parameter in path"""
        import re
        # Replace {id}, {user_id}, etc.
        path = re.sub(r'\{[^}]*id[^}]*\}', new_id, path, flags=re.IGNORECASE)
        # Replace /id/ patterns
        path = re.sub(r'/\d+', f'/{new_id}', path)
        return path

    def generate_security_test_suite(self, violations: List[LogicViolation]) -> str:
        """Generate automated security test suite"""
        newline = '\n'
        test_suite = f"# Auto-generated Security Test Suite{newline}{newline}"
        test_suite += f"import pytest{newline}import asyncio{newline}{newline}"

        for i, violation in enumerate(violations):
            test_name = f"test_{violation.type.value}_{i}"

            test_suite += f"async def {test_name}():{newline}"
            test_suite += f"    \"\"\"{newline}"
            test_suite += f"    Test for: {violation.title}{newline}"
            test_suite += f"    Severity: {violation.severity}{newline}"
            test_suite += f"    \"\"\"{newline}"
            test_suite += f"    # {violation.attack_scenario}{newline}"
            test_suite += f"    # TODO: Implement actual test{newline}"
            test_suite += f"    assert False, 'Security vulnerability detected: {violation.title}'{newline}{newline}"

        return test_suite

    # ========================================
    # RUNTIME TESTING METHODS
    # ========================================

    async def _test_idor_runtime(
        self,
        violation: LogicViolation,
        endpoint: APIEndpoint,
        endpoint_url: str,
        auth_headers: Optional[Dict[str, str]]
    ):
        """Test IDOR vulnerability with actual API calls"""
        logger.info(f"Runtime testing IDOR on {endpoint_url}")

        # Test sequential ID access
        test_ids = [1, 2, 3, 999, -1]

        for test_id in test_ids:
            test_url = self._replace_id_in_url(endpoint_url, str(test_id))

            try:
                # Learn baseline behavior first
                baseline_requests = [
                    {'method': endpoint.method, 'data': {}}
                ]
                await self.behavior_learner.learn_endpoint_behavior(
                    test_url, baseline_requests, auth_headers
                )

                # Test anomaly
                is_anomaly, score, reason = await self.behavior_learner.detect_anomalies(
                    test_url,
                    {'method': endpoint.method, 'data': {}},
                    auth_headers
                )

                if not is_anomaly:
                    # Unauthorized access succeeded
                    self.results.append(AttackResult(
                        violation_type=LogicViolationType.IDOR,
                        endpoint=violation.endpoint,
                        success=True,
                        attack_payload=f"Accessed {test_url} with ID {test_id}",
                        response=f"IDOR confirmed: Successfully accessed resource {test_id}",
                        impact=f"Unauthorized access to resource ID {test_id}",
                        confidence=0.9
                    ))
                    logger.warning(f"IDOR vulnerability confirmed for ID {test_id}")
                    break

            except Exception as e:
                logger.debug(f"Error testing IDOR with ID {test_id}: {str(e)}")

    async def _test_price_tampering_runtime(
        self,
        violation: LogicViolation,
        endpoint: APIEndpoint,
        endpoint_url: str,
        auth_headers: Optional[Dict[str, str]]
    ):
        """Test price tampering with actual API calls"""
        logger.info(f"Runtime testing price tampering on {endpoint_url}")

        # Learn parameter profiles from legitimate requests
        legitimate_requests = [
            {
                'method': 'POST',
                'data': {'item_id': 'test', 'quantity': 1, 'price': 100.0}
            }
        ]

        await self.parameter_fuzzer.learn_parameters(
            endpoint_url,
            legitimate_requests,
            auth_headers
        )

        # Fuzz price parameter
        test_request = {'method': 'POST', 'data': {'item_id': 'test', 'quantity': 1, 'price': 100.0}}

        fuzz_results = await self.parameter_fuzzer.execute_fuzz_tests(
            endpoint_url,
            test_request,
            'price',
            auth_headers
        )

        # Check for vulnerabilities
        for fuzz_result in fuzz_results:
            if fuzz_result.is_vulnerability:
                self.results.append(AttackResult(
                    violation_type=LogicViolationType.PRICE_TAMPERING,
                    endpoint=violation.endpoint,
                    success=True,
                    attack_payload=f"Fuzz test: {fuzz_result.test.test_name} with value {fuzz_result.test.fuzz_value}",
                    response=f"Status: {fuzz_result.status_code}, {fuzz_result.error_message or 'Success'}",
                    impact=fuzz_result.description,
                    confidence=0.9
                ))
                logger.warning(
                    f"Price tampering vulnerability confirmed: {fuzz_result.vulnerability_type}"
                )

    async def _test_race_condition_runtime(
        self,
        violation: LogicViolation,
        endpoint: APIEndpoint,
        endpoint_url: str,
        auth_headers: Optional[Dict[str, str]]
    ):
        """Test race condition with actual concurrent API calls"""
        logger.info(f"Runtime testing race condition on {endpoint_url}")

        # Prepare race test
        race_test = RaceTest(
            test_name="business_logic_race",
            description=f"Test race condition on {endpoint.path}",
            race_type=RaceConditionType.DOUBLE_SPENDING,
            endpoint_url=endpoint_url,
            request_template={
                'method': endpoint.method,
                'data': {'action': 'withdraw', 'amount': 100}
            },
            headers=auth_headers,
            num_concurrent_requests=20,
            expected_successful_requests=1
        )

        # Execute race test
        result = await self.race_tester.test_race_condition(race_test)

        if result.is_vulnerable:
            self.results.append(AttackResult(
                violation_type=LogicViolationType.RACE_CONDITION,
                endpoint=violation.endpoint,
                success=True,
                attack_payload=f"Sent {result.total_requests} concurrent requests",
                response=f"{result.successful_requests} requests succeeded (expected {race_test.expected_successful_requests})",
                impact=result.vulnerability_description,
                confidence=0.95
            ))
            logger.warning(f"Race condition vulnerability confirmed: {result.vulnerability_description}")

    def _replace_id_in_url(self, url: str, new_id: str) -> str:
        """Replace ID parameter in URL"""
        import re
        # Replace {id}, {user_id}, etc.
        url = re.sub(r'\{[^}]*id[^}]*\}', new_id, url, flags=re.IGNORECASE)
        # Replace /id/ patterns
        url = re.sub(r'/\d+', f'/{new_id}', url)
        return url
