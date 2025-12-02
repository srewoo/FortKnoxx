"""
Logic Violation Rule Engine
Detects business logic vulnerabilities using pattern matching
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum
import re
import logging
from .flow_analyzer import FlowGraph, APIEndpoint

logger = logging.getLogger(__name__)


class LogicViolationType(str, Enum):
    """Types of logic violations"""
    IDOR = "idor"
    WORKFLOW_BYPASS = "workflow_bypass"
    RACE_CONDITION = "race_condition"
    ROLE_BYPASS = "role_bypass"
    REPLAY_ATTACK = "replay_attack"
    PRICE_TAMPERING = "price_tampering"
    LIMIT_ABUSE = "limit_abuse"
    STATE_MANIPULATION = "state_manipulation"


class LogicViolation(BaseModel):
    """Detected logic violation"""
    type: LogicViolationType
    title: str
    description: str
    severity: str
    confidence: float

    # Location
    endpoint: str
    file_path: str
    line_number: int

    # Attack scenario
    attack_scenario: str
    proof_of_concept: Optional[str] = None

    # Remediation
    recommendation: str

    # Context
    affected_workflow: Optional[List[str]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class LogicRuleEngine:
    """Detects business logic vulnerabilities"""

    def __init__(self):
        self.violations: List[LogicViolation] = []

    async def analyze_flow_graph(self, flow_graph: FlowGraph, repo_path: str) -> List[LogicViolation]:
        """
        Analyze flow graph for logic vulnerabilities

        Args:
            flow_graph: Application flow graph
            repo_path: Repository path for code inspection

        Returns:
            List of detected violations
        """
        logger.info("Running logic rule engine analysis")

        self.violations = []

        # Run all detection rules
        await self._detect_idor(flow_graph, repo_path)
        await self._detect_workflow_bypass(flow_graph)
        await self._detect_race_conditions(flow_graph)
        await self._detect_role_bypass(flow_graph)
        await self._detect_price_tampering(flow_graph)
        await self._detect_replay_attacks(flow_graph)
        await self._detect_limit_abuse(flow_graph)

        logger.info(f"Found {len(self.violations)} logic violations")
        return self.violations

    async def _detect_idor(self, flow_graph: FlowGraph, repo_path: str):
        """Detect Insecure Direct Object References"""

        # Look for endpoints with ID parameters but no authorization checks
        for key, endpoint in flow_graph.endpoints.items():
            # Check if endpoint has ID parameter
            has_id_param = any(
                re.search(r'\{?\w*id\}?', param, re.IGNORECASE)
                for param in endpoint.parameters
            ) or re.search(r'/\{?\w*id\}?', endpoint.path, re.IGNORECASE)

            if has_id_param and endpoint.method in ['GET', 'PUT', 'DELETE']:
                # Check if there's proper authorization
                if not endpoint.requires_auth:
                    self.violations.append(LogicViolation(
                        type=LogicViolationType.IDOR,
                        title=f"Potential IDOR in {endpoint.path}",
                        description=f"Endpoint {endpoint.path} accepts ID parameter but lacks authentication",
                        severity="high",
                        confidence=0.8,
                        endpoint=key,
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        attack_scenario=(
                            "An attacker can access or modify resources belonging to other users "
                            "by manipulating the ID parameter without authentication."
                        ),
                        proof_of_concept=f"curl -X {endpoint.method} http://api.example.com{endpoint.path.replace('{id}', '1')}",
                        recommendation=(
                            "1. Add authentication to this endpoint\n"
                            "2. Implement ownership verification: ensure the authenticated user owns the resource\n"
                            "3. Use UUIDs instead of sequential IDs"
                        )
                    ))

                elif not self._has_ownership_check(endpoint, repo_path):
                    self.violations.append(LogicViolation(
                        type=LogicViolationType.IDOR,
                        title=f"Missing ownership check in {endpoint.path}",
                        description=f"Endpoint {endpoint.path} is authenticated but doesn't verify resource ownership",
                        severity="critical",
                        confidence=0.7,
                        endpoint=key,
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        attack_scenario=(
                            "An authenticated attacker can access or modify resources belonging to other users "
                            "by manipulating the ID parameter."
                        ),
                        recommendation=(
                            "Add ownership verification:\n"
                            "- Verify that current_user.id == resource.owner_id\n"
                            "- Or check if user has permission to access the resource"
                        )
                    ))

    async def _detect_workflow_bypass(self, flow_graph: FlowGraph):
        """Detect workflow bypass vulnerabilities"""

        # Check for workflows that can be bypassed
        for chain in flow_graph.workflow_chains:
            if len(chain) >= 3:
                # Check if later steps can be accessed without completing earlier steps
                final_step = chain[-1]

                # Look for endpoint matching final step
                final_endpoints = [
                    ep for ep in flow_graph.endpoints.values()
                    if final_step.lower() in ep.path.lower() or final_step.lower() in ep.function_name.lower()
                ]

                for endpoint in final_endpoints:
                    # Check if endpoint verifies prerequisite steps
                    if not self._has_prerequisite_checks(endpoint):
                        self.violations.append(LogicViolation(
                            type=LogicViolationType.WORKFLOW_BYPASS,
                            title=f"Workflow bypass in {endpoint.path}",
                            description=f"Endpoint {endpoint.path} doesn't verify prerequisite workflow steps",
                            severity="high",
                            confidence=0.6,
                            endpoint=f"{endpoint.method}:{endpoint.path}",
                            file_path=endpoint.file_path,
                            line_number=endpoint.line_number,
                            attack_scenario=(
                                f"An attacker can skip workflow steps {' -> '.join(chain[:-1])} "
                                f"and directly access {final_step}"
                            ),
                            affected_workflow=chain,
                            recommendation=(
                                "Add state verification:\n"
                                "1. Check that user has completed previous steps\n"
                                "2. Validate workflow state before allowing access\n"
                                "3. Use state machine pattern to enforce step order"
                            )
                        ))

    async def _detect_race_conditions(self, flow_graph: FlowGraph):
        """Detect potential race condition vulnerabilities"""

        # Look for endpoints that modify state without proper locking
        state_modifying = [
            ep for ep in flow_graph.endpoints.values()
            if ep.modifies_state and ep.method in ['POST', 'PUT', 'PATCH']
        ]

        for endpoint in state_modifying:
            # Check for financial or quantity operations
            sensitive_keywords = ['payment', 'balance', 'quantity', 'stock', 'credit', 'wallet']

            if any(kw in endpoint.path.lower() for kw in sensitive_keywords):
                self.violations.append(LogicViolation(
                    type=LogicViolationType.RACE_CONDITION,
                    title=f"Potential race condition in {endpoint.path}",
                    description=f"State-modifying endpoint {endpoint.path} may be vulnerable to race conditions",
                    severity="high",
                    confidence=0.5,
                    endpoint=f"{endpoint.method}:{endpoint.path}",
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    attack_scenario=(
                        "An attacker can send multiple concurrent requests to exploit race conditions, "
                        "potentially leading to double-spending, over-redemption, or data corruption."
                    ),
                    recommendation=(
                        "Implement concurrency controls:\n"
                        "1. Use database transactions with proper isolation levels\n"
                        "2. Implement optimistic or pessimistic locking\n"
                        "3. Use atomic operations where possible\n"
                        "4. Add idempotency keys for critical operations"
                    )
                ))

    async def _detect_role_bypass(self, flow_graph: FlowGraph):
        """Detect role-based access control bypasses"""

        # Look for admin endpoints without proper role checks
        admin_keywords = ['admin', 'manage', 'configure', 'settings']

        for key, endpoint in flow_graph.endpoints.items():
            if any(kw in endpoint.path.lower() for kw in admin_keywords):
                if not endpoint.required_roles or 'admin' not in [r.lower() for r in endpoint.required_roles]:
                    self.violations.append(LogicViolation(
                        type=LogicViolationType.ROLE_BYPASS,
                        title=f"Missing admin role check in {endpoint.path}",
                        description=f"Admin endpoint {endpoint.path} lacks proper role verification",
                        severity="critical",
                        confidence=0.7,
                        endpoint=key,
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        attack_scenario=(
                            "An authenticated user with lower privileges can access admin functionality"
                        ),
                        recommendation=(
                            "Add role-based access control:\n"
                            "1. Use @require_role([UserRole.ADMIN]) decorator\n"
                            "2. Verify user role in function logic\n"
                            "3. Implement principle of least privilege"
                        )
                    ))

    async def _detect_price_tampering(self, flow_graph: FlowGraph):
        """Detect price tampering vulnerabilities"""

        payment_keywords = ['payment', 'checkout', 'order', 'purchase', 'buy']

        for key, endpoint in flow_graph.endpoints.items():
            if any(kw in endpoint.path.lower() for kw in payment_keywords) and endpoint.method == 'POST':
                # Check if price is in parameters (client-controlled)
                if any('price' in param.lower() or 'amount' in param.lower() for param in endpoint.parameters):
                    self.violations.append(LogicViolation(
                        type=LogicViolationType.PRICE_TAMPERING,
                        title=f"Client-controlled price in {endpoint.path}",
                        description=f"Endpoint {endpoint.path} appears to accept price from client",
                        severity="critical",
                        confidence=0.6,
                        endpoint=key,
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        attack_scenario=(
                            "An attacker can manipulate the price parameter to purchase items at arbitrary prices"
                        ),
                        proof_of_concept=(
                            '{"item_id": "123", "price": 0.01, "quantity": 100}'
                        ),
                        recommendation=(
                            "Never trust client-provided prices:\n"
                            "1. Fetch price from server-side database using item_id\n"
                            "2. Calculate total on server side\n"
                            "3. Validate against expected price ranges\n"
                            "4. Log and alert on price discrepancies"
                        )
                    ))

    async def _detect_replay_attacks(self, flow_graph: FlowGraph):
        """Detect replay attack vulnerabilities"""

        sensitive_operations = ['otp', 'token', 'verify', 'reset', 'confirm']

        for key, endpoint in flow_graph.endpoints.items():
            if any(kw in endpoint.path.lower() for kw in sensitive_operations):
                self.violations.append(LogicViolation(
                    type=LogicViolationType.REPLAY_ATTACK,
                    title=f"Potential replay attack in {endpoint.path}",
                    description=f"Endpoint {endpoint.path} may not prevent token/OTP reuse",
                    severity="medium",
                    confidence=0.5,
                    endpoint=key,
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    attack_scenario=(
                        "An attacker can intercept and reuse OTPs, tokens, or verification codes"
                    ),
                    recommendation=(
                        "Implement replay protection:\n"
                        "1. Mark tokens as used after first use\n"
                        "2. Add expiration timestamps\n"
                        "3. Implement nonce values\n"
                        "4. Use one-time tokens for sensitive operations"
                    )
                ))

    async def _detect_limit_abuse(self, flow_graph: FlowGraph):
        """Detect rate limiting and abuse vulnerabilities"""

        abuse_prone = ['register', 'login', 'forgot', 'send', 'create', 'submit']

        for key, endpoint in flow_graph.endpoints.items():
            if any(kw in endpoint.path.lower() for kw in abuse_prone) and endpoint.method == 'POST':
                self.violations.append(LogicViolation(
                    type=LogicViolationType.LIMIT_ABUSE,
                    title=f"Missing rate limiting in {endpoint.path}",
                    description=f"Endpoint {endpoint.path} may lack rate limiting",
                    severity="medium",
                    confidence=0.4,
                    endpoint=key,
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    attack_scenario=(
                        "An attacker can abuse this endpoint with automated requests for:\n"
                        "- Brute force attacks\n"
                        "- Resource exhaustion\n"
                        "- Spam/abuse"
                    ),
                    recommendation=(
                        "Implement rate limiting:\n"
                        "1. Add per-IP rate limits\n"
                        "2. Implement per-user rate limits\n"
                        "3. Use CAPTCHA for sensitive operations\n"
                        "4. Add exponential backoff on failures"
                    )
                ))

    def _has_ownership_check(self, endpoint: APIEndpoint, repo_path: str) -> bool:
        """Check if endpoint verifies resource ownership"""
        try:
            with open(endpoint.file_path, 'r') as f:
                content = f.read()

            # Look for ownership verification patterns
            ownership_patterns = [
                r'current_user\.id\s*==',
                r'\.owner_id\s*==',
                r'check_ownership',
                r'verify_owner',
                r'can_access',
                r'has_permission'
            ]

            return any(re.search(pattern, content) for pattern in ownership_patterns)
        except:
            return False

    def _has_prerequisite_checks(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint verifies workflow prerequisites"""
        try:
            with open(endpoint.file_path, 'r') as f:
                content = f.read()

            prerequisite_patterns = [
                r'check_status',
                r'verify_state',
                r'has_completed',
                r'workflow_state',
                r'prerequisite'
            ]

            return any(re.search(pattern, content) for pattern in prerequisite_patterns)
        except:
            return False
