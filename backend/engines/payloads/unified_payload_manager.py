"""
Unified Payload Manager
Combines PayloadsAllTheThings-inspired payloads with LLM-specific attacks
Provides intelligent payload selection and mutation
"""

import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from .payload_generator import PayloadGenerator, PayloadCategory, Payload
from .strix_fuzzer import StrixFuzzer, MutationStrategy, FuzzTarget
from ..llm_security.payload_generator import AdversarialPayloadGenerator, AttackCategory

logger = logging.getLogger(__name__)


@dataclass
class UnifiedPayload:
    """Unified payload structure"""
    payload: str
    category: str
    description: str
    severity: str
    attack_type: str  # "generic", "llm", "web"
    detection_bypass: bool = False
    encoding: Optional[str] = None
    metadata: Dict[str, Any] = None


class UnifiedPayloadManager:
    """
    Central payload management system
    Combines generic web attack payloads with LLM-specific attacks
    """

    def __init__(self):
        self.generic_payload_gen = PayloadGenerator()
        self.llm_payload_gen = AdversarialPayloadGenerator()
        self.fuzzer = StrixFuzzer()

    async def get_all_payloads(self) -> List[UnifiedPayload]:
        """Get all payloads from all sources"""
        unified_payloads = []

        # Get generic web attack payloads
        generic_payloads = self.generic_payload_gen.get_all_payloads()
        for payload in generic_payloads:
            unified = UnifiedPayload(
                payload=payload.payload,
                category=payload.category.value,
                description=payload.description,
                severity=payload.severity,
                attack_type="web",
                detection_bypass=payload.detection_bypass,
                encoding=payload.encoding,
                metadata=payload.metadata or {}
            )
            unified_payloads.append(unified)

        # Get LLM-specific payloads
        llm_payloads = await self.llm_payload_gen.generate_all_payloads()
        for payload in llm_payloads:
            unified = UnifiedPayload(
                payload=payload.payload,
                category=payload.category.value,
                description=payload.description,
                severity=payload.severity,
                attack_type="llm",
                detection_bypass=False,
                metadata=payload.metadata or {}
            )
            unified_payloads.append(unified)

        logger.info(f"Loaded {len(unified_payloads)} total payloads ({len(generic_payloads)} web + {len(llm_payloads)} LLM)")

        return unified_payloads

    async def get_payloads_for_scanner(self, scanner_type: str) -> List[UnifiedPayload]:
        """
        Get relevant payloads for a specific scanner type

        Args:
            scanner_type: "llm_security", "business_logic", "auth_scanner", etc.

        Returns:
            Filtered list of payloads
        """
        all_payloads = await self.get_all_payloads()

        if scanner_type == "llm_security":
            # Get LLM-specific + injection payloads
            return [p for p in all_payloads if p.attack_type == "llm" or
                    p.category in ["template_injection", "llm_injection"]]

        elif scanner_type == "business_logic":
            # Get SQLi, NoSQLi, logic-based attacks
            return [p for p in all_payloads if p.category in [
                "sql_injection", "nosql_injection", "command_injection",
                "path_traversal", "deserialization"
            ]]

        elif scanner_type == "auth_scanner":
            # Get auth-related attacks
            return [p for p in all_payloads if p.category in [
                "jwt_attacks", "oauth_attacks", "session_fixation"
            ]]

        elif scanner_type == "zero_day":
            # Get advanced/bypass payloads
            return [p for p in all_payloads if p.detection_bypass or p.severity == "critical"]

        elif scanner_type == "codeql":
            # Get payloads that match CodeQL query patterns
            return [p for p in all_payloads if p.category in [
                "sql_injection", "xss", "command_injection", "path_traversal"
            ]]

        else:
            # Return all for unknown scanner type
            return all_payloads

    def get_high_severity_payloads(self) -> List[UnifiedPayload]:
        """Get only critical and high severity payloads"""
        all_payloads = self.generic_payload_gen.get_all_payloads()

        unified_payloads = []
        for payload in all_payloads:
            if payload.severity in ["critical", "high"]:
                unified = UnifiedPayload(
                    payload=payload.payload,
                    category=payload.category.value,
                    description=payload.description,
                    severity=payload.severity,
                    attack_type="web",
                    detection_bypass=payload.detection_bypass,
                    encoding=payload.encoding,
                    metadata=payload.metadata or {}
                )
                unified_payloads.append(unified)

        return unified_payloads

    def get_bypass_payloads(self) -> List[UnifiedPayload]:
        """Get payloads designed to bypass WAF/detection"""
        all_payloads = self.generic_payload_gen.get_bypass_payloads()

        unified_payloads = []
        for payload in all_payloads:
            unified = UnifiedPayload(
                payload=payload.payload,
                category=payload.category.value,
                description=payload.description,
                severity=payload.severity,
                attack_type="web",
                detection_bypass=True,
                encoding=payload.encoding,
                metadata=payload.metadata or {}
            )
            unified_payloads.append(unified)

        return unified_payloads

    async def get_payloads_by_category(self, category: str) -> List[UnifiedPayload]:
        """Get payloads for specific attack category"""
        all_payloads = await self.get_all_payloads()
        return [p for p in all_payloads if p.category == category]

    async def generate_mutated_payloads(
        self,
        base_payloads: List[UnifiedPayload],
        mutation_count: int = 5
    ) -> List[UnifiedPayload]:
        """
        Generate mutated variants of payloads using fuzzing

        Args:
            base_payloads: Base payloads to mutate
            mutation_count: Number of mutations per payload

        Returns:
            List of mutated payloads
        """
        mutated = []

        for base_payload in base_payloads[:50]:  # Limit to 50 for performance
            # Use generic payload mutation
            if base_payload.attack_type == "web":
                original = Payload(
                    category=PayloadCategory(base_payload.category),
                    payload=base_payload.payload,
                    description=base_payload.description,
                    severity=base_payload.severity,
                    encoding=base_payload.encoding,
                    detection_bypass=base_payload.detection_bypass,
                    metadata=base_payload.metadata or {}
                )

                variants = self.generic_payload_gen.generate_variants(original, mutation_count)

                for variant in variants:
                    mutated.append(UnifiedPayload(
                        payload=variant.payload,
                        category=variant.category.value,
                        description=variant.description,
                        severity=variant.severity,
                        attack_type="web",
                        detection_bypass=True,
                        encoding=variant.encoding,
                        metadata=variant.metadata or {}
                    ))

        logger.info(f"Generated {len(mutated)} mutated payload variants")
        return mutated

    async def smart_payload_selection(
        self,
        target_info: Dict[str, Any],
        max_payloads: int = 100
    ) -> List[UnifiedPayload]:
        """
        Intelligently select payloads based on target characteristics

        Args:
            target_info: Information about the target (language, framework, features)
            max_payloads: Maximum number of payloads to return

        Returns:
            Optimized list of payloads
        """
        all_payloads = await self.get_all_payloads()

        # Score payloads based on target info
        scored_payloads = []

        for payload in all_payloads:
            score = self._score_payload_relevance(payload, target_info)
            scored_payloads.append((score, payload))

        # Sort by score (highest first)
        scored_payloads.sort(key=lambda x: x[0], reverse=True)

        # Return top N
        return [p for score, p in scored_payloads[:max_payloads]]

    def _score_payload_relevance(
        self,
        payload: UnifiedPayload,
        target_info: Dict[str, Any]
    ) -> float:
        """Score payload relevance to target"""
        score = 0.0

        # Base score by severity
        severity_scores = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 2.0
        }
        score += severity_scores.get(payload.severity, 1.0)

        # Boost for detection bypass
        if payload.detection_bypass:
            score += 5.0

        # Language-specific scoring
        language = target_info.get("language", "").lower()

        if language == "python":
            if payload.category in ["template_injection", "deserialization", "command_injection"]:
                score += 5.0
        elif language == "javascript" or language == "typescript":
            if payload.category in ["xss", "nosql_injection", "template_injection"]:
                score += 5.0
        elif language == "java":
            if payload.category in ["deserialization", "xxe", "sql_injection"]:
                score += 5.0
        elif language == "php":
            if payload.category in ["sql_injection", "file_upload", "deserialization"]:
                score += 5.0

        # Framework-specific scoring
        framework = target_info.get("framework", "").lower()

        if "express" in framework or "fastapi" in framework or "flask" in framework:
            if payload.category in ["sql_injection", "nosql_injection", "command_injection"]:
                score += 3.0

        if "react" in framework or "vue" in framework or "angular" in framework:
            if payload.category in ["xss"]:
                score += 3.0

        # Feature-based scoring
        features = target_info.get("features", [])

        if "llm" in features or "ai" in features:
            if payload.attack_type == "llm":
                score += 10.0

        if "auth" in features or "authentication" in features:
            if payload.category in ["jwt_attacks", "oauth_attacks"]:
                score += 7.0

        if "database" in features:
            if payload.category in ["sql_injection", "nosql_injection"]:
                score += 7.0

        if "file_upload" in features:
            if payload.category == "file_upload":
                score += 10.0

        return score

    async def get_payload_statistics(self) -> Dict[str, Any]:
        """Get statistics about available payloads"""
        all_payloads = await self.get_all_payloads()

        # Count by category
        category_counts = {}
        for payload in all_payloads:
            category_counts[payload.category] = category_counts.get(payload.category, 0) + 1

        # Count by severity
        severity_counts = {}
        for payload in all_payloads:
            severity_counts[payload.severity] = severity_counts.get(payload.severity, 0) + 1

        # Count by attack type
        attack_type_counts = {}
        for payload in all_payloads:
            attack_type_counts[payload.attack_type] = attack_type_counts.get(payload.attack_type, 0) + 1

        return {
            "total_payloads": len(all_payloads),
            "by_category": category_counts,
            "by_severity": severity_counts,
            "by_attack_type": attack_type_counts,
            "bypass_capable": len([p for p in all_payloads if p.detection_bypass])
        }
