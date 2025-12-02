"""
Authentication & Authorization Logic Scanner
Detects auth vulnerabilities and misconfigurations
"""

from .static_analyzer import AuthStaticAnalyzer, AuthVulnerability
from .runtime_simulator import AuthAttackSimulator, AuthAttackResult

__all__ = [
    "AuthStaticAnalyzer",
    "AuthVulnerability",
    "AuthAttackSimulator",
    "AuthAttackResult"
]
