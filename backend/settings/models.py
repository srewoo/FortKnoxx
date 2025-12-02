"""
Settings Models for FortKnoxx
Stores configuration and API keys in MongoDB
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from enum import Enum


class SettingCategory(str, Enum):
    """Categories for different types of settings"""
    LLM_API_KEYS = "llm_api_keys"
    SCANNER_CONFIG = "scanner_config"
    SYSTEM = "system"
    GIT_INTEGRATIONS = "git_integrations"


class GitProvider(str, Enum):
    """Supported Git providers"""
    GITHUB = "github"
    GITLAB = "gitlab"


class GitIntegration(BaseModel):
    """Model for a Git provider integration"""
    provider: GitProvider
    name: str = Field(..., description="Display name for this integration")
    access_token: Optional[str] = Field(default=None, description="Personal access token or OAuth token")
    base_url: Optional[str] = Field(default=None, description="Base URL for self-hosted instances (e.g., GitLab Enterprise)")
    is_connected: bool = Field(default=False, description="Whether the integration is active")
    username: Optional[str] = Field(default=None, description="Connected username/org")
    webhook_secret: Optional[str] = Field(default=None, description="Secret for webhook verification")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_schema_extra = {
            "example": {
                "provider": "github",
                "name": "My GitHub",
                "access_token": "ghp_...",
                "base_url": None,
                "is_connected": True,
                "username": "myorg",
                "webhook_secret": "whsec_..."
            }
        }


class GitRepository(BaseModel):
    """Model for a connected Git repository"""
    repo_id: str = Field(..., description="Unique repository identifier")
    provider: GitProvider
    full_name: str = Field(..., description="Full repository name (e.g., owner/repo)")
    name: str = Field(..., description="Repository name")
    owner: str = Field(..., description="Repository owner")
    clone_url: str = Field(..., description="URL to clone the repository")
    default_branch: str = Field(default="main", description="Default branch name")
    private: bool = Field(default=False, description="Whether the repo is private")
    auto_scan: bool = Field(default=False, description="Auto-scan on push events")
    last_scanned: Optional[datetime] = Field(default=None, description="Last scan timestamp")
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_schema_extra = {
            "example": {
                "repo_id": "github_12345",
                "provider": "github",
                "full_name": "myorg/myrepo",
                "name": "myrepo",
                "owner": "myorg",
                "clone_url": "https://github.com/myorg/myrepo.git",
                "default_branch": "main",
                "private": False,
                "auto_scan": True
            }
        }


class APIKeySetting(BaseModel):
    """Model for API key settings"""
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API key for GPT models")
    anthropic_api_key: Optional[str] = Field(default=None, description="Anthropic API key for Claude models")
    gemini_api_key: Optional[str] = Field(default=None, description="Google Gemini API key")
    github_token: Optional[str] = Field(default=None, description="GitHub token for better rate limits")
    snyk_token: Optional[str] = Field(default=None, description="Snyk authentication token")

    class Config:
        json_schema_extra = {
            "example": {
                "openai_api_key": "sk-...",
                "anthropic_api_key": "sk-ant-...",
                "gemini_api_key": "AI...",
                "github_token": "ghp_...",
                "snyk_token": "..."
            }
        }


class Setting(BaseModel):
    """Generic setting document"""
    setting_id: str = Field(default_factory=lambda: f"setting_{datetime.now(timezone.utc).timestamp()}")
    category: SettingCategory
    key: str = Field(..., description="Setting key/name")
    value: Any = Field(..., description="Setting value (can be any type)")
    encrypted: bool = Field(default=False, description="Whether the value is encrypted")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_by: Optional[str] = Field(default=None, description="User who last updated this setting")

    class Config:
        json_schema_extra = {
            "example": {
                "setting_id": "setting_1234567890",
                "category": "llm_api_keys",
                "key": "openai_api_key",
                "value": "sk-...",
                "encrypted": True,
                "updated_at": "2025-12-01T00:00:00Z",
                "updated_by": "admin"
            }
        }


class GitIntegrationStatus(BaseModel):
    """Status of a Git integration (without sensitive data)"""
    provider: GitProvider
    name: str
    is_connected: bool
    username: Optional[str] = None
    base_url: Optional[str] = None
    has_webhook: bool = False
    updated_at: Optional[datetime] = None


class SettingsResponse(BaseModel):
    """Response model for settings API"""
    llm_api_keys: Dict[str, bool] = Field(
        default_factory=dict,
        description="Status of LLM API keys (key: is_set)"
    )
    scanner_settings: Optional['ScannerSettings'] = Field(
        default=None,
        description="All scanner enable/disable settings"
    )
    ai_scanner_settings: Dict[str, bool] = Field(
        default_factory=dict,
        description="DEPRECATED: Use scanner_settings instead"
    )
    scanner_config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Scanner configurations"
    )
    system: Dict[str, Any] = Field(
        default_factory=dict,
        description="System settings"
    )
    git_integrations: List[GitIntegrationStatus] = Field(
        default_factory=list,
        description="Connected Git provider integrations"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "llm_api_keys": {
                    "openai_api_key": True,
                    "anthropic_api_key": False,
                    "gemini_api_key": True,
                    "github_token": True,
                    "snyk_token": False
                },
                "scanner_config": {},
                "system": {},
                "git_integrations": [
                    {
                        "provider": "github",
                        "name": "My GitHub",
                        "is_connected": True,
                        "username": "myorg",
                        "has_webhook": True
                    }
                ]
            }
        }


class ScannerSettings(BaseModel):
    """Settings for all security scanners - user can enable/disable each scanner"""

    # Core Security Scanners (SAST)
    enable_semgrep: bool = Field(default=True, description="Semgrep - Multi-language SAST")
    enable_bandit: bool = Field(default=True, description="Bandit - Python security scanner")
    enable_gitleaks: bool = Field(default=True, description="Gitleaks - Secret detection")
    enable_trufflehog: bool = Field(default=True, description="TruffleHog - Secret scanning")
    enable_trivy: bool = Field(default=True, description="Trivy - Vulnerability scanner")
    enable_grype: bool = Field(default=True, description="Grype - Vulnerability detection")
    enable_checkov: bool = Field(default=True, description="Checkov - IaC security")
    enable_eslint: bool = Field(default=True, description="ESLint - JavaScript/TypeScript security")

    # Quality Scanners
    enable_pylint: bool = Field(default=True, description="Pylint - Python quality")
    enable_flake8: bool = Field(default=True, description="Flake8 - Python style")
    enable_radon: bool = Field(default=True, description="Radon - Complexity analysis")
    enable_shellcheck: bool = Field(default=True, description="ShellCheck - Shell script analysis")
    enable_hadolint: bool = Field(default=True, description="Hadolint - Dockerfile linter")
    enable_sqlfluff: bool = Field(default=True, description="SQLFluff - SQL linter")
    enable_pydeps: bool = Field(default=True, description="Pydeps - Dependency analysis")

    # Compliance Scanners
    enable_pip_audit: bool = Field(default=True, description="pip-audit - Python dependency audit")
    enable_npm_audit: bool = Field(default=True, description="npm-audit - Node.js dependency audit")
    enable_syft: bool = Field(default=True, description="Syft - SBOM generation")

    # Advanced Scanners
    enable_nuclei: bool = Field(default=True, description="Nuclei - CVE template scanner")
    enable_codeql: bool = Field(default=False, description="CodeQL - Semantic analysis (requires setup)")

    # High-Value Scanners
    enable_snyk: bool = Field(default=True, description="Snyk - Modern dependency scanner")
    enable_gosec: bool = Field(default=True, description="Gosec - Go security")
    enable_spotbugs: bool = Field(default=True, description="SpotBugs - Java bytecode analysis")
    enable_pyre: bool = Field(default=True, description="Pyre - Python type checker")
    enable_horusec: bool = Field(default=True, description="Horusec - Multi-language SAST")

    # Web & API Security
    enable_zap: bool = Field(default=True, description="OWASP ZAP - Web security patterns (static)")
    enable_zap_dast: bool = Field(default=False, description="OWASP ZAP DAST - Dynamic scanning (requires Docker)")
    enable_api_fuzzer: bool = Field(default=True, description="API Fuzzer - Dedicated API security testing")

    # AI-Powered Scanners
    enable_zero_day_detector: bool = Field(default=True, description="ML-based zero-day detection")
    enable_business_logic_scanner: bool = Field(default=True, description="Business logic flaw detection")
    enable_llm_security_scanner: bool = Field(default=True, description="LLM prompt injection testing")
    enable_auth_scanner: bool = Field(default=True, description="Authentication vulnerability scanner")

    class Config:
        json_schema_extra = {
            "example": {
                "enable_semgrep": True,
                "enable_bandit": True,
                "enable_zap_dast": False,
                "enable_api_fuzzer": True,
                "enable_zero_day_detector": True
            }
        }


class AIScannerSettings(BaseModel):
    """DEPRECATED: Use ScannerSettings instead. Kept for backwards compatibility."""
    enable_zero_day_detector: bool = Field(default=True, description="Enable ML-based zero-day detection")
    enable_business_logic_scanner: bool = Field(default=True, description="Enable business logic flaw detection")
    enable_llm_security_scanner: bool = Field(default=True, description="Enable LLM prompt injection testing")
    enable_auth_scanner: bool = Field(default=True, description="Enable authentication vulnerability scanner")

    class Config:
        json_schema_extra = {
            "example": {
                "enable_zero_day_detector": True,
                "enable_business_logic_scanner": True,
                "enable_llm_security_scanner": True,
                "enable_auth_scanner": False
            }
        }


class UpdateScannerSettingsRequest(BaseModel):
    """Request model for updating scanner settings - any scanner can be enabled/disabled"""
    # Core Security Scanners
    enable_semgrep: Optional[bool] = None
    enable_bandit: Optional[bool] = None
    enable_gitleaks: Optional[bool] = None
    enable_trufflehog: Optional[bool] = None
    enable_trivy: Optional[bool] = None
    enable_grype: Optional[bool] = None
    enable_checkov: Optional[bool] = None
    enable_eslint: Optional[bool] = None

    # Quality Scanners
    enable_pylint: Optional[bool] = None
    enable_flake8: Optional[bool] = None
    enable_radon: Optional[bool] = None
    enable_shellcheck: Optional[bool] = None
    enable_hadolint: Optional[bool] = None
    enable_sqlfluff: Optional[bool] = None
    enable_pydeps: Optional[bool] = None

    # Compliance Scanners
    enable_pip_audit: Optional[bool] = None
    enable_npm_audit: Optional[bool] = None
    enable_syft: Optional[bool] = None

    # Advanced Scanners
    enable_nuclei: Optional[bool] = None
    enable_codeql: Optional[bool] = None

    # High-Value Scanners
    enable_snyk: Optional[bool] = None
    enable_gosec: Optional[bool] = None
    enable_spotbugs: Optional[bool] = None
    enable_pyre: Optional[bool] = None
    enable_horusec: Optional[bool] = None

    # Web & API Security
    enable_zap: Optional[bool] = None
    enable_zap_dast: Optional[bool] = None
    enable_api_fuzzer: Optional[bool] = None

    # AI-Powered Scanners
    enable_zero_day_detector: Optional[bool] = None
    enable_business_logic_scanner: Optional[bool] = None
    enable_llm_security_scanner: Optional[bool] = None
    enable_auth_scanner: Optional[bool] = None


class UpdateAIScannerSettingsRequest(BaseModel):
    """DEPRECATED: Use UpdateScannerSettingsRequest instead. Kept for backwards compatibility."""
    enable_zero_day_detector: Optional[bool] = None
    enable_business_logic_scanner: Optional[bool] = None
    enable_llm_security_scanner: Optional[bool] = None
    enable_auth_scanner: Optional[bool] = None


class UpdateAPIKeysRequest(BaseModel):
    """Request model for updating API keys"""
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    github_token: Optional[str] = None
    snyk_token: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "openai_api_key": "sk-...",
                "anthropic_api_key": "sk-ant-...",
                "gemini_api_key": "AI...",
                "github_token": "ghp_...",
                "snyk_token": "..."
            }
        }


class ConnectGitIntegrationRequest(BaseModel):
    """Request model for connecting a Git provider"""
    provider: GitProvider
    name: str = Field(..., description="Display name for this integration")
    access_token: str = Field(..., description="Personal access token")
    base_url: Optional[str] = Field(default=None, description="Base URL for self-hosted (e.g., https://gitlab.company.com)")

    class Config:
        json_schema_extra = {
            "example": {
                "provider": "github",
                "name": "My GitHub Account",
                "access_token": "ghp_xxxxxxxxxxxx",
                "base_url": None
            }
        }


class AddRepositoryRequest(BaseModel):
    """Request model for adding a repository to scan"""
    provider: GitProvider
    repo_url: str = Field(..., description="Repository URL (e.g., https://github.com/owner/repo)")
    auto_scan: bool = Field(default=False, description="Enable auto-scan on push")
    branch: Optional[str] = Field(default=None, description="Branch to scan (defaults to default branch)")
    access_token: Optional[str] = Field(default=None, description="Access token for private repos (optional for public repos)")
    is_public: bool = Field(default=False, description="Whether this is a public repository (no token required)")

    class Config:
        json_schema_extra = {
            "example": {
                "provider": "github",
                "repo_url": "https://github.com/myorg/myrepo",
                "auto_scan": True,
                "branch": "main",
                "is_public": True
            }
        }


class WebhookEvent(BaseModel):
    """Model for incoming webhook events"""
    provider: GitProvider
    event_type: str = Field(..., description="Event type (e.g., push, pull_request)")
    repository: str = Field(..., description="Repository full name")
    branch: str = Field(..., description="Branch name")
    commit_sha: Optional[str] = None
    sender: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


# Resolve forward references
SettingsResponse.model_rebuild()
