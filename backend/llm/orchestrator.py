"""
Multi-LLM Orchestrator
Direct integration with free LLM APIs: OpenAI, Anthropic, Google Gemini
No third-party dependencies - uses official SDKs only
"""

import logging
import os
from typing import Optional, Dict, Any
import asyncio

logger = logging.getLogger(__name__)


class LLMOrchestrator:
    """
    Orchestrates requests to multiple LLM providers
    Supports: OpenAI, Anthropic (Claude), Google Gemini
    """

    def __init__(self, db=None, settings_manager=None):
        """Initialize with API keys from settings manager, environment, or database"""
        self.db = db
        self.settings_manager = settings_manager
        self.openai_key = None
        self.anthropic_key = None
        self.gemini_key = None

        # Lazy-load clients
        self._openai_client = None
        self._anthropic_client = None
        self._gemini_client = None
        self._keys_loaded = False

    async def _load_keys(self):
        """Load API keys from settings manager, environment, or database"""
        if self._keys_loaded:
            return

        # Priority 1: Settings Manager (database with encryption)
        if self.settings_manager:
            try:
                keys = await self.settings_manager.get_api_keys()
                self.openai_key = keys.get("openai_api_key")
                self.anthropic_key = keys.get("anthropic_api_key")
                self.gemini_key = keys.get("gemini_api_key")
                logger.info("Loaded API keys from settings manager")
            except Exception as e:
                logger.warning(f"Failed to load API keys from settings manager: {e}")

        # Priority 2: Environment variables (backwards compatibility)
        if not self.openai_key:
            self.openai_key = os.getenv("OPENAI_API_KEY")
        if not self.anthropic_key:
            self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.gemini_key:
            self.gemini_key = os.getenv("GEMINI_API_KEY")

        # Priority 3: Legacy database settings
        if self.db is not None and (not self.openai_key or not self.anthropic_key or not self.gemini_key):
            await self._load_keys_from_db()

        self._keys_loaded = True

        # Log warning about missing API keys
        missing_providers = []
        if not self.openai_key:
            missing_providers.append("OpenAI")
        if not self.anthropic_key:
            missing_providers.append("Anthropic")
        if not self.gemini_key:
            missing_providers.append("Gemini")

        if missing_providers:
            logger.warning(
                f"⚠️  LLM API keys not configured for: {', '.join(missing_providers)}. "
                "AI-powered features (vulnerability fixes, LLM security testing) will be unavailable for these providers. "
                "Configure keys in Settings > API Keys or set environment variables."
            )

    async def _load_keys_from_db(self):
        """Load API keys from database if not in environment (legacy)"""
        if self.db is None:
            return

        try:
            settings = await self.db.settings.find_one({"type": "api_keys"}, {"_id": 0})
            if settings:
                if not self.openai_key and settings.get("openai_key"):
                    self.openai_key = settings["openai_key"]
                if not self.anthropic_key and settings.get("anthropic_key"):
                    self.anthropic_key = settings["anthropic_key"]
                if not self.gemini_key and settings.get("gemini_key"):
                    self.gemini_key = settings["gemini_key"]
        except Exception as e:
            logger.warning(f"Failed to load API keys from database: {e}")

    def _get_openai_client(self):
        """Get or create OpenAI client"""
        if not self.openai_key:
            raise ValueError("OPENAI_API_KEY not set in environment")

        if self._openai_client is None:
            try:
                import openai
                import httpx
                # Create custom httpx client without proxy to avoid compatibility issues
                http_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(60.0, connect=10.0)
                )
                self._openai_client = openai.AsyncOpenAI(
                    api_key=self.openai_key,
                    http_client=http_client
                )
            except Exception as e:
                # Fallback: try basic initialization
                import openai
                self._openai_client = openai.AsyncOpenAI(api_key=self.openai_key)

        return self._openai_client

    def _get_anthropic_client(self):
        """Get or create Anthropic client"""
        if not self.anthropic_key:
            raise ValueError("ANTHROPIC_API_KEY not set in environment")

        if self._anthropic_client is None:
            try:
                import anthropic
                import httpx
                # Create custom httpx client without proxy to avoid compatibility issues
                http_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(60.0, connect=10.0)
                )
                self._anthropic_client = anthropic.AsyncAnthropic(
                    api_key=self.anthropic_key,
                    http_client=http_client
                )
            except ImportError:
                raise ImportError("anthropic package not installed. Run: pip install anthropic")
            except Exception as e:
                # Fallback to basic initialization if parameters fail
                import anthropic
                self._anthropic_client = anthropic.AsyncAnthropic(api_key=self.anthropic_key)

        return self._anthropic_client

    def _get_gemini_client(self):
        """Get or create Gemini client"""
        if not self.gemini_key:
            raise ValueError("GEMINI_API_KEY not set in environment")

        if self._gemini_client is None:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.gemini_key)
                self._gemini_client = genai
            except ImportError:
                raise ImportError("google-generativeai package not installed. Run: pip install google-generativeai")

        return self._gemini_client

    async def generate_completion(
        self,
        provider: str,
        model: str,
        messages: list,
        system_message: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 5000
    ) -> str:
        """
        Generate completion from specified LLM provider

        Args:
            provider: "openai", "anthropic", or "gemini"
            model: Model name (e.g., "gpt-4oo", "claude-4-sonnet-20250514", "gemini-2.0-flash-exp")
            messages: List of message dicts with "role" and "content"
            system_message: Optional system prompt
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens in response

        Returns:
            Generated text response
        """
        # Load API keys from settings manager, environment, or database
        await self._load_keys()

        provider = provider.lower()

        try:
            if provider == "openai":
                return await self._openai_completion(
                    model, messages, system_message, temperature, max_tokens
                )
            elif provider == "anthropic":
                return await self._anthropic_completion(
                    model, messages, system_message, temperature, max_tokens
                )
            elif provider == "gemini":
                return await self._gemini_completion(
                    model, messages, system_message, temperature, max_tokens
                )
            else:
                raise ValueError(f"Unknown provider: {provider}. Supported: openai, anthropic, gemini")

        except Exception as e:
            logger.error(f"Error calling {provider} API: {str(e)}")
            raise

    async def _openai_completion(
        self,
        model: str,
        messages: list,
        system_message: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> str:
        """Generate completion using OpenAI API"""
        client = self._get_openai_client()

        # Add system message if provided
        api_messages = []
        if system_message:
            api_messages.append({"role": "system", "content": system_message})

        api_messages.extend(messages)

        response = await client.chat.completions.create(
            model=model,
            messages=api_messages,
            temperature=temperature,
            max_tokens=max_tokens
        )

        return response.choices[0].message.content

    async def _anthropic_completion(
        self,
        model: str,
        messages: list,
        system_message: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> str:
        """Generate completion using Anthropic Claude API"""
        client = self._get_anthropic_client()

        # Anthropic API structure is slightly different
        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_message or "",
            messages=messages
        )

        return response.content[0].text

    async def _gemini_completion(
        self,
        model: str,
        messages: list,
        system_message: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> str:
        """Generate completion using Google Gemini API"""
        genai = self._get_gemini_client()

        # Create model instance
        model_instance = genai.GenerativeModel(
            model_name=model,
            generation_config={
                "temperature": temperature,
                "max_output_tokens": max_tokens,
            }
        )

        # Combine system message and user messages
        prompt_parts = []
        if system_message:
            prompt_parts.append(f"System: {system_message}\n\n")

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            prompt_parts.append(f"{role.capitalize()}: {content}\n\n")

        full_prompt = "".join(prompt_parts)

        # Generate response
        response = await asyncio.to_thread(
            model_instance.generate_content,
            full_prompt
        )

        return response.text

    async def generate_vulnerability_fix(
        self,
        provider: str,
        model: str,
        vulnerability: Dict[str, Any]
    ) -> str:
        """
        Generate AI-powered fix recommendation for a vulnerability

        Args:
            provider: LLM provider to use
            model: Model name
            vulnerability: Vulnerability dictionary with details

        Returns:
            Markdown-formatted fix recommendation
        """
        # Extract and limit code snippet to avoid token limits
        code_snippet = vulnerability.get('code_snippet', 'No code snippet available')
        # Limit code snippet to ~5000 characters to stay within token limits
        if len(code_snippet) > 5000:
            code_snippet = code_snippet[:5000] + "\n... (truncated)"

        # Get description, limit to 1000 chars
        description = vulnerability.get('description', 'No description available')
        if len(description) > 1000:
            description = description[:1000] + "..."

        # Build concise prompt - only essential information
        prompt = f"""Analyze this security vulnerability and provide a fix recommendation:

**Vulnerability:**
- **Type**: {vulnerability.get('category', 'Unknown')}
- **Severity**: {vulnerability.get('severity', 'Unknown')}
- **File**: {vulnerability.get('file_path', 'Unknown')}
- **Line**: {vulnerability.get('line_start', 'Unknown')}
- **CWE**: {vulnerability.get('cwe', 'Unknown')}

**Description:**
{description}

**Vulnerable Code:**
```
{code_snippet}
```

Please provide:
1. Brief explanation of the vulnerability
2. How to fix it (step-by-step)
3. Secure code example
4. Prevention tips

Format your response in markdown."""

        system_message = """You are a security expert. Provide concise, actionable fix recommendations with code examples."""

        messages = [{"role": "user", "content": prompt}]

        return await self.generate_completion(
            provider=provider,
            model=model,
            messages=messages,
            system_message=system_message,
            temperature=0.3,
            max_tokens=10000
        )

    def get_available_models(self, provider: str) -> Dict[str, list]:
        """Get list of available models for a provider"""
        models = {
            "openai": [
                {"id": "gpt-4o-mini", "name": "GPT-4o Mini", "description": "Fast and affordable OpenAI model"}
            ],
            "anthropic": [
                {"id": "claude-3-7-sonnet-20250219", "name": "Claude Sonnet 3.7", "description": "Latest Claude Sonnet model"}
            ],
            "gemini": [
                {"id": "gemini-2.0-flash", "name": "Gemini 2.5 Flash", "description": "Fast Gemini model"}
            ]
        }

        return models.get(provider.lower(), [])

    def is_provider_available(self, provider: str) -> bool:
        """Check if API key is configured for a provider"""
        provider = provider.lower()
        if provider == "openai":
            return bool(self.openai_key)
        elif provider == "anthropic":
            return bool(self.anthropic_key)
        elif provider == "gemini":
            return bool(self.gemini_key)
        return False

    async def get_available_providers(self) -> Dict[str, bool]:
        """Get availability status of all providers"""
        await self._load_keys()
        return {
            "openai": bool(self.openai_key),
            "anthropic": bool(self.anthropic_key),
            "gemini": bool(self.gemini_key)
        }

    async def ensure_provider_available(self, provider: str) -> None:
        """Raise informative error if provider is not available"""
        await self._load_keys()
        if not self.is_provider_available(provider):
            raise ValueError(
                f"LLM provider '{provider}' is not configured. "
                f"Please set the API key in Settings > API Keys or configure the "
                f"{provider.upper()}_API_KEY environment variable."
            )
