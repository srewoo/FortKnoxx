"""
Real LLM API Client
Makes actual API calls to OpenAI, Anthropic, Google Gemini for security testing
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from llm.model_registry import (
    DEFAULT_MODEL_BY_PROVIDER,
    get_pricing,
    resolve_model_id,
    supports_temperature,
    uses_max_completion_tokens,
)

logger = logging.getLogger(__name__)

# Import LLM SDK clients
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    logger.warning("OpenAI SDK not installed")
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    logger.warning("Anthropic SDK not installed")
    ANTHROPIC_AVAILABLE = False

try:
    import google.generativeai as genai
    GOOGLE_AVAILABLE = True
except ImportError:
    logger.warning("Google Generative AI SDK not installed")
    GOOGLE_AVAILABLE = False


class Provider(str, Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"


@dataclass
class APIResponse:
    """LLM API response with metadata"""
    provider: Provider
    model: str
    prompt: str
    response_text: str

    # Metadata
    response_time: float
    tokens_used: Optional[int] = None
    finish_reason: Optional[str] = None

    # Safety checks
    blocked: bool = False
    block_reason: Optional[str] = None

    # Cost estimation (USD)
    estimated_cost: float = 0.0

    # Error handling
    error: Optional[str] = None


class RateLimiter:
    """Simple rate limiter for API calls"""

    def __init__(self, calls_per_minute: int = 50):
        self.calls_per_minute = calls_per_minute
        self.call_times: List[float] = []

    async def wait_if_needed(self):
        """Wait if rate limit is reached"""
        now = time.time()

        # Remove calls older than 1 minute
        self.call_times = [t for t in self.call_times if now - t < 60]

        # If at limit, wait
        if len(self.call_times) >= self.calls_per_minute:
            oldest_call = min(self.call_times)
            wait_time = 60 - (now - oldest_call)
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)

        self.call_times.append(now)


class LLMAPIClient:
    """
    Unified client for calling multiple LLM APIs
    Handles rate limiting, retries, and cost tracking
    """

    def __init__(self, api_keys: Dict[str, str], rate_limit: int = 50):
        """
        Initialize API client

        Args:
            api_keys: Dictionary of provider -> API key
            rate_limit: Calls per minute per provider
        """
        self.api_keys = api_keys
        self.rate_limiters = {
            Provider.OPENAI: RateLimiter(rate_limit),
            Provider.ANTHROPIC: RateLimiter(rate_limit),
            Provider.GOOGLE: RateLimiter(rate_limit),
        }

        self.total_cost = 0.0
        self.total_tokens = 0

        # Initialize clients
        self._init_clients()

    def _init_clients(self):
        """Initialize API clients"""

        # OpenAI
        if OPENAI_AVAILABLE and "openai" in self.api_keys:
            openai.api_key = self.api_keys["openai"]
            logger.info("OpenAI client initialized")

        # Anthropic
        if ANTHROPIC_AVAILABLE and "anthropic" in self.api_keys:
            self.anthropic_client = anthropic.Anthropic(
                api_key=self.api_keys["anthropic"]
            )
            logger.info("Anthropic client initialized")

        # Google Gemini
        if GOOGLE_AVAILABLE and "google" in self.api_keys:
            genai.configure(api_key=self.api_keys["google"])
            logger.info("Google Gemini client initialized")

    async def call_api(
        self,
        provider: Provider,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1000
    ) -> APIResponse:
        """
        Call LLM API with unified interface

        Args:
            provider: Which LLM provider to use
            prompt: User prompt
            system_prompt: Optional system prompt
            model: Optional model override
            temperature: Sampling temperature
            max_tokens: Max response tokens

        Returns:
            API response with metadata
        """

        # Check API key availability
        if provider.value not in self.api_keys:
            return APIResponse(
                provider=provider,
                model=model or "unknown",
                prompt=prompt,
                response_text="",
                response_time=0,
                error=f"No API key configured for {provider.value}"
            )

        # Rate limiting
        await self.rate_limiters[provider].wait_if_needed()

        # Route to appropriate provider
        try:
            if provider == Provider.OPENAI:
                return await self._call_openai(
                    prompt, system_prompt, model, temperature, max_tokens
                )
            elif provider == Provider.ANTHROPIC:
                return await self._call_anthropic(
                    prompt, system_prompt, model, temperature, max_tokens
                )
            elif provider == Provider.GOOGLE:
                return await self._call_google(
                    prompt, system_prompt, model, temperature, max_tokens
                )
            else:
                return APIResponse(
                    provider=provider,
                    model=model or "unknown",
                    prompt=prompt,
                    response_text="",
                    response_time=0,
                    error=f"Unsupported provider: {provider}"
                )

        except Exception as e:
            logger.error(f"Error calling {provider.value} API: {str(e)}")
            return APIResponse(
                provider=provider,
                model=model or "unknown",
                prompt=prompt,
                response_text="",
                response_time=0,
                error=str(e)
            )

    async def _call_openai(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> APIResponse:
        """Call OpenAI API"""

        if not OPENAI_AVAILABLE:
            return APIResponse(
                provider=Provider.OPENAI,
                model=resolve_model_id(model, "openai"),
                prompt=prompt,
                response_text="",
                response_time=0,
                error="OpenAI SDK not installed"
            )

        model_name = resolve_model_id(model, "openai")
        start_time = time.time()

        try:
            messages = []

            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})

            messages.append({"role": "user", "content": prompt})

            kwargs: Dict[str, Any] = {"model": model_name, "messages": messages}
            if supports_temperature(model_name):
                kwargs["temperature"] = temperature
            if uses_max_completion_tokens(model_name):
                kwargs["max_completion_tokens"] = max_tokens
            else:
                kwargs["max_tokens"] = max_tokens

            response = await openai.ChatCompletion.acreate(**kwargs)

            response_time = time.time() - start_time

            response_text = response.choices[0].message.content
            tokens = response.usage.total_tokens if hasattr(response, 'usage') else None
            finish_reason = response.choices[0].finish_reason

            # Estimate cost (rough estimates for gpt-4o-mini)
            cost = self._estimate_openai_cost(model_name, tokens or 0)

            self.total_cost += cost
            self.total_tokens += tokens or 0

            return APIResponse(
                provider=Provider.OPENAI,
                model=model_name,
                prompt=prompt,
                response_text=response_text,
                response_time=response_time,
                tokens_used=tokens,
                finish_reason=finish_reason,
                estimated_cost=cost
            )

        except openai.error.InvalidRequestError as e:
            if "content_filter" in str(e).lower():
                return APIResponse(
                    provider=Provider.OPENAI,
                    model=model_name,
                    prompt=prompt,
                    response_text="",
                    response_time=time.time() - start_time,
                    blocked=True,
                    block_reason="Content filter triggered",
                    error=str(e)
                )
            raise

    async def _call_anthropic(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> APIResponse:
        """Call Anthropic API"""

        if not ANTHROPIC_AVAILABLE:
            return APIResponse(
                provider=Provider.ANTHROPIC,
                model=resolve_model_id(model, "anthropic"),
                prompt=prompt,
                response_text="",
                response_time=0,
                error="Anthropic SDK not installed"
            )

        model_name = resolve_model_id(model, "anthropic")
        start_time = time.time()

        try:
            create_kwargs: Dict[str, Any] = {
                "model": model_name,
                "max_tokens": max_tokens,
                "system": system_prompt or "",
                "messages": [{"role": "user", "content": prompt}],
            }
            if supports_temperature(model_name):
                create_kwargs["temperature"] = temperature

            message = await self.anthropic_client.messages.create(**create_kwargs)

            response_time = time.time() - start_time

            response_text = message.content[0].text
            tokens = message.usage.input_tokens + message.usage.output_tokens
            finish_reason = message.stop_reason

            # Estimate cost
            cost = self._estimate_anthropic_cost(model_name, message.usage.input_tokens, message.usage.output_tokens)

            self.total_cost += cost
            self.total_tokens += tokens

            return APIResponse(
                provider=Provider.ANTHROPIC,
                model=model_name,
                prompt=prompt,
                response_text=response_text,
                response_time=response_time,
                tokens_used=tokens,
                finish_reason=finish_reason,
                estimated_cost=cost
            )

        except anthropic.APIError as e:
            if "content_policy" in str(e).lower():
                return APIResponse(
                    provider=Provider.ANTHROPIC,
                    model=model_name,
                    prompt=prompt,
                    response_text="",
                    response_time=time.time() - start_time,
                    blocked=True,
                    block_reason="Content policy triggered",
                    error=str(e)
                )
            raise

    async def _call_google(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> APIResponse:
        """Call Google Gemini API"""

        if not GOOGLE_AVAILABLE:
            return APIResponse(
                provider=Provider.GOOGLE,
                model=resolve_model_id(model, "gemini"),
                prompt=prompt,
                response_text="",
                response_time=0,
                error="Google Generative AI SDK not installed"
            )

        model_name = resolve_model_id(model, "gemini")
        start_time = time.time()

        try:
            gemini_model = genai.GenerativeModel(model_name)

            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"

            gen_kwargs: Dict[str, Any] = {"max_output_tokens": max_tokens}
            if supports_temperature(model_name):
                gen_kwargs["temperature"] = temperature

            response = await gemini_model.generate_content_async(
                full_prompt,
                generation_config=genai.types.GenerationConfig(**gen_kwargs),
            )

            response_time = time.time() - start_time

            # Check if blocked by safety filters
            if response.prompt_feedback.block_reason:
                return APIResponse(
                    provider=Provider.GOOGLE,
                    model=model_name,
                    prompt=prompt,
                    response_text="",
                    response_time=response_time,
                    blocked=True,
                    block_reason=str(response.prompt_feedback.block_reason)
                )

            response_text = response.text

            # Estimate tokens (rough approximation)
            tokens = len(prompt.split()) + len(response_text.split())

            # Estimate cost (Gemini Pro is free for moderate use)
            cost = 0.0

            self.total_tokens += tokens

            return APIResponse(
                provider=Provider.GOOGLE,
                model=model_name,
                prompt=prompt,
                response_text=response_text,
                response_time=response_time,
                tokens_used=tokens,
                finish_reason="complete",
                estimated_cost=cost
            )

        except Exception as e:
            if "safety" in str(e).lower():
                return APIResponse(
                    provider=Provider.GOOGLE,
                    model=model_name,
                    prompt=prompt,
                    response_text="",
                    response_time=time.time() - start_time,
                    blocked=True,
                    block_reason="Safety filter triggered",
                    error=str(e)
                )
            raise

    def _estimate_openai_cost(self, model: str, tokens: int) -> float:
        """Estimate OpenAI cost when input/output split is unknown.

        Approximates with the average of input/output rates from the
        registry, since the OpenAI legacy `Completion.acreate` path does
        not always surface token splits.
        """
        input_rate, output_rate = get_pricing(model)
        avg_per_1k = (input_rate + output_rate) / 2 or 0.001
        return (tokens / 1000) * avg_per_1k

    def _estimate_anthropic_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        input_rate, output_rate = get_pricing(model)
        return (input_tokens / 1000) * input_rate + (output_tokens / 1000) * output_rate

    def get_cost_summary(self) -> Dict[str, Any]:
        """Get summary of API usage and costs"""
        return {
            "total_cost_usd": round(self.total_cost, 4),
            "total_tokens": self.total_tokens,
            "cost_per_call": round(self.total_cost / max(1, len(self.rate_limiters[Provider.OPENAI].call_times)), 4)
        }
