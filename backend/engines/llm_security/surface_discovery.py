"""
LLM Surface Discovery
Detects LLM API usage, prompt templates, and AI integrations
"""

import re
import ast
from typing import List, Dict, Set, Optional
from pathlib import Path
from pydantic import BaseModel, Field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class LLMProvider(str, Enum):
    """LLM providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    COHERE = "cohere"
    HUGGINGFACE = "huggingface"
    LOCAL = "local"
    UNKNOWN = "unknown"


class LLMEndpoint(BaseModel):
    """Detected LLM integration"""
    provider: LLMProvider
    model_name: Optional[str] = None

    file_path: str
    line_number: int
    function_name: str

    # Prompt information
    prompt_template: Optional[str] = None
    uses_user_input: bool = False
    input_variables: List[str] = Field(default_factory=list)

    # System prompt
    system_prompt: Optional[str] = None

    # Tool/Function calling
    has_tools: bool = False
    tool_names: List[str] = Field(default_factory=list)

    # Safety measures
    has_input_validation: bool = False
    has_output_filtering: bool = False
    has_rate_limiting: bool = False

    # Context
    code_snippet: Optional[str] = None


class LLMSurfaceDiscovery:
    """Discovers LLM usage in codebase"""

    def __init__(self):
        self.endpoints: List[LLMEndpoint] = []

        # API patterns for different providers
        self.api_patterns = {
            LLMProvider.OPENAI: [
                r'openai\.chat\.completions\.create',
                r'openai\.ChatCompletion\.create',
                r'ChatOpenAI',
                r'from\s+openai\s+import',
            ],
            LLMProvider.ANTHROPIC: [
                r'anthropic\.Anthropic',
                r'anthropic\.messages\.create',
                r'from\s+anthropic\s+import',
            ],
            LLMProvider.GOOGLE: [
                r'google\.generativeai',
                r'genai\.GenerativeModel',
                r'from\s+google\.generativeai',
            ],
            LLMProvider.HUGGINGFACE: [
                r'transformers\.',
                r'pipeline\(',
                r'AutoModel',
            ]
        }

    async def discover_llm_usage(self, repo_path: str) -> List[LLMEndpoint]:
        """
        Discover all LLM integrations in repository

        Args:
            repo_path: Path to repository

        Returns:
            List of LLM endpoints
        """
        logger.info(f"Discovering LLM usage in {repo_path}")

        self.endpoints = []
        repo_path_obj = Path(repo_path)

        # Scan Python files
        for py_file in repo_path_obj.rglob("*.py"):
            await self._scan_python_file(str(py_file))

        # Scan JavaScript/TypeScript files
        for js_file in list(repo_path_obj.rglob("*.js")) + list(repo_path_obj.rglob("*.ts")):
            await self._scan_javascript_file(str(js_file))

        logger.info(f"Found {len(self.endpoints)} LLM endpoints")
        return self.endpoints

    async def _scan_python_file(self, file_path: str):
        """Scan Python file for LLM usage"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Detect provider
            provider = self._detect_provider(content)
            if provider == LLMProvider.UNKNOWN:
                return

            # Parse AST to find LLM calls
            try:
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        endpoint = await self._analyze_llm_call(node, content, file_path, provider)
                        if endpoint:
                            self.endpoints.append(endpoint)

            except SyntaxError:
                # If AST parsing fails, use regex fallback
                await self._regex_scan_python(content, file_path, provider)

        except Exception as e:
            logger.warning(f"Error scanning {file_path}: {str(e)}")

    def _detect_provider(self, content: str) -> LLMProvider:
        """Detect which LLM provider is used"""
        for provider, patterns in self.api_patterns.items():
            if any(re.search(pattern, content) for pattern in patterns):
                return provider

        # Check for generic AI/LLM patterns
        if any(keyword in content for keyword in ['llm', 'language_model', 'chat_completion']):
            return LLMProvider.UNKNOWN

        return LLMProvider.UNKNOWN

    async def _analyze_llm_call(
        self,
        call_node: ast.Call,
        content: str,
        file_path: str,
        provider: LLMProvider
    ) -> Optional[LLMEndpoint]:
        """Analyze AST call node for LLM usage"""
        call_str = ast.unparse(call_node)

        # Check if this is an LLM API call
        llm_keywords = ['create', 'generate', 'complete', 'chat', 'messages']
        if not any(kw in call_str.lower() for kw in llm_keywords):
            return None

        # Extract parameters
        prompt_template = None
        system_prompt = None
        model_name = None
        input_variables = []
        has_tools = False
        tool_names = []

        # Analyze keyword arguments
        for keyword in call_node.keywords:
            arg_name = keyword.arg
            arg_value = ast.unparse(keyword.value)

            if arg_name in ['prompt', 'message', 'content', 'input']:
                prompt_template = arg_value
                # Check if uses user input
                input_variables = self._extract_variables(arg_value)

            elif arg_name == 'system':
                system_prompt = arg_value

            elif arg_name == 'model':
                model_name = arg_value.strip('"\'')

            elif arg_name in ['tools', 'functions']:
                has_tools = True
                tool_names = self._extract_tool_names(arg_value)

        # Find function context
        function_name = self._find_function_name(call_node, content)

        # Check for safety measures
        has_input_validation = self._check_input_validation(content, call_str)
        has_output_filtering = self._check_output_filtering(content, call_str)

        # Get line number
        line_number = getattr(call_node, 'lineno', 1)

        endpoint = LLMEndpoint(
            provider=provider,
            model_name=model_name,
            file_path=file_path,
            line_number=line_number,
            function_name=function_name or "unknown",
            prompt_template=prompt_template,
            uses_user_input=len(input_variables) > 0,
            input_variables=input_variables,
            system_prompt=system_prompt,
            has_tools=has_tools,
            tool_names=tool_names,
            has_input_validation=has_input_validation,
            has_output_filtering=has_output_filtering,
            code_snippet=call_str[:500]
        )

        return endpoint

    async def _regex_scan_python(self, content: str, file_path: str, provider: LLMProvider):
        """Fallback regex-based scanning"""
        # Look for common LLM API patterns
        patterns = [
            r'(openai|anthropic|genai)\.\w+\.create\([^)]+\)',
            r'ChatOpenAI\([^)]+\)',
            r'messages\.create\([^)]+\)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content, re.DOTALL):
                line_number = content[:match.start()].count('\n') + 1

                # Extract prompt if visible
                prompt_match = re.search(r'(?:prompt|message|content)\s*=\s*["\']([^"\']+)["\']', match.group(0))
                prompt_template = prompt_match.group(1) if prompt_match else None

                endpoint = LLMEndpoint(
                    provider=provider,
                    file_path=file_path,
                    line_number=line_number,
                    function_name="detected_via_regex",
                    prompt_template=prompt_template,
                    code_snippet=match.group(0)[:500]
                )

                self.endpoints.append(endpoint)

    async def _scan_javascript_file(self, file_path: str):
        """Scan JavaScript/TypeScript for LLM usage"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            provider = self._detect_provider(content)
            if provider == LLMProvider.UNKNOWN:
                return

            # Regex patterns for JavaScript
            js_patterns = [
                r'openai\.chat\.completions\.create',
                r'new\s+OpenAI\(',
                r'anthropic\.messages\.create',
            ]

            for pattern in js_patterns:
                for match in re.finditer(pattern, content):
                    line_number = content[:match.start()].count('\n') + 1

                    endpoint = LLMEndpoint(
                        provider=provider,
                        file_path=file_path,
                        line_number=line_number,
                        function_name="javascript_detected",
                        code_snippet=content[match.start():match.start()+500]
                    )

                    self.endpoints.append(endpoint)

        except Exception as e:
            logger.warning(f"Error scanning {file_path}: {str(e)}")

    def _extract_variables(self, code: str) -> List[str]:
        """Extract variable names from code"""
        # Look for f-string variables, .format(), or string concatenation
        variables = []

        # f-string variables: {var_name}
        f_string_vars = re.findall(r'\{(\w+)\}', code)
        variables.extend(f_string_vars)

        # .format() variables
        format_vars = re.findall(r'\.format\([^)]*(\w+)', code)
        variables.extend(format_vars)

        # Common user input variables
        user_input_keywords = ['user_input', 'query', 'message', 'request', 'prompt']
        for keyword in user_input_keywords:
            if keyword in code.lower():
                variables.append(keyword)

        return list(set(variables))

    def _extract_tool_names(self, tools_code: str) -> List[str]:
        """Extract tool/function names"""
        # Look for function definitions
        tool_names = re.findall(r'"name"\s*:\s*"(\w+)"', tools_code)
        return tool_names

    def _find_function_name(self, node: ast.AST, content: str) -> Optional[str]:
        """Find containing function name"""
        # This is simplified - in real implementation, walk up the AST
        lines = content.split('\n')
        if hasattr(node, 'lineno') and node.lineno > 0:
            # Search backwards for function definition
            for i in range(node.lineno - 1, max(0, node.lineno - 50), -1):
                if i < len(lines):
                    match = re.match(r'\s*def\s+(\w+)\s*\(', lines[i])
                    if match:
                        return match.group(1)
        return None

    def _check_input_validation(self, content: str, call_context: str) -> bool:
        """Check if input is validated before LLM call"""
        # Look for validation patterns
        validation_patterns = [
            r'validate\(',
            r'sanitize\(',
            r'len\(.+\)\s*[<>]',
            r'if\s+.+\s+in\s+\[',
            r'filter\(',
        ]

        # Check content before the call
        return any(re.search(pattern, content) for pattern in validation_patterns)

    def _check_output_filtering(self, content: str, call_context: str) -> bool:
        """Check if output is filtered after LLM call"""
        output_patterns = [
            r'filter\(',
            r'sanitize\(',
            r'escape\(',
            r'replace\(',
        ]

        return any(re.search(pattern, content) for pattern in output_patterns)
