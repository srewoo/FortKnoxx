"""
Application Flow Graph Analyzer
Analyzes code to extract API flows, state transitions, and user journeys
"""

import ast
import re
from typing import List, Dict, Set, Optional, Any
from pathlib import Path
from pydantic import BaseModel, Field
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class APIEndpoint(BaseModel):
    """Represents an API endpoint"""
    path: str
    method: str  # GET, POST, PUT, DELETE, etc.
    file_path: str
    line_number: int
    function_name: str

    # Authentication & Authorization
    requires_auth: bool = False
    required_roles: List[str] = Field(default_factory=list)

    # Parameters
    parameters: List[str] = Field(default_factory=list)
    query_params: List[str] = Field(default_factory=list)
    body_params: List[str] = Field(default_factory=list)

    # Dependencies
    calls_endpoints: List[str] = Field(default_factory=list)
    accesses_resources: List[str] = Field(default_factory=list)

    # State changes
    modifies_state: bool = False
    state_fields: List[str] = Field(default_factory=list)


class StateTransition(BaseModel):
    """Represents a state transition"""
    from_state: str
    to_state: str
    endpoint: str
    conditions: List[str] = Field(default_factory=list)
    required_steps: List[str] = Field(default_factory=list)


class FlowGraph(BaseModel):
    """Application flow graph"""
    endpoints: Dict[str, APIEndpoint] = Field(default_factory=dict)
    transitions: List[StateTransition] = Field(default_factory=list)

    # Detected patterns
    workflow_chains: List[List[str]] = Field(default_factory=list)
    resource_access_patterns: Dict[str, List[str]] = Field(default_factory=dict)


class FlowAnalyzer:
    """
    Analyzes application code to build flow graphs
    Supports Python, JavaScript/TypeScript, and Java
    """

    def __init__(self):
        self.endpoints: Dict[str, APIEndpoint] = {}
        self.transitions: List[StateTransition] = []

        # Framework-specific patterns
        self.framework_patterns = {
            'fastapi': {
                'route_decorators': [r'@app\.(get|post|put|delete|patch)\('],
                'auth_decorators': [r'@require_auth', r'Depends\(get_current_user\)', r'require_role'],
            },
            'flask': {
                'route_decorators': [r'@app\.route\('],
                'auth_decorators': [r'@login_required', r'@requires_auth'],
            },
            'express': {
                'route_patterns': [r'app\.(get|post|put|delete|patch)\('],
                'auth_patterns': [r'authenticate\(', r'authorize\('],
            },
            'spring': {
                'route_annotations': [r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)'],
                'auth_annotations': [r'@Secured', r'@PreAuthorize'],
            }
        }

    async def analyze_repository(self, repo_path: str) -> FlowGraph:
        """
        Analyze entire repository to build flow graph

        Args:
            repo_path: Path to repository

        Returns:
            FlowGraph with all detected endpoints and transitions
        """
        logger.info(f"Analyzing repository for flow graph: {repo_path}")

        repo_path_obj = Path(repo_path)

        # Analyze Python files
        for py_file in repo_path_obj.rglob("*.py"):
            await self._analyze_python_file(str(py_file))

        # Analyze JavaScript/TypeScript files
        for js_file in list(repo_path_obj.rglob("*.js")) + list(repo_path_obj.rglob("*.ts")):
            await self._analyze_javascript_file(str(js_file))

        # Build transitions
        self._build_state_transitions()

        # Detect workflow chains
        workflow_chains = self._detect_workflow_chains()

        graph = FlowGraph(
            endpoints=self.endpoints,
            transitions=self.transitions,
            workflow_chains=workflow_chains
        )

        logger.info(f"Flow graph built: {len(self.endpoints)} endpoints, {len(self.transitions)} transitions")
        return graph

    async def _analyze_python_file(self, file_path: str):
        """Analyze Python file for API endpoints"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    endpoint = self._extract_python_endpoint(node, file_path, content)
                    if endpoint:
                        self.endpoints[f"{endpoint.method}:{endpoint.path}"] = endpoint

        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {str(e)}")

    def _extract_python_endpoint(
        self,
        func_node: ast.FunctionDef,
        file_path: str,
        content: str
    ) -> Optional[APIEndpoint]:
        """Extract endpoint information from Python function"""

        # Check for route decorators
        route_decorator = None
        method = "GET"
        path = None
        requires_auth = False
        required_roles = []

        for decorator in func_node.decorator_list:
            decorator_str = ast.unparse(decorator)

            # Check for route decorators (FastAPI/Flask)
            if re.search(r'@app\.(get|post|put|delete|patch)', decorator_str):
                match = re.search(r'@app\.(\w+)\(["\']([^"\']+)', decorator_str)
                if match:
                    method = match.group(1).upper()
                    path = match.group(2)
                    route_decorator = decorator_str

            elif '@app.route' in decorator_str:
                match = re.search(r'["\']([^"\']+)["\']', decorator_str)
                if match:
                    path = match.group(1)
                    # Check for methods parameter
                    methods_match = re.search(r'methods=\[([^\]]+)\]', decorator_str)
                    if methods_match:
                        method = methods_match.group(1).replace('"', '').replace("'", "").split(',')[0].strip()

            # Check for auth decorators
            if any(auth_pattern in decorator_str for auth_pattern in ['require_auth', 'Depends', 'require_role']):
                requires_auth = True

                # Extract roles
                role_match = re.search(r'UserRole\.(\w+)', decorator_str)
                if role_match:
                    required_roles.append(role_match.group(1))

        if not path:
            return None

        # Extract parameters
        parameters = [arg.arg for arg in func_node.args.args if arg.arg != 'self']

        # Detect state modifications
        modifies_state = self._detects_state_modification(func_node)

        # Extract resource access
        resources = self._extract_resource_access(func_node)

        endpoint = APIEndpoint(
            path=path,
            method=method,
            file_path=file_path,
            line_number=func_node.lineno,
            function_name=func_node.name,
            requires_auth=requires_auth,
            required_roles=required_roles,
            parameters=parameters,
            modifies_state=modifies_state,
            accesses_resources=resources
        )

        return endpoint

    async def _analyze_javascript_file(self, file_path: str):
        """Analyze JavaScript/TypeScript file for API endpoints"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Regex-based extraction for Express.js patterns
            route_pattern = r'app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'

            for match in re.finditer(route_pattern, content):
                method = match.group(1).upper()
                path = match.group(2)

                # Find line number
                line_number = content[:match.start()].count('\n') + 1

                # Check for authentication middleware
                context = content[max(0, match.start() - 200):match.end() + 200]
                requires_auth = 'authenticate' in context or 'auth' in context.lower()

                endpoint = APIEndpoint(
                    path=path,
                    method=method,
                    file_path=file_path,
                    line_number=line_number,
                    function_name=f"handler_{method.lower()}_{path.replace('/', '_')}",
                    requires_auth=requires_auth
                )

                self.endpoints[f"{method}:{path}"] = endpoint

        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {str(e)}")

    def _detects_state_modification(self, func_node: ast.FunctionDef) -> bool:
        """Check if function modifies state"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                func_name = ast.unparse(node.func).lower()
                if any(keyword in func_name for keyword in ['update', 'insert', 'delete', 'save', 'create', 'modify']):
                    return True
        return False

    def _extract_resource_access(self, func_node: ast.FunctionDef) -> List[str]:
        """Extract resource access patterns"""
        resources = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                func_name = ast.unparse(node.func).lower()
                if 'find' in func_name or 'get' in func_name or 'query' in func_name:
                    # Try to extract collection/table name
                    if hasattr(node.func, 'value') and hasattr(node.func.value, 'attr'):
                        resources.append(node.func.value.attr)
        return resources

    def _build_state_transitions(self):
        """Build state transitions from endpoints"""
        # Group endpoints by resource
        resource_endpoints = defaultdict(list)

        for key, endpoint in self.endpoints.items():
            for resource in endpoint.accesses_resources:
                resource_endpoints[resource].append(endpoint)

        # Detect transitions (e.g., create -> update -> delete)
        for resource, endpoints in resource_endpoints.items():
            create_ep = next((e for e in endpoints if e.method == 'POST'), None)
            update_ep = next((e for e in endpoints if e.method in ['PUT', 'PATCH']), None)
            delete_ep = next((e for e in endpoints if e.method == 'DELETE'), None)

            if create_ep and update_ep:
                self.transitions.append(StateTransition(
                    from_state=f"{resource}_created",
                    to_state=f"{resource}_updated",
                    endpoint=f"{update_ep.method}:{update_ep.path}",
                    required_steps=[f"{create_ep.method}:{create_ep.path}"]
                ))

    def _detect_workflow_chains(self) -> List[List[str]]:
        """Detect common workflow chains"""
        chains = []

        # Detect authentication flow
        auth_endpoints = [k for k, v in self.endpoints.items() if 'login' in v.path or 'auth' in v.path]
        if auth_endpoints:
            chains.append(['register', 'verify', 'login'])

        # Detect e-commerce flow
        commerce_keywords = ['order', 'cart', 'payment', 'checkout']
        commerce_endpoints = [k for k, v in self.endpoints.items()
                             if any(kw in v.path for kw in commerce_keywords)]
        if len(commerce_endpoints) >= 3:
            chains.append(['add_to_cart', 'checkout', 'payment', 'confirm'])

        return chains

    def find_unprotected_endpoints(self) -> List[APIEndpoint]:
        """Find endpoints that should require auth but don't"""
        unprotected = []

        sensitive_keywords = ['delete', 'admin', 'user', 'account', 'payment', 'order']

        for endpoint in self.endpoints.values():
            if endpoint.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                if not endpoint.requires_auth:
                    # Check if path contains sensitive keywords
                    if any(kw in endpoint.path.lower() for kw in sensitive_keywords):
                        unprotected.append(endpoint)

        return unprotected
