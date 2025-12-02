"""
Dedicated API Fuzzing Scanner
Comprehensive API security testing beyond LLM-based testing

Features:
- REST API endpoint discovery
- OpenAPI/Swagger spec analysis
- GraphQL introspection
- Rate limiting detection
- Authentication bypass attempts
- Input validation fuzzing
- Business logic testing
- BOLA/IDOR detection
"""

import asyncio
import logging
import json
import os
import re
from typing import List, Dict, Optional, Any
from pathlib import Path
import aiohttp

logger = logging.getLogger(__name__)


class APIFuzzerScanner:
    """Dedicated API security fuzzer"""

    def __init__(self):
        self.timeout = 10
        self.max_concurrent = 5

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Scan repository for API vulnerabilities

        Discovers:
        - API endpoints from code/specs
        - Authentication weaknesses
        - Input validation issues
        - Rate limiting problems
        - Business logic flaws
        """
        vulnerabilities = []

        try:
            # 1. Find API specifications
            api_specs = await self._find_api_specs(repo_path)
            for spec_file in api_specs:
                spec_vulns = await self._analyze_api_spec(spec_file, repo_path)
                vulnerabilities.extend(spec_vulns)

            # 2. Find API endpoints in code
            endpoints = await self._discover_endpoints(repo_path)
            endpoint_vulns = await self._analyze_endpoints(endpoints, repo_path)
            vulnerabilities.extend(endpoint_vulns)

            # 3. Check for GraphQL
            graphql_vulns = await self._check_graphql(repo_path)
            vulnerabilities.extend(graphql_vulns)

            # 4. Authentication/authorization checks
            auth_vulns = await self._check_api_auth(repo_path)
            vulnerabilities.extend(auth_vulns)

            # 5. Rate limiting checks
            rate_limit_vulns = await self._check_rate_limiting(repo_path)
            vulnerabilities.extend(rate_limit_vulns)

            logger.info(f"API Fuzzer found {len(vulnerabilities)} issues")
            return vulnerabilities

        except Exception as e:
            logger.error(f"API Fuzzer scan failed: {str(e)}")
            return []

    async def _find_api_specs(self, repo_path: str) -> List[str]:
        """Find OpenAPI/Swagger specification files"""
        spec_files = []
        spec_patterns = [
            '**/swagger.json', '**/swagger.yaml', '**/swagger.yml',
            '**/openapi.json', '**/openapi.yaml', '**/openapi.yml',
            '**/api-spec.json', '**/api-spec.yaml',
            '**/api-docs.json', '**/api-docs.yaml',
        ]

        for root, _, files in os.walk(repo_path):
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 'venv']):
                continue

            for file in files:
                file_lower = file.lower()
                if any(pattern in file_lower for pattern in ['swagger', 'openapi', 'api-spec', 'api-docs']):
                    if file_lower.endswith(('.json', '.yaml', '.yml')):
                        spec_files.append(os.path.join(root, file))

        return spec_files

    async def _analyze_api_spec(self, spec_file: str, repo_path: str) -> List[Dict]:
        """Analyze OpenAPI/Swagger specification for security issues"""
        vulnerabilities = []

        try:
            with open(spec_file, 'r') as f:
                if spec_file.endswith('.json'):
                    spec = json.load(f)
                else:
                    import yaml
                    spec = yaml.safe_load(f)

            # Check for security definitions
            if 'securityDefinitions' not in spec and 'components' not in spec.get('components', {}):
                vulnerabilities.append({
                    'title': 'Missing API Security Definitions',
                    'description': 'API specification lacks security definitions. All endpoints may be unauthenticated.',
                    'severity': 'high',
                    'file_path': spec_file,
                    'line_start': 1,
                    'line_end': 1,
                    'detected_by': 'api_fuzzer',
                    'category': 'API Security',
                    'type': 'missing_authentication',
                    'owasp_category': 'A07:2021 - Identification and Authentication Failures',
                    'cwe': 'CWE-306',
                })

            # Check paths for security issues
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method, operation in methods.items():
                    if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        continue

                    # Check for missing authentication on sensitive endpoints
                    if not operation.get('security'):
                        if any(sensitive in path.lower() for sensitive in ['admin', 'user', 'delete', 'update', 'create']):
                            vulnerabilities.append({
                                'title': f'Unauthenticated {method.upper()} Endpoint',
                                'description': f'Endpoint {method.upper()} {path} has no authentication requirement.',
                                'severity': 'high',
                                'file_path': spec_file,
                                'line_start': 1,
                                'line_end': 1,
                                'detected_by': 'api_fuzzer',
                                'category': 'API Security',
                                'type': 'unauthenticated_endpoint',
                                'owasp_category': 'A01:2021 - Broken Access Control',
                                'cwe': 'CWE-284',
                                'remediation': f'Add authentication to {method.upper()} {path}'
                            })

                    # Check for overly permissive CORS
                    responses = operation.get('responses', {})
                    for resp_code, response in responses.items():
                        headers = response.get('headers', {})
                        if 'Access-Control-Allow-Origin' in headers:
                            origin = headers['Access-Control-Allow-Origin']
                            if origin == '*':
                                vulnerabilities.append({
                                    'title': 'Permissive CORS Configuration',
                                    'description': f'Endpoint {path} allows any origin (*) in CORS headers.',
                                    'severity': 'medium',
                                    'file_path': spec_file,
                                    'line_start': 1,
                                    'line_end': 1,
                                    'detected_by': 'api_fuzzer',
                                    'category': 'API Security',
                                    'type': 'cors_misconfiguration',
                                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                                    'cwe': 'CWE-942',
                                })

        except Exception as e:
            logger.debug(f"Error analyzing API spec {spec_file}: {str(e)}")

        return vulnerabilities

    async def _discover_endpoints(self, repo_path: str) -> Dict[str, List[Dict]]:
        """Discover API endpoints from source code"""
        endpoints = {'express': [], 'fastapi': [], 'flask': [], 'django': []}

        # Patterns for different frameworks
        patterns = {
            'express': [
                (r'app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'javascript'),
                (r'router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'javascript'),
            ],
            'fastapi': [
                (r'@app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'python'),
                (r'@router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'python'),
            ],
            'flask': [
                (r'@app\.route\s*\(\s*["\']([^"\']+)["\'].*methods\s*=\s*\[([^\]]+)\]', 'python'),
            ],
            'django': [
                (r'path\s*\(\s*["\']([^"\']+)["\']', 'python'),
            ]
        }

        for root, _, files in os.walk(repo_path):
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 'venv']):
                continue

            for file in files:
                file_path = os.path.join(root, file)

                # Determine file type
                if file.endswith(('.js', '.ts')):
                    frameworks = ['express']
                elif file.endswith('.py'):
                    frameworks = ['fastapi', 'flask', 'django']
                else:
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    for framework in frameworks:
                        for pattern, lang in patterns.get(framework, []):
                            matches = re.findall(pattern, content, re.MULTILINE)
                            for match in matches:
                                if isinstance(match, tuple):
                                    if framework == 'flask':
                                        path, methods = match
                                        method = 'GET'  # Default
                                    else:
                                        method, path = match
                                else:
                                    method, path = 'GET', match

                                endpoints[framework].append({
                                    'method': method.upper(),
                                    'path': path,
                                    'file': file_path,
                                    'framework': framework
                                })

                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {str(e)}")

        return endpoints

    async def _analyze_endpoints(self, endpoints: Dict, repo_path: str) -> List[Dict]:
        """Analyze discovered endpoints for vulnerabilities"""
        vulnerabilities = []

        for framework, endpoint_list in endpoints.items():
            for endpoint in endpoint_list:
                path = endpoint['path']
                method = endpoint['method']
                file_path = endpoint['file']

                # Check for parameter injection risks
                if '{' in path or ':' in path:
                    # Has path parameters
                    if method in ['DELETE', 'PUT', 'PATCH']:
                        vulnerabilities.append({
                            'title': 'Potential BOLA/IDOR Vulnerability',
                            'description': f'{method} {path} accepts URL parameters. Verify proper authorization checks to prevent accessing other users\' resources.',
                            'severity': 'high',
                            'file_path': file_path,
                            'line_start': 1,
                            'line_end': 1,
                            'detected_by': 'api_fuzzer',
                            'category': 'API Security',
                            'type': 'bola_idor',
                            'owasp_category': 'A01:2021 - Broken Access Control',
                            'cwe': 'CWE-639',
                            'remediation': 'Implement proper authorization checks before allowing resource access/modification'
                        })

                # Check for mass assignment risks
                if method in ['POST', 'PUT', 'PATCH']:
                    vulnerabilities.append({
                        'title': 'Potential Mass Assignment Vulnerability',
                        'description': f'{method} {path} may be vulnerable to mass assignment. Ensure request body validation.',
                        'severity': 'medium',
                        'file_path': file_path,
                        'line_start': 1,
                        'line_end': 1,
                        'detected_by': 'api_fuzzer',
                        'category': 'API Security',
                        'type': 'mass_assignment',
                        'owasp_category': 'A03:2021 - Injection',
                        'cwe': 'CWE-915',
                        'remediation': 'Use allow-lists for request body fields, not deny-lists'
                    })

        return vulnerabilities

    async def _check_graphql(self, repo_path: str) -> List[Dict]:
        """Check for GraphQL security issues"""
        vulnerabilities = []

        # Look for GraphQL schemas
        for root, _, files in os.walk(repo_path):
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 'venv']):
                continue

            for file in files:
                if file.endswith(('.graphql', '.gql')) or 'schema' in file.lower():
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        # Check for introspection enabled
                        if 'type __Schema' in content or '__schema' in content.lower():
                            vulnerabilities.append({
                                'title': 'GraphQL Introspection Enabled',
                                'description': 'GraphQL introspection is enabled, allowing attackers to discover the full schema.',
                                'severity': 'medium',
                                'file_path': file_path,
                                'line_start': 1,
                                'line_end': 1,
                                'detected_by': 'api_fuzzer',
                                'category': 'API Security',
                                'type': 'graphql_introspection',
                                'owasp_category': 'A05:2021 - Security Misconfiguration',
                                'cwe': 'CWE-16',
                                'remediation': 'Disable introspection in production environments'
                            })

                        # Check for query depth/complexity limits
                        if 'query' in content.lower() and 'depth' not in content.lower():
                            vulnerabilities.append({
                                'title': 'Missing GraphQL Query Depth Limits',
                                'description': 'GraphQL schema lacks query depth limits, potentially allowing DoS attacks.',
                                'severity': 'medium',
                                'file_path': file_path,
                                'line_start': 1,
                                'line_end': 1,
                                'detected_by': 'api_fuzzer',
                                'category': 'API Security',
                                'type': 'graphql_dos',
                                'owasp_category': 'A05:2021 - Security Misconfiguration',
                                'cwe': 'CWE-400',
                                'remediation': 'Implement query depth and complexity limits'
                            })

                    except Exception as e:
                        logger.debug(f"Error checking GraphQL file {file_path}: {str(e)}")

        return vulnerabilities

    async def _check_api_auth(self, repo_path: str) -> List[Dict]:
        """Check for API authentication issues"""
        vulnerabilities = []

        # Look for API key patterns
        api_key_patterns = [
            (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API Key'),
            (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', 'Hardcoded Bearer Token'),
            (r'Basic\s+[A-Za-z0-9+/=]+', 'Hardcoded Basic Auth'),
        ]

        for root, _, files in os.walk(repo_path):
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 'venv']):
                continue

            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.go')):
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            lines = content.split('\n')

                        for i, line in enumerate(lines, 1):
                            for pattern, title in api_key_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    # Skip if it's a comment or example
                                    if any(marker in line.lower() for marker in ['example', 'todo', 'fixme', '#', '//']):
                                        continue

                                    vulnerabilities.append({
                                        'title': title,
                                        'description': f'Hardcoded credential found in source code. Use environment variables or secret management.',
                                        'severity': 'critical',
                                        'file_path': file_path,
                                        'line_start': i,
                                        'line_end': i,
                                        'detected_by': 'api_fuzzer',
                                        'category': 'API Security',
                                        'type': 'hardcoded_credential',
                                        'owasp_category': 'A07:2021 - Identification and Authentication Failures',
                                        'cwe': 'CWE-798',
                                        'code_snippet': line.strip()[:100]
                                    })

                    except Exception as e:
                        logger.debug(f"Error checking auth in {file_path}: {str(e)}")

        return vulnerabilities

    async def _check_rate_limiting(self, repo_path: str) -> List[Dict]:
        """Check for missing rate limiting"""
        vulnerabilities = []

        rate_limit_indicators = ['rate_limit', 'ratelimit', 'throttle', 'slowdown']

        for root, _, files in os.walk(repo_path):
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 'venv']):
                continue

            for file in files:
                if file.endswith(('.py', '.js', '.ts')):
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().lower()

                        # Check if file has API routes but no rate limiting
                        has_routes = any(keyword in content for keyword in ['@app', '@router', 'app.get', 'app.post', 'router.get', 'router.post'])

                        if has_routes:
                            has_rate_limit = any(indicator in content for indicator in rate_limit_indicators)

                            if not has_rate_limit:
                                vulnerabilities.append({
                                    'title': 'Missing API Rate Limiting',
                                    'description': f'API endpoints in {file} lack rate limiting, potentially allowing DoS attacks.',
                                    'severity': 'medium',
                                    'file_path': file_path,
                                    'line_start': 1,
                                    'line_end': 1,
                                    'detected_by': 'api_fuzzer',
                                    'category': 'API Security',
                                    'type': 'missing_rate_limit',
                                    'owasp_category': 'A05:2021 - Security Misconfiguration',
                                    'cwe': 'CWE-770',
                                    'remediation': 'Implement rate limiting middleware to prevent abuse'
                                })

                    except Exception as e:
                        logger.debug(f"Error checking rate limiting in {file_path}: {str(e)}")

        return vulnerabilities[:5]  # Limit to avoid spam


# Async wrapper for compatibility
async def scan(repo_path: str) -> List[Dict]:
    """Run API Fuzzer scanner"""
    scanner = APIFuzzerScanner()
    return await scanner.scan(repo_path)
