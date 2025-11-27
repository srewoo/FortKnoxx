"""
Context-Aware Vulnerability Analysis System
Provides intelligent analysis and prioritization of security vulnerabilities
"""

import logging
from typing import List, Dict, Optional, Set
from pathlib import Path
import re

logger = logging.getLogger(__name__)


class ContextAnalyzer:
    """
    Analyzes vulnerabilities in context to provide better prioritization
    and recommendations
    """

    # Critical file patterns that increase severity
    CRITICAL_FILE_PATTERNS = {
        r'auth.*\.py$': 'authentication',
        r'login.*\.py$': 'authentication',
        r'password.*\.py$': 'authentication',
        r'api.*\.py$': 'api_endpoint',
        r'router.*\.py$': 'api_endpoint',
        r'endpoint.*\.py$': 'api_endpoint',
        r'db.*\.py$': 'database',
        r'database.*\.py$': 'database',
        r'model.*\.py$': 'database',
        r'payment.*\.py$': 'payment',
        r'billing.*\.py$': 'payment',
        r'admin.*\.py$': 'admin',
        r'config.*\.py$': 'configuration',
        r'settings.*\.py$': 'configuration',
        r'\.env$': 'secrets',
        r'secret.*\.py$': 'secrets',
    }

    # Data flow risk patterns
    DATA_FLOW_PATTERNS = {
        'user_input': [
            r'request\.get',
            r'request\.post',
            r'request\.json',
            r'input\(',
            r'sys\.argv',
            r'os\.environ\.get',
        ],
        'database_query': [
            r'execute\(',
            r'executemany\(',
            r'raw\(',
            r'\.query\(',
            r'SELECT.*FROM',
            r'INSERT.*INTO',
        ],
        'external_call': [
            r'requests\.get',
            r'requests\.post',
            r'urllib',
            r'subprocess\.',
            r'os\.system',
        ],
        'crypto_operation': [
            r'hashlib\.',
            r'Crypto\.',
            r'cryptography\.',
            r'random\.',
            r'secrets\.',
        ]
    }

    def __init__(self):
        self.repo_structure = {}
        self.file_contexts = {}

    async def analyze_repository_structure(self, repo_path: str) -> Dict:
        """
        Analyze repository structure to understand context

        Returns:
            Dictionary with repository metadata
        """
        structure = {
            'total_files': 0,
            'languages': set(),
            'frameworks': set(),
            'has_tests': False,
            'has_ci_cd': False,
            'has_docker': False,
            'entry_points': [],
            'sensitive_files': []
        }

        repo_path_obj = Path(repo_path)

        for file_path in repo_path_obj.rglob('*'):
            if not file_path.is_file():
                continue

            structure['total_files'] += 1

            # Detect languages
            if file_path.suffix == '.py':
                structure['languages'].add('Python')
            elif file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
                structure['languages'].add('JavaScript/TypeScript')
            elif file_path.suffix in ['.java']:
                structure['languages'].add('Java')
            elif file_path.suffix in ['.go']:
                structure['languages'].add('Go')
            elif file_path.suffix in ['.rb']:
                structure['languages'].add('Ruby')

            # Detect frameworks
            if file_path.name == 'package.json':
                structure['frameworks'].add('Node.js')
            elif file_path.name == 'requirements.txt':
                structure['frameworks'].add('Python')
            elif file_path.name == 'Gemfile':
                structure['frameworks'].add('Ruby')
            elif file_path.name == 'go.mod':
                structure['frameworks'].add('Go')

            # Detect entry points
            if file_path.name in ['main.py', 'app.py', 'server.py', 'index.js', 'main.go']:
                structure['entry_points'].append(str(file_path.relative_to(repo_path_obj)))

            # Detect tests
            if 'test' in file_path.name.lower() or 'spec' in file_path.name.lower():
                structure['has_tests'] = True

            # Detect CI/CD
            if file_path.name in ['.github', '.gitlab-ci.yml', 'Jenkinsfile', '.circleci']:
                structure['has_ci_cd'] = True

            # Detect Docker
            if file_path.name in ['Dockerfile', 'docker-compose.yml']:
                structure['has_docker'] = True

            # Detect sensitive files
            if self._is_sensitive_file(str(file_path)):
                structure['sensitive_files'].append(str(file_path.relative_to(repo_path_obj)))

        structure['languages'] = list(structure['languages'])
        structure['frameworks'] = list(structure['frameworks'])

        self.repo_structure = structure
        return structure

    def _is_sensitive_file(self, file_path: str) -> bool:
        """Check if file contains sensitive code"""
        for pattern in self.CRITICAL_FILE_PATTERNS.keys():
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    async def enrich_vulnerability(self, vuln: Dict, repo_path: str) -> Dict:
        """
        Enrich vulnerability with contextual information

        Args:
            vuln: Vulnerability dictionary
            repo_path: Path to repository

        Returns:
            Enriched vulnerability with additional context
        """
        enriched = vuln.copy()

        # Determine file context
        file_path = vuln.get('file_path', '')
        file_context = self._get_file_context(file_path)
        enriched['file_context'] = file_context

        # Read code snippet with context
        code_context = await self._get_code_context(
            repo_path,
            file_path,
            vuln.get('line_start', 0),
            vuln.get('line_end', 0)
        )
        enriched['code_context'] = code_context

        # Analyze data flow
        data_flow = self._analyze_data_flow(code_context.get('full_snippet', ''))
        enriched['data_flow'] = data_flow

        # Calculate risk score
        risk_score = self._calculate_risk_score(vuln, file_context, data_flow)
        enriched['risk_score'] = risk_score
        enriched['risk_level'] = self._get_risk_level(risk_score)

        # Determine exploitability
        exploitability = self._assess_exploitability(vuln, file_context, data_flow)
        enriched['exploitability'] = exploitability

        # Business impact
        business_impact = self._assess_business_impact(vuln, file_context)
        enriched['business_impact'] = business_impact

        return enriched

    def _get_file_context(self, file_path: str) -> Dict:
        """Determine the context/purpose of the file"""
        context = {
            'type': 'general',
            'sensitivity': 'low',
            'description': 'General application file'
        }

        for pattern, file_type in self.CRITICAL_FILE_PATTERNS.items():
            if re.search(pattern, file_path, re.IGNORECASE):
                context['type'] = file_type

                if file_type in ['authentication', 'payment', 'secrets']:
                    context['sensitivity'] = 'critical'
                    context['description'] = f'Critical {file_type} component'
                elif file_type in ['admin', 'api_endpoint', 'database']:
                    context['sensitivity'] = 'high'
                    context['description'] = f'High-risk {file_type} component'
                else:
                    context['sensitivity'] = 'medium'
                    context['description'] = f'{file_type.replace("_", " ").title()} component'

                break

        return context

    async def _get_code_context(
        self,
        repo_path: str,
        file_path: str,
        line_start: int,
        line_end: int,
        context_lines: int = 5
    ) -> Dict:
        """Get code snippet with surrounding context"""
        try:
            full_path = Path(repo_path) / file_path
            if not full_path.exists():
                return {
                    'before': [],
                    'vulnerable': [],
                    'after': [],
                    'full_snippet': ''
                }

            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            start_idx = max(0, line_start - context_lines - 1)
            end_idx = min(len(lines), line_end + context_lines)

            before = lines[start_idx:line_start - 1]
            vulnerable = lines[line_start - 1:line_end]
            after = lines[line_end:end_idx]

            return {
                'before': [line.rstrip() for line in before],
                'vulnerable': [line.rstrip() for line in vulnerable],
                'after': [line.rstrip() for line in after],
                'full_snippet': ''.join(lines[start_idx:end_idx])
            }

        except Exception as e:
            logger.error(f"Error reading code context: {e}")
            return {
                'before': [],
                'vulnerable': [],
                'after': [],
                'full_snippet': ''
            }

    def _analyze_data_flow(self, code_snippet: str) -> Dict:
        """Analyze data flow in code snippet"""
        flows = {
            'has_user_input': False,
            'has_database_query': False,
            'has_external_call': False,
            'has_crypto_operation': False,
            'flow_details': []
        }

        for flow_type, patterns in self.DATA_FLOW_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code_snippet, re.IGNORECASE | re.MULTILINE):
                    key = f'has_{flow_type}'
                    flows[key] = True
                    flows['flow_details'].append({
                        'type': flow_type,
                        'pattern': pattern
                    })

        return flows

    def _calculate_risk_score(
        self,
        vuln: Dict,
        file_context: Dict,
        data_flow: Dict
    ) -> float:
        """
        Calculate comprehensive risk score (0-100)

        Factors:
        - Base severity (40 points)
        - File sensitivity (20 points)
        - Data flow risk (20 points)
        - CVSS score (10 points)
        - Exploitability (10 points)
        """
        score = 0.0

        # Base severity (40 points)
        severity = vuln.get('severity', 'medium').lower()
        severity_scores = {
            'critical': 40,
            'high': 30,
            'medium': 20,
            'low': 10
        }
        score += severity_scores.get(severity, 20)

        # File sensitivity (20 points)
        sensitivity = file_context.get('sensitivity', 'low')
        sensitivity_scores = {
            'critical': 20,
            'high': 15,
            'medium': 10,
            'low': 5
        }
        score += sensitivity_scores.get(sensitivity, 5)

        # Data flow risk (20 points)
        if data_flow.get('has_user_input') and data_flow.get('has_database_query'):
            score += 20  # SQL injection risk
        elif data_flow.get('has_user_input') and data_flow.get('has_external_call'):
            score += 18  # Command injection risk
        elif data_flow.get('has_user_input'):
            score += 15  # User input handling
        elif data_flow.get('has_database_query'):
            score += 10  # Database access

        # CVSS score (10 points)
        cvss = vuln.get('cvss_score', 0)
        if cvss:
            score += min(10, cvss)

        # Verified secrets get maximum score
        if vuln.get('verified', False):
            score = max(score, 95)

        return min(100.0, score)

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'

    def _assess_exploitability(
        self,
        vuln: Dict,
        file_context: Dict,
        data_flow: Dict
    ) -> Dict:
        """Assess how easily the vulnerability can be exploited"""
        assessment = {
            'level': 'medium',
            'factors': [],
            'attack_vector': 'unknown'
        }

        # Check if vulnerability is in publicly accessible code
        if file_context.get('type') in ['api_endpoint', 'router']:
            assessment['factors'].append('Publicly accessible endpoint')
            assessment['attack_vector'] = 'remote'
            assessment['level'] = 'high'
        elif file_context.get('type') == 'admin':
            assessment['factors'].append('Admin interface')
            assessment['attack_vector'] = 'authenticated'
            assessment['level'] = 'medium'
        else:
            assessment['attack_vector'] = 'local'
            assessment['level'] = 'low'

        # Check for user input handling
        if data_flow.get('has_user_input'):
            assessment['factors'].append('Processes user input')
            assessment['level'] = 'high' if assessment['level'] != 'high' else 'critical'

        # Check category-specific exploitability
        category = vuln.get('category', '').lower()
        if 'injection' in category or 'sql' in category:
            assessment['factors'].append('Injection vulnerability')
            assessment['level'] = 'high'
        elif 'secret' in category or vuln.get('verified'):
            assessment['factors'].append('Exposed secret')
            assessment['level'] = 'critical'

        return assessment

    def _assess_business_impact(self, vuln: Dict, file_context: Dict) -> Dict:
        """Assess potential business impact"""
        impact = {
            'level': 'medium',
            'affected_areas': [],
            'potential_consequences': []
        }

        file_type = file_context.get('type', 'general')

        # Map file types to business impact
        if file_type == 'authentication':
            impact['level'] = 'critical'
            impact['affected_areas'] = ['User accounts', 'Access control']
            impact['potential_consequences'] = [
                'Unauthorized access',
                'Account takeover',
                'Data breach'
            ]
        elif file_type == 'payment':
            impact['level'] = 'critical'
            impact['affected_areas'] = ['Payment processing', 'Financial data']
            impact['potential_consequences'] = [
                'Financial fraud',
                'PCI compliance violation',
                'Revenue loss'
            ]
        elif file_type == 'database':
            impact['level'] = 'high'
            impact['affected_areas'] = ['Data storage', 'Data integrity']
            impact['potential_consequences'] = [
                'Data breach',
                'Data loss',
                'Privacy violation'
            ]
        elif file_type == 'api_endpoint':
            impact['level'] = 'high'
            impact['affected_areas'] = ['API functionality', 'Service availability']
            impact['potential_consequences'] = [
                'Service disruption',
                'Data exposure',
                'Rate limit bypass'
            ]
        else:
            impact['level'] = 'medium'
            impact['affected_areas'] = ['Application functionality']
            impact['potential_consequences'] = [
                'Degraded user experience',
                'Minor security issue'
            ]

        # Adjust based on OWASP category
        owasp = vuln.get('owasp_category', '')
        if owasp in ['A01', 'A02', 'A03']:  # Top 3 OWASP risks
            impact['level'] = 'high' if impact['level'] == 'medium' else impact['level']

        return impact

    async def prioritize_vulnerabilities(
        self,
        vulnerabilities: List[Dict],
        repo_path: str
    ) -> List[Dict]:
        """
        Prioritize vulnerabilities based on context analysis

        Returns:
            Sorted list of vulnerabilities (highest priority first)
        """
        # Enrich all vulnerabilities
        enriched = []
        for vuln in vulnerabilities:
            enriched_vuln = await self.enrich_vulnerability(vuln, repo_path)
            enriched.append(enriched_vuln)

        # Sort by risk score (descending)
        enriched.sort(key=lambda v: v.get('risk_score', 0), reverse=True)

        return enriched

    def generate_priority_report(self, enriched_vulnerabilities: List[Dict]) -> Dict:
        """Generate a priority report from enriched vulnerabilities"""
        report = {
            'total_vulnerabilities': len(enriched_vulnerabilities),
            'critical_priority': 0,
            'high_priority': 0,
            'medium_priority': 0,
            'low_priority': 0,
            'top_risks': [],
            'by_file_type': {},
            'by_attack_vector': {},
            'immediate_actions': []
        }

        for vuln in enriched_vulnerabilities:
            risk_level = vuln.get('risk_level', 'medium')

            # Count by priority
            if risk_level == 'critical':
                report['critical_priority'] += 1
            elif risk_level == 'high':
                report['high_priority'] += 1
            elif risk_level == 'medium':
                report['medium_priority'] += 1
            else:
                report['low_priority'] += 1

            # Track by file type
            file_type = vuln.get('file_context', {}).get('type', 'unknown')
            report['by_file_type'][file_type] = report['by_file_type'].get(file_type, 0) + 1

            # Track by attack vector
            attack_vector = vuln.get('exploitability', {}).get('attack_vector', 'unknown')
            report['by_attack_vector'][attack_vector] = report['by_attack_vector'].get(attack_vector, 0) + 1

        # Get top 10 highest risk
        report['top_risks'] = enriched_vulnerabilities[:10]

        # Generate immediate actions
        for vuln in enriched_vulnerabilities[:5]:  # Top 5
            if vuln.get('risk_level') in ['critical', 'high']:
                report['immediate_actions'].append({
                    'file': vuln.get('file_path'),
                    'line': vuln.get('line_start'),
                    'title': vuln.get('title'),
                    'action': f"Fix {vuln.get('risk_level')} risk in {vuln.get('file_context', {}).get('type', 'file')}"
                })

        return report
