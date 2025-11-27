"""
CodeQL Scanner Integration
Advanced semantic code analysis using GitHub's CodeQL
"""

import subprocess
import json
import os
from typing import List, Dict, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CodeQLScanner:
    """
    CodeQL - GitHub's semantic code analysis engine

    Features:
    - Deep dataflow analysis
    - Taint tracking
    - Path-sensitive analysis
    - Language support: Python, JavaScript, Java, Go, C++, C#, Ruby
    """

    def __init__(self):
        self.codeql_path = self._find_codeql()

    def _find_codeql(self) -> Optional[str]:
        """Find CodeQL CLI in system PATH"""
        import shutil
        return shutil.which("codeql")

    async def is_available(self) -> bool:
        """Check if CodeQL is installed"""
        return self.codeql_path is not None

    async def scan(self, repo_path: str, languages: List[str] = None) -> List[Dict]:
        """
        Run CodeQL security analysis

        Args:
            repo_path: Path to repository
            languages: Languages to scan (auto-detect if None)

        Returns:
            List of vulnerabilities found
        """
        if not await self.is_available():
            logger.warning("CodeQL not installed. Skipping scan.")
            return []

        try:
            # Auto-detect languages if not specified
            if not languages:
                languages = await self._detect_languages(repo_path)

            # Create CodeQL database
            db_path = await self._create_database(repo_path, languages)

            if not db_path:
                return []

            # Run analysis
            results = await self._run_queries(db_path, languages)

            # Parse results
            vulnerabilities = await self._parse_results(results, repo_path)

            # Cleanup
            await self._cleanup_database(db_path)

            return vulnerabilities

        except Exception as e:
            logger.error(f"CodeQL scan error: {str(e)}")
            return []

    async def _detect_languages(self, repo_path: str) -> List[str]:
        """Auto-detect languages in repository"""
        languages = []

        # Simple file extension based detection
        extensions_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.jsx': 'javascript',
            '.tsx': 'javascript',
            '.java': 'java',
            '.go': 'go',
            '.cpp': 'cpp',
            '.c': 'cpp',
            '.cs': 'csharp',
            '.rb': 'ruby'
        }

        for root, dirs, files in os.walk(repo_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__']]

            for file in files:
                ext = Path(file).suffix
                if ext in extensions_map:
                    lang = extensions_map[ext]
                    if lang not in languages:
                        languages.append(lang)

        logger.info(f"Detected languages: {languages}")
        return languages

    async def _create_database(self, repo_path: str, languages: List[str]) -> Optional[str]:
        """Create CodeQL database"""
        db_path = f"{repo_path}/.codeql-db"

        # Remove existing database
        if os.path.exists(db_path):
            import shutil
            shutil.rmtree(db_path)

        language_str = ','.join(languages)

        cmd = [
            self.codeql_path,
            "database", "create",
            db_path,
            f"--language={language_str}",
            f"--source-root={repo_path}",
            "--overwrite"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )

            if result.returncode == 0:
                logger.info(f"CodeQL database created at {db_path}")
                return db_path
            else:
                logger.error(f"Failed to create CodeQL database: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("CodeQL database creation timed out")
            return None
        except Exception as e:
            logger.error(f"Error creating CodeQL database: {str(e)}")
            return None

    async def _run_queries(self, db_path: str, languages: List[str]) -> Optional[str]:
        """Run CodeQL security queries"""
        results_path = f"{db_path}/results.sarif"

        # Use built-in security queries
        query_suite = "security-extended"

        cmd = [
            self.codeql_path,
            "database", "analyze",
            db_path,
            f"--format=sarif-latest",
            f"--output={results_path}",
            f"--threads=0",  # Use all available cores
            query_suite
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode == 0:
                logger.info(f"CodeQL analysis completed. Results: {results_path}")
                return results_path
            else:
                logger.error(f"CodeQL analysis failed: {result.stderr}")
                return None

        except Exception as e:
            logger.error(f"Error running CodeQL analysis: {str(e)}")
            return None

    async def _parse_results(self, results_path: Optional[str], repo_path: str) -> List[Dict]:
        """Parse SARIF results into vulnerability format"""
        if not results_path or not os.path.exists(results_path):
            return []

        vulnerabilities = []

        try:
            with open(results_path, 'r') as f:
                sarif_data = json.load(f)

            for run in sarif_data.get('runs', []):
                for result in run.get('results', []):
                    vuln = self._convert_sarif_result(result, repo_path, run)
                    if vuln:
                        vulnerabilities.append(vuln)

            logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from CodeQL results")

        except Exception as e:
            logger.error(f"Error parsing CodeQL results: {str(e)}")

        return vulnerabilities

    def _convert_sarif_result(self, result: Dict, repo_path: str, run: Dict) -> Optional[Dict]:
        """Convert SARIF result to internal vulnerability format"""
        try:
            # Get primary location
            locations = result.get('locations', [])
            if not locations:
                return None

            location = locations[0]
            physical_location = location.get('physicalLocation', {})
            artifact = physical_location.get('artifactLocation', {})
            region = physical_location.get('region', {})

            # Get file path
            file_path = artifact.get('uri', 'unknown')

            # Get line numbers
            start_line = region.get('startLine', 0)
            end_line = region.get('endLine', start_line)

            # Get rule details
            rule_id = result.get('ruleId', 'unknown')
            rule = self._find_rule(rule_id, run)

            # Get severity
            severity_level = result.get('level', 'warning')
            severity = self._map_severity(severity_level)

            # Get message
            message = result.get('message', {}).get('text', 'Security issue detected')

            # Get code snippet
            code_snippet = region.get('snippet', {}).get('text', '')

            # Determine OWASP category
            owasp_category = self._map_to_owasp(rule_id, message)

            return {
                'file_path': file_path,
                'line_start': start_line,
                'line_end': end_line,
                'severity': severity,
                'category': f"codeql-{rule_id}",
                'owasp_category': owasp_category,
                'title': rule.get('shortDescription', {}).get('text', message),
                'description': rule.get('fullDescription', {}).get('text', message),
                'code_snippet': code_snippet,
                'cwe': self._extract_cwe(rule),
                'detected_by': 'CodeQL',
                'help_url': rule.get('helpUri', ''),
                'dataflow': self._extract_dataflow(result)
            }

        except Exception as e:
            logger.error(f"Error converting SARIF result: {str(e)}")
            return None

    def _find_rule(self, rule_id: str, run: Dict) -> Dict:
        """Find rule definition in SARIF run"""
        tool = run.get('tool', {})
        driver = tool.get('driver', {})
        rules = driver.get('rules', [])

        for rule in rules:
            if rule.get('id') == rule_id:
                return rule

        return {}

    def _map_severity(self, level: str) -> str:
        """Map SARIF severity to internal format"""
        mapping = {
            'error': 'high',
            'warning': 'medium',
            'note': 'low',
            'none': 'info'
        }
        return mapping.get(level, 'medium')

    def _map_to_owasp(self, rule_id: str, message: str) -> str:
        """Map CodeQL finding to OWASP Top 10"""
        text = f"{rule_id} {message}".lower()

        if any(word in text for word in ['sql', 'injection', 'command', 'xpath', 'ldap']):
            return 'A03'
        elif any(word in text for word in ['xss', 'cross-site']):
            return 'A03'
        elif any(word in text for word in ['auth', 'session', 'token', 'password']):
            return 'A07'
        elif any(word in text for word in ['crypto', 'hash', 'encryption']):
            return 'A02'
        elif any(word in text for word in ['access', 'authorization', 'permission']):
            return 'A01'
        elif any(word in text for word in ['ssrf', 'request forgery']):
            return 'A10'
        elif any(word in text for word in ['deserialization', 'pickle']):
            return 'A08'
        elif any(word in text for word in ['log', 'logging']):
            return 'A09'
        else:
            return 'A05'

    def _extract_cwe(self, rule: Dict) -> Optional[str]:
        """Extract CWE from rule properties"""
        properties = rule.get('properties', {})
        tags = properties.get('tags', [])

        for tag in tags:
            if tag.startswith('external/cwe/cwe-'):
                return tag.replace('external/cwe/', '').upper()

        return None

    def _extract_dataflow(self, result: Dict) -> Optional[List[Dict]]:
        """Extract dataflow/taint tracking information"""
        code_flows = result.get('codeFlows', [])
        if not code_flows:
            return None

        flows = []
        for flow in code_flows:
            thread_flows = flow.get('threadFlows', [])
            for thread_flow in thread_flows:
                locations = thread_flow.get('locations', [])
                flow_steps = []

                for loc in locations:
                    location = loc.get('location', {})
                    physical = location.get('physicalLocation', {})
                    artifact = physical.get('artifactLocation', {})
                    region = physical.get('region', {})

                    flow_steps.append({
                        'file': artifact.get('uri', 'unknown'),
                        'line': region.get('startLine', 0),
                        'message': location.get('message', {}).get('text', '')
                    })

                flows.append(flow_steps)

        return flows if flows else None

    async def _cleanup_database(self, db_path: str):
        """Clean up CodeQL database"""
        try:
            import shutil
            if os.path.exists(db_path):
                shutil.rmtree(db_path)
                logger.info(f"Cleaned up CodeQL database: {db_path}")
        except Exception as e:
            logger.warning(f"Failed to cleanup CodeQL database: {str(e)}")


# Installation instructions
"""
To install CodeQL:

1. Download from: https://github.com/github/codeql-cli-binaries/releases
2. Extract and add to PATH:

   macOS/Linux:
   export PATH="/path/to/codeql:$PATH"

   Or via Homebrew:
   brew install codeql

3. Verify installation:
   codeql --version

4. Download standard queries (optional but recommended):
   codeql pack download codeql/python-queries
   codeql pack download codeql/javascript-queries
   codeql pack download codeql/java-queries
"""
