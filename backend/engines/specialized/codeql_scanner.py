"""
CodeQL Scanner Integration
Integrates GitHub's CodeQL for semantic code analysis
"""

import asyncio
import subprocess
import json
import logging
import tempfile
import shutil
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class CodeQLLanguage(str, Enum):
    """Supported CodeQL languages"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    CPP = "cpp"
    GO = "go"
    RUBY = "ruby"


@dataclass
class CodeQLFinding:
    """CodeQL analysis finding"""
    rule_id: str
    rule_name: str
    severity: str
    message: str

    file_path: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int

    code_snippet: Optional[str] = None
    cwe_ids: List[str] = None

    def __post_init__(self):
        if self.cwe_ids is None:
            self.cwe_ids = []


class CodeQLScanner:
    """
    Integrates GitHub CodeQL for deep semantic analysis
    Uses CodeQL CLI to run queries and analyze results
    """

    def __init__(self, codeql_path: str = "/opt/codeql/codeql"):
        """
        Initialize CodeQL scanner

        Args:
            codeql_path: Path to CodeQL CLI executable
        """
        self.codeql_path = codeql_path
        self.findings: List[CodeQLFinding] = []

        # Verify CodeQL is installed
        if not self._check_codeql_installed():
            logger.warning(
                "CodeQL not found. Install from: "
                "https://github.com/github/codeql-cli-binaries/releases"
            )

    def _check_codeql_installed(self) -> bool:
        """Check if CodeQL CLI is installed"""
        try:
            result = subprocess.run(
                [self.codeql_path, "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"CodeQL version: {result.stdout.strip()}")
                return True
            return False
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    async def scan_repository(
        self,
        repo_path: str,
        language: CodeQLLanguage,
        query_suite: str = "security-extended"
    ) -> List[CodeQLFinding]:
        """
        Scan repository with CodeQL

        Args:
            repo_path: Path to repository
            language: Programming language
            query_suite: Query suite to run (security-extended, security-and-quality, etc.)

        Returns:
            List of findings
        """
        logger.info(f"Starting CodeQL scan of {repo_path} ({language.value})")

        self.findings = []

        # Create temporary database directory
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "codeql-db"

            # Step 1: Create CodeQL database
            logger.info("Creating CodeQL database...")
            if not await self._create_database(repo_path, str(db_path), language):
                logger.error("Failed to create CodeQL database")
                return []

            # Step 2: Run analysis
            logger.info(f"Running {query_suite} queries...")
            results_file = Path(temp_dir) / "results.sarif"
            if not await self._run_analysis(str(db_path), language, query_suite, str(results_file)):
                logger.error("Failed to run CodeQL analysis")
                return []

            # Step 3: Parse results
            logger.info("Parsing results...")
            self.findings = self._parse_sarif_results(results_file, repo_path)

        logger.info(f"CodeQL scan completed: {len(self.findings)} findings")
        return self.findings

    async def _create_database(
        self,
        repo_path: str,
        db_path: str,
        language: CodeQLLanguage
    ) -> bool:
        """Create CodeQL database from source code"""

        cmd = [
            self.codeql_path,
            "database", "create",
            db_path,
            f"--language={language.value}",
            f"--source-root={repo_path}",
            "--overwrite"
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info("CodeQL database created successfully")
                return True
            else:
                logger.error(f"Database creation failed: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error creating database: {str(e)}")
            return False

    async def _run_analysis(
        self,
        db_path: str,
        language: CodeQLLanguage,
        query_suite: str,
        output_file: str
    ) -> bool:
        """Run CodeQL analysis queries"""

        # Map language to query suite path
        query_path = f"{language.value}-{query_suite}.qls"

        cmd = [
            self.codeql_path,
            "database", "analyze",
            db_path,
            query_path,
            "--format=sarif-latest",
            f"--output={output_file}",
            "--threads=0"  # Use all available cores
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info("CodeQL analysis completed successfully")
                return True
            else:
                logger.error(f"Analysis failed: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error running analysis: {str(e)}")
            return False

    def _parse_sarif_results(
        self,
        sarif_file: Path,
        repo_path: str
    ) -> List[CodeQLFinding]:
        """Parse SARIF results file"""

        if not sarif_file.exists():
            logger.warning(f"SARIF file not found: {sarif_file}")
            return []

        try:
            with open(sarif_file, 'r') as f:
                sarif_data = json.load(f)

            findings = []

            for run in sarif_data.get('runs', []):
                # Get rules for metadata
                rules = {}
                for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
                    rules[rule['id']] = rule

                # Parse results
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'unknown')
                    rule = rules.get(rule_id, {})

                    # Get location
                    locations = result.get('locations', [])
                    if not locations:
                        continue

                    location = locations[0].get('physicalLocation', {})
                    artifact = location.get('artifactLocation', {})
                    region = location.get('region', {})

                    file_path = artifact.get('uri', 'unknown')
                    start_line = region.get('startLine', 0)
                    end_line = region.get('endLine', start_line)
                    start_column = region.get('startColumn', 0)
                    end_column = region.get('endColumn', 0)

                    # Get code snippet
                    code_snippet = region.get('snippet', {}).get('text', '')

                    # Extract severity
                    severity = result.get('level', 'warning')
                    if severity == 'error':
                        severity = 'high'
                    elif severity == 'warning':
                        severity = 'medium'
                    else:
                        severity = 'low'

                    # Get CWE IDs
                    cwe_ids = []
                    for tag in rule.get('properties', {}).get('tags', []):
                        if tag.startswith('external/cwe/cwe-'):
                            cwe_ids.append(tag.replace('external/cwe/cwe-', 'CWE-'))

                    finding = CodeQLFinding(
                        rule_id=rule_id,
                        rule_name=rule.get('name', rule_id),
                        severity=severity,
                        message=result.get('message', {}).get('text', ''),
                        file_path=str(Path(repo_path) / file_path),
                        start_line=start_line,
                        end_line=end_line,
                        start_column=start_column,
                        end_column=end_column,
                        code_snippet=code_snippet,
                        cwe_ids=cwe_ids
                    )

                    findings.append(finding)

            return findings

        except Exception as e:
            logger.error(f"Error parsing SARIF results: {str(e)}")
            return []

    async def run_custom_query(
        self,
        db_path: str,
        query_file: str,
        output_format: str = "sarif-latest"
    ) -> Optional[str]:
        """
        Run a custom CodeQL query

        Args:
            db_path: Path to CodeQL database
            query_file: Path to .ql query file
            output_format: Output format (sarif-latest, csv, json)

        Returns:
            Query results as string
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            output_file = f.name

        cmd = [
            self.codeql_path,
            "database", "analyze",
            db_path,
            query_file,
            f"--format={output_format}",
            f"--output={output_file}"
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                with open(output_file, 'r') as f:
                    return f.read()
            else:
                logger.error(f"Custom query failed: {stderr.decode()}")
                return None

        except Exception as e:
            logger.error(f"Error running custom query: {str(e)}")
            return None
        finally:
            # Cleanup
            try:
                Path(output_file).unlink()
            except:
                pass

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive CodeQL report"""

        findings_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        findings_by_cwe = {}

        for finding in self.findings:
            # Group by severity
            findings_by_severity[finding.severity].append(finding)

            # Group by CWE
            for cwe in finding.cwe_ids:
                if cwe not in findings_by_cwe:
                    findings_by_cwe[cwe] = []
                findings_by_cwe[cwe].append(finding)

        return {
            "summary": {
                "total_findings": len(self.findings),
                "critical": len(findings_by_severity['critical']),
                "high": len(findings_by_severity['high']),
                "medium": len(findings_by_severity['medium']),
                "low": len(findings_by_severity['low'])
            },
            "cwe_coverage": {
                cwe: len(findings)
                for cwe, findings in findings_by_cwe.items()
            },
            "top_issues": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "file": f.file_path,
                    "line": f.start_line,
                    "message": f.message[:100] + "..." if len(f.message) > 100 else f.message
                }
                for f in sorted(
                    self.findings,
                    key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x.severity]
                )[:10]
            ],
            "files_with_issues": len(set(f.file_path for f in self.findings))
        }

    def export_to_sarif(self, output_file: str):
        """Export findings to SARIF format for tool integration"""

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "FortKnoxx CodeQL Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/fortknox"
                    }
                },
                "results": []
            }]
        }

        for finding in self.findings:
            result = {
                "ruleId": finding.rule_id,
                "level": "error" if finding.severity in ['critical', 'high'] else "warning",
                "message": {
                    "text": finding.message
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path
                        },
                        "region": {
                            "startLine": finding.start_line,
                            "endLine": finding.end_line,
                            "startColumn": finding.start_column,
                            "endColumn": finding.end_column
                        }
                    }
                }]
            }

            sarif["runs"][0]["results"].append(result)

        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2)

        logger.info(f"SARIF results exported to {output_file}")
