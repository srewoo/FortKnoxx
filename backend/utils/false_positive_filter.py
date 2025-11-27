"""
False Positive Filter - Reduces noise from multiple scanners
Implements intelligent filtering to minimize false positives
"""

import logging
from typing import List, Dict
from collections import defaultdict

logger = logging.getLogger(__name__)


# Scanner reliability scores (0.0 to 1.0)
SCANNER_RELIABILITY = {
    'gitleaks': 0.98,        # Excellent for secrets
    'trufflehog': 0.95,      # Very accurate secret detection
    'semgrep': 0.95,         # High quality SAST
    'trivy': 0.92,           # Strong CVE database
    'snyk': 0.92,            # Excellent dependency scanner
    'grype': 0.90,           # Good vulnerability detection
    'checkov': 0.88,         # Good IaC detection
    'bandit': 0.85,          # Good for Python security
    'gosec': 0.85,           # Good for Go security
    'cargo-audit': 0.90,     # Rust advisory database
    'horusec': 0.80,         # Multi-language aggregator
    'eslint': 0.82,          # Some style false positives
    'nuclei': 0.85,          # Good CVE templates
    'zap': 0.75,             # Static analysis only (partial DAST)
    'pyre': 0.80,            # Type checking
    'spotbugs': 0.82,        # Java bytecode analysis
    'pylint': 0.70,          # Many code quality FPs
    'flake8': 0.65,          # High FP for style issues
    'radon': 0.70,           # Complexity metrics
    'shellcheck': 0.85,      # Good shell analysis
    'hadolint': 0.80,        # Docker best practices
    'sqlfluff': 0.75,        # SQL style/security
    'pydeps': 0.70,          # Architecture analysis
    'pip-audit': 0.88,       # Python CVE database
    'npm-audit': 0.85,       # NPM CVE database
    'syft': 0.90,            # SBOM/licensing
}


def filter_false_positives(
    issues: List[Dict],
    confidence_threshold: str = "medium",
    enable_deduplication: bool = True,
    enable_context_filtering: bool = True
) -> List[Dict]:
    """
    Filter false positives using multiple strategies

    Args:
        issues: List of vulnerability/issue dictionaries
        confidence_threshold: "low", "medium", or "high" - minimum confidence to include
        enable_deduplication: Remove duplicate findings
        enable_context_filtering: Filter based on file context (tests, examples, etc.)

    Returns:
        Filtered list of issues
    """
    filtered = issues

    # Step 1: Context-based filtering (test files, examples, etc.)
    if enable_context_filtering:
        filtered = [issue for issue in filtered if not _is_likely_false_positive(issue)]
        logger.info(f"Context filtering: {len(issues)} → {len(filtered)} issues")

    # Step 2: Deduplication and confidence scoring
    if enable_deduplication:
        filtered = _deduplicate_and_score(filtered)
        logger.info(f"After deduplication: {len(filtered)} unique issues")

    # Step 3: Apply confidence threshold (but NEVER filter critical/high severity)
    threshold_map = {"low": 0.0, "medium": 0.4, "high": 0.65}  # Lowered thresholds to be safer
    min_confidence = threshold_map.get(confidence_threshold, 0.4)
    filtered = [
        issue for issue in filtered
        if issue.get('confidence_score', 0.5) >= min_confidence
        or issue.get('severity', '').lower() in ['critical', 'high']  # Always keep critical/high
    ]
    logger.info(f"After confidence threshold ({confidence_threshold}): {len(filtered)} issues")

    return filtered


def _is_likely_false_positive(issue: Dict) -> bool:
    """
    Check if issue is likely a false positive based on context.

    IMPORTANT: This function is CONSERVATIVE - when in doubt, we do NOT filter.
    Real vulnerabilities should never be hidden from users.
    """
    file_path = issue.get('file_path', '').lower()
    category = issue.get('category', '').lower()
    severity = issue.get('severity', '').lower()
    detected_by = issue.get('detected_by', '').lower()
    title = issue.get('title', '').lower()

    # RULE 0: NEVER filter critical or high severity issues - they require human review
    if severity in ['critical', 'high']:
        return False  # Always show critical/high issues

    # RULE 1: NEVER filter security-sensitive categories regardless of location
    security_categories = [
        'secret', 'credential', 'password', 'api_key', 'token', 'private_key',
        'sql injection', 'sqli', 'command injection', 'rce', 'remote code',
        'xss', 'cross-site', 'csrf', 'ssrf', 'path traversal', 'lfi', 'rfi',
        'deserialization', 'xxe', 'authentication', 'authorization', 'crypto',
        'cve-', 'cwe-'
    ]
    if any(sec_cat in category or sec_cat in title for sec_cat in security_categories):
        return False  # Always show security issues

    # Filter 1: Dependency directories only (these are third-party code, not user's responsibility)
    dependency_dirs = ['node_modules/', 'vendor/', 'venv/', '.venv/', '__pycache__/', '.git/']
    if any(dep_dir in file_path for dep_dir in dependency_dirs):
        return True  # Third-party code - safe to filter

    # Filter 2: Build artifacts (generated code, not source)
    build_dirs = ['/dist/', '/build/', '/out/', '/.next/', '/__generated__/']
    if any(build_dir in file_path for build_dir in build_dirs):
        return True  # Generated code - safe to filter

    # Filter 3: Only filter STYLE issues (not security) from linters in LOW severity
    if detected_by in ['pylint', 'flake8', 'eslint'] and severity == 'low':
        # Only filter pure style/formatting issues
        pure_style_categories = ['line-too-long', 'trailing-whitespace', 'missing-docstring',
                                  'invalid-name', 'missing-final-newline', 'indent', 'whitespace',
                                  'blank-line', 'import-order']
        if any(style in category for style in pure_style_categories):
            return True  # Pure style issues - safe to filter

    # Filter 4: Complexity metrics in documentation files only
    if any(file_path.endswith(ext) for ext in ['.md', '.txt', '.rst', '.adoc']):
        if 'complexity' in category or 'maintainability' in category:
            return True  # Complexity in docs - safe to filter

    # DEFAULT: Do NOT filter - show the issue to the user
    return False


def _deduplicate_and_score(issues: List[Dict]) -> List[Dict]:
    """
    Deduplicate similar issues and calculate confidence scores
    Issues found by multiple scanners get higher confidence
    """
    # Group issues by fingerprint
    issue_groups = defaultdict(lambda: {
        'issues': [],
        'scanners': set(),
        'severities': defaultdict(int)
    })

    for issue in issues:
        # Create fingerprint based on location and type
        fingerprint = _create_fingerprint(issue)

        group = issue_groups[fingerprint]
        group['issues'].append(issue)
        group['scanners'].add(issue.get('detected_by', 'unknown'))
        group['severities'][issue.get('severity', 'medium')] += 1

    # Build deduplicated list with confidence scores
    deduplicated = []

    for fingerprint, group in issue_groups.items():
        # Use the most detailed issue as the base
        base_issue = max(group['issues'], key=lambda x: len(x.get('description', '')))

        # Calculate confidence score
        scanner_count = len(group['scanners'])
        scanner_names = list(group['scanners'])

        # Base confidence from scanner reliability
        reliability_scores = [
            SCANNER_RELIABILITY.get(scanner.lower(), 0.5)
            for scanner in scanner_names
        ]
        avg_reliability = sum(reliability_scores) / len(reliability_scores) if reliability_scores else 0.5

        # Boost confidence if multiple scanners agree
        multi_scanner_boost = min(scanner_count * 0.1, 0.3)  # Up to +0.3 for 3+ scanners

        confidence_score = min(avg_reliability + multi_scanner_boost, 1.0)

        # Determine consensus severity (most common)
        consensus_severity = max(group['severities'].items(), key=lambda x: x[1])[0]

        # Enhance the base issue
        base_issue['confidence_score'] = confidence_score
        base_issue['detection_count'] = scanner_count
        base_issue['detected_by_scanners'] = scanner_names
        base_issue['severity'] = consensus_severity  # Use consensus severity

        # Add confidence label
        if confidence_score >= 0.85:
            base_issue['confidence_label'] = 'Very High'
        elif confidence_score >= 0.75:
            base_issue['confidence_label'] = 'High'
        elif confidence_score >= 0.5:
            base_issue['confidence_label'] = 'Medium'
        else:
            base_issue['confidence_label'] = 'Low'

        deduplicated.append(base_issue)

    return deduplicated


def _create_fingerprint(issue: Dict) -> str:
    """
    Create a fingerprint for issue deduplication
    Groups issues that are essentially the same finding
    """
    file_path = issue.get('file_path', 'unknown')
    line_start = issue.get('line_start', 0)

    # Normalize category/CWE
    category = issue.get('cwe', '') or issue.get('category', '') or issue.get('owasp_category', '')
    category = category.lower().strip()

    # Create fingerprint: file:line:category
    # Use line range (±2 lines) to catch similar issues
    line_bucket = (line_start // 3) * 3  # Group lines in buckets of 3

    fingerprint = f"{file_path}:{line_bucket}:{category}"
    return fingerprint


def get_filter_stats(original_count: int, filtered_count: int) -> Dict:
    """
    Get statistics about filtering effectiveness
    """
    reduction_count = original_count - filtered_count
    reduction_percent = (reduction_count / original_count * 100) if original_count > 0 else 0

    return {
        'original_count': original_count,
        'filtered_count': filtered_count,
        'reduction_count': reduction_count,
        'reduction_percent': round(reduction_percent, 1),
        'false_positive_rate_estimate': f"{round(reduction_percent, 1)}%"
    }
