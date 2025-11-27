"""
Comprehensive Reporting System
Generates executive, developer, and security team reports
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates comprehensive security reports for different audiences
    """

    def __init__(self, db):
        """
        Args:
            db: MongoDB database connection
        """
        self.db = db

    async def generate_executive_summary(
        self,
        repo_id: str,
        scan_id: Optional[str] = None
    ) -> Dict:
        """
        Generate executive summary report

        High-level overview for non-technical stakeholders focusing on:
        - Overall security posture
        - Business risk
        - Trends
        - Compliance status
        """
        # Get repository info
        repo = await self.db.repositories.find_one({"id": repo_id}, {"_id": 0})
        if not repo:
            raise ValueError(f"Repository {repo_id} not found")

        # Get latest scan or specific scan
        if scan_id:
            scan = await self.db.scans.find_one({"id": scan_id}, {"_id": 0})
        else:
            scan = await self.db.scans.find_one(
                {"repo_id": repo_id},
                {"_id": 0},
                sort=[("created_at", -1)]
            )

        if not scan:
            raise ValueError("No scans found for repository")

        # Get all vulnerabilities for this scan
        vulns = await self.db.vulnerabilities.find(
            {"scan_id": scan["id"]},
            {"_id": 0}
        ).to_list(10000)

        # Calculate key metrics
        total_vulns = len(vulns)
        critical_count = sum(1 for v in vulns if v.get("severity") == "critical")
        high_count = sum(1 for v in vulns if v.get("severity") == "high")
        medium_count = sum(1 for v in vulns if v.get("severity") == "medium")
        low_count = sum(1 for v in vulns if v.get("severity") == "low")

        # Calculate security score
        security_score = scan.get("security_score", 0)

        # Get risk rating
        if security_score >= 80:
            risk_rating = "Low Risk"
            risk_color = "green"
        elif security_score >= 60:
            risk_rating = "Medium Risk"
            risk_color = "yellow"
        elif security_score >= 40:
            risk_rating = "High Risk"
            risk_color = "orange"
        else:
            risk_rating = "Critical Risk"
            risk_color = "red"

        # Get top OWASP categories
        owasp_counts = Counter([v.get("owasp_category", "Unknown") for v in vulns])
        top_owasp = owasp_counts.most_common(5)

        # Get trends (compare with previous scans)
        trend = await self._calculate_trends(repo_id, scan["id"])

        # Business impact analysis
        business_impact = self._assess_business_impact_summary(vulns)

        # Compliance status
        compliance = self._assess_compliance_status(vulns)

        report = {
            "report_type": "Executive Summary",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repository": {
                "name": repo.get("name"),
                "url": repo.get("url"),
                "last_scan": scan.get("completed_at")
            },
            "security_posture": {
                "score": security_score,
                "rating": risk_rating,
                "color": risk_color,
                "total_vulnerabilities": total_vulns,
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "key_findings": {
                "most_critical_issues": [
                    {
                        "title": v.get("title"),
                        "file": v.get("file_path"),
                        "risk_level": v.get("risk_level", v.get("severity"))
                    }
                    for v in sorted(vulns, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]
                ],
                "top_owasp_risks": [
                    {"category": cat, "count": count}
                    for cat, count in top_owasp
                ]
            },
            "trends": trend,
            "business_impact": business_impact,
            "compliance": compliance,
            "recommendations": self._generate_executive_recommendations(
                critical_count,
                high_count,
                security_score,
                business_impact
            )
        }

        return report

    async def generate_developer_report(
        self,
        repo_id: str,
        scan_id: Optional[str] = None
    ) -> Dict:
        """
        Generate detailed developer report

        Technical details for developers including:
        - Specific vulnerabilities
        - Code locations
        - Fix recommendations
        - Examples
        """
        # Get scan info
        if scan_id:
            scan = await self.db.scans.find_one({"id": scan_id}, {"_id": 0})
        else:
            scan = await self.db.scans.find_one(
                {"repo_id": repo_id},
                {"_id": 0},
                sort=[("created_at", -1)]
            )

        if not scan:
            raise ValueError("No scans found")

        # Get all vulnerabilities
        vulns = await self.db.vulnerabilities.find(
            {"scan_id": scan["id"]},
            {"_id": 0}
        ).to_list(10000)

        # Group by file
        by_file = defaultdict(list)
        for vuln in vulns:
            by_file[vuln.get("file_path", "unknown")].append(vuln)

        # Group by category
        by_category = defaultdict(list)
        for vuln in vulns:
            by_category[vuln.get("category", "unknown")].append(vuln)

        # Group by severity
        by_severity = {
            "critical": [v for v in vulns if v.get("severity") == "critical"],
            "high": [v for v in vulns if v.get("severity") == "high"],
            "medium": [v for v in vulns if v.get("severity") == "medium"],
            "low": [v for v in vulns if v.get("severity") == "low"]
        }

        # Scanner statistics
        scanner_stats = scan.get("scan_results", {})

        report = {
            "report_type": "Developer Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_summary": {
                "scan_id": scan["id"],
                "completed_at": scan.get("completed_at"),
                "total_files": scan.get("total_files", 0),
                "total_vulnerabilities": len(vulns),
                "scanners_used": list(scanner_stats.keys()),
                "scanner_results": scanner_stats
            },
            "vulnerabilities_by_severity": {
                severity: [
                    {
                        "id": v.get("id"),
                        "file": v.get("file_path"),
                        "line": v.get("line_start"),
                        "title": v.get("title"),
                        "category": v.get("category"),
                        "detected_by": v.get("detected_by"),
                        "code_snippet": v.get("code_snippet", "")[:100],
                        "description": v.get("description", "")[:200]
                    }
                    for v in vulns_list
                ]
                for severity, vulns_list in by_severity.items()
            },
            "vulnerabilities_by_file": {
                file_path: {
                    "total": len(file_vulns),
                    "critical": sum(1 for v in file_vulns if v.get("severity") == "critical"),
                    "high": sum(1 for v in file_vulns if v.get("severity") == "high"),
                    "issues": [
                        {
                            "line": v.get("line_start"),
                            "severity": v.get("severity"),
                            "title": v.get("title"),
                            "category": v.get("category")
                        }
                        for v in sorted(file_vulns, key=lambda x: x.get("line_start", 0))
                    ]
                }
                for file_path, file_vulns in sorted(
                    by_file.items(),
                    key=lambda x: len(x[1]),
                    reverse=True
                )[:20]  # Top 20 files
            },
            "vulnerabilities_by_category": {
                category: {
                    "count": len(cat_vulns),
                    "severity_breakdown": Counter([v.get("severity") for v in cat_vulns]),
                    "examples": [
                        {
                            "file": v.get("file_path"),
                            "line": v.get("line_start"),
                            "severity": v.get("severity")
                        }
                        for v in cat_vulns[:3]
                    ]
                }
                for category, cat_vulns in sorted(
                    by_category.items(),
                    key=lambda x: len(x[1]),
                    reverse=True
                )[:10]
            },
            "priority_fixes": self._generate_priority_fixes(vulns),
            "quick_wins": self._identify_quick_wins(vulns)
        }

        return report

    async def generate_security_team_report(
        self,
        repo_id: str,
        scan_id: Optional[str] = None
    ) -> Dict:
        """
        Generate security team report

        Detailed security analysis including:
        - Attack vectors
        - Exploitability
        - Risk scores
        - Remediation guidance
        """
        # Get scan
        if scan_id:
            scan = await self.db.scans.find_one({"id": scan_id}, {"_id": 0})
        else:
            scan = await self.db.scans.find_one(
                {"repo_id": repo_id},
                {"_id": 0},
                sort=[("created_at", -1)]
            )

        # Get vulnerabilities
        vulns = await self.db.vulnerabilities.find(
            {"scan_id": scan["id"]},
            {"_id": 0}
        ).to_list(10000)

        # Attack surface analysis
        attack_surface = self._analyze_attack_surface(vulns)

        # Exploitability analysis
        exploitability = self._analyze_exploitability(vulns)

        # Risk distribution
        risk_distribution = self._analyze_risk_distribution(vulns)

        # CWE analysis
        cwe_analysis = self._analyze_cwes(vulns)

        # OWASP Top 10 mapping
        owasp_mapping = self._analyze_owasp_mapping(vulns)

        report = {
            "report_type": "Security Team Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan["id"],
            "attack_surface_analysis": attack_surface,
            "exploitability_assessment": exploitability,
            "risk_distribution": risk_distribution,
            "cwe_analysis": cwe_analysis,
            "owasp_top10_mapping": owasp_mapping,
            "critical_vulnerabilities": [
                {
                    "id": v.get("id"),
                    "title": v.get("title"),
                    "file": v.get("file_path"),
                    "line": v.get("line_start"),
                    "severity": v.get("severity"),
                    "risk_score": v.get("risk_score", 0),
                    "cwe": v.get("cwe"),
                    "cvss_score": v.get("cvss_score"),
                    "exploitability": v.get("exploitability", {}),
                    "business_impact": v.get("business_impact", {}),
                    "verified": v.get("verified", False)
                }
                for v in sorted(vulns, key=lambda x: x.get("risk_score", 0), reverse=True)[:20]
            ],
            "remediation_roadmap": self._generate_remediation_roadmap(vulns),
            "security_metrics": self._calculate_security_metrics(scan, vulns)
        }

        return report

    async def _calculate_trends(self, repo_id: str, current_scan_id: str) -> Dict:
        """Calculate vulnerability trends compared to previous scans"""
        # Get previous scan
        previous_scan = await self.db.scans.find_one(
            {
                "repo_id": repo_id,
                "id": {"$ne": current_scan_id}
            },
            {"_id": 0},
            sort=[("created_at", -1)]
        )

        if not previous_scan:
            return {
                "status": "first_scan",
                "message": "This is the first scan, no trends available"
            }

        # Get current vulnerabilities count
        current_vulns = await self.db.vulnerabilities.count_documents(
            {"scan_id": current_scan_id}
        )

        # Get previous vulnerabilities count
        previous_vulns = await self.db.vulnerabilities.count_documents(
            {"scan_id": previous_scan["id"]}
        )

        # Calculate change
        change = current_vulns - previous_vulns
        change_percent = (change / previous_vulns * 100) if previous_vulns > 0 else 0

        if change > 0:
            trend = "worsening"
        elif change < 0:
            trend = "improving"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "current_count": current_vulns,
            "previous_count": previous_vulns,
            "change": change,
            "change_percent": round(change_percent, 2),
            "previous_scan_date": previous_scan.get("completed_at")
        }

    def _assess_business_impact_summary(self, vulns: List[Dict]) -> Dict:
        """Assess overall business impact"""
        impacts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        affected_areas = set()

        for vuln in vulns:
            impact = vuln.get("business_impact", {})
            level = impact.get("level", "medium")
            impacts[level] = impacts.get(level, 0) + 1

            for area in impact.get("affected_areas", []):
                affected_areas.add(area)

        return {
            "total_affected_areas": len(affected_areas),
            "affected_areas": list(affected_areas),
            "impact_distribution": impacts,
            "highest_impact": max(impacts.items(), key=lambda x: x[1])[0] if impacts else "unknown"
        }

    def _assess_compliance_status(self, vulns: List[Dict]) -> Dict:
        """Assess compliance status based on vulnerabilities"""
        compliance = {
            "owasp_top10": {
                "covered": set(),
                "violations": 0
            },
            "pci_dss": {
                "status": "compliant",
                "violations": []
            },
            "gdpr": {
                "status": "compliant",
                "violations": []
            }
        }

        for vuln in vulns:
            # OWASP Top 10
            owasp_cat = vuln.get("owasp_category")
            if owasp_cat:
                compliance["owasp_top10"]["covered"].add(owasp_cat)
                compliance["owasp_top10"]["violations"] += 1

            # PCI DSS (payment-related vulnerabilities)
            if any(keyword in vuln.get("file_path", "").lower() for keyword in ["payment", "card", "billing"]):
                if vuln.get("severity") in ["critical", "high"]:
                    compliance["pci_dss"]["status"] = "non-compliant"
                    compliance["pci_dss"]["violations"].append(vuln.get("title"))

            # GDPR (data protection issues)
            if any(keyword in vuln.get("category", "").lower() for keyword in ["secret", "password", "credential"]):
                if vuln.get("severity") in ["critical", "high"]:
                    compliance["gdpr"]["status"] = "non-compliant"
                    compliance["gdpr"]["violations"].append(vuln.get("title"))

        compliance["owasp_top10"]["covered"] = list(compliance["owasp_top10"]["covered"])

        return compliance

    def _generate_executive_recommendations(
        self,
        critical_count: int,
        high_count: int,
        security_score: int,
        business_impact: Dict
    ) -> List[str]:
        """Generate executive-level recommendations"""
        recommendations = []

        if critical_count > 0:
            recommendations.append(
                f"Immediate action required: {critical_count} critical vulnerabilities must be addressed within 24-48 hours"
            )

        if high_count > 5:
            recommendations.append(
                f"Priority remediation needed: {high_count} high-severity issues should be resolved within 1 week"
            )

        if security_score < 50:
            recommendations.append(
                "Security posture is below acceptable standards. Recommend comprehensive security audit and remediation plan"
            )

        if business_impact.get("highest_impact") == "critical":
            recommendations.append(
                "Critical business systems are affected. Consider implementing additional monitoring and security controls"
            )

        if not recommendations:
            recommendations.append(
                "Security posture is good. Continue regular scanning and maintain current security practices"
            )

        return recommendations

    def _generate_priority_fixes(self, vulns: List[Dict]) -> List[Dict]:
        """Generate prioritized list of fixes"""
        # Sort by risk score
        sorted_vulns = sorted(vulns, key=lambda x: x.get("risk_score", 0), reverse=True)

        priority_fixes = []
        for vuln in sorted_vulns[:10]:  # Top 10
            priority_fixes.append({
                "priority": len(priority_fixes) + 1,
                "file": vuln.get("file_path"),
                "line": vuln.get("line_start"),
                "issue": vuln.get("title"),
                "severity": vuln.get("severity"),
                "risk_score": vuln.get("risk_score", 0),
                "estimated_effort": self._estimate_fix_effort(vuln),
                "impact": vuln.get("business_impact", {}).get("level", "medium")
            })

        return priority_fixes

    def _identify_quick_wins(self, vulns: List[Dict]) -> List[Dict]:
        """Identify easy-to-fix vulnerabilities with high impact"""
        quick_wins = []

        for vuln in vulns:
            # Quick wins: high/critical severity but simple category
            if vuln.get("severity") in ["high", "critical"]:
                category = vuln.get("category", "").lower()

                # Easy fixes
                if any(keyword in category for keyword in ["hardcoded", "secret", "password", "weak"]):
                    quick_wins.append({
                        "file": vuln.get("file_path"),
                        "line": vuln.get("line_start"),
                        "issue": vuln.get("title"),
                        "fix": "Remove hardcoded credentials and use environment variables",
                        "severity": vuln.get("severity")
                    })

        return quick_wins[:5]  # Top 5 quick wins

    def _estimate_fix_effort(self, vuln: Dict) -> str:
        """Estimate effort required to fix vulnerability"""
        category = vuln.get("category", "").lower()

        if any(keyword in category for keyword in ["hardcoded", "secret", "config"]):
            return "Low (1-2 hours)"
        elif any(keyword in category for keyword in ["dependency", "package"]):
            return "Low (update package)"
        elif any(keyword in category for keyword in ["injection", "xss"]):
            return "Medium (4-8 hours)"
        elif any(keyword in category for keyword in ["architecture", "design"]):
            return "High (1-3 days)"
        else:
            return "Medium (4-8 hours)"

    def _analyze_attack_surface(self, vulns: List[Dict]) -> Dict:
        """Analyze exposed attack surface"""
        attack_vectors = Counter([
            v.get("exploitability", {}).get("attack_vector", "unknown")
            for v in vulns
        ])

        return {
            "total_exposed_components": len(vulns),
            "attack_vectors": dict(attack_vectors),
            "remote_exploitable": attack_vectors.get("remote", 0),
            "network_exploitable": attack_vectors.get("network", 0) + attack_vectors.get("remote", 0),
            "requires_authentication": attack_vectors.get("authenticated", 0),
            "local_only": attack_vectors.get("local", 0)
        }

    def _analyze_exploitability(self, vulns: List[Dict]) -> Dict:
        """Analyze exploitability of vulnerabilities"""
        exploitability_levels = Counter([
            v.get("exploitability", {}).get("level", "medium")
            for v in vulns
        ])

        return {
            "distribution": dict(exploitability_levels),
            "critical": exploitability_levels.get("critical", 0),
            "high": exploitability_levels.get("high", 0),
            "medium": exploitability_levels.get("medium", 0),
            "low": exploitability_levels.get("low", 0),
            "percentage_easily_exploitable": round(
                (exploitability_levels.get("critical", 0) + exploitability_levels.get("high", 0)) / len(vulns) * 100, 2
            ) if vulns else 0
        }

    def _analyze_risk_distribution(self, vulns: List[Dict]) -> Dict:
        """Analyze risk score distribution"""
        risk_scores = [v.get("risk_score", 0) for v in vulns]

        if not risk_scores:
            return {}

        return {
            "average_risk_score": round(sum(risk_scores) / len(risk_scores), 2),
            "max_risk_score": max(risk_scores),
            "min_risk_score": min(risk_scores),
            "high_risk_count": sum(1 for score in risk_scores if score >= 80),
            "medium_risk_count": sum(1 for score in risk_scores if 40 <= score < 80),
            "low_risk_count": sum(1 for score in risk_scores if score < 40)
        }

    def _analyze_cwes(self, vulns: List[Dict]) -> Dict:
        """Analyze CWE distribution"""
        cwes = [v.get("cwe") for v in vulns if v.get("cwe")]
        cwe_counts = Counter(cwes)

        return {
            "total_unique_cwes": len(cwe_counts),
            "top_cwes": [
                {"cwe": cwe, "count": count}
                for cwe, count in cwe_counts.most_common(10)
            ]
        }

    def _analyze_owasp_mapping(self, vulns: List[Dict]) -> Dict:
        """Analyze OWASP Top 10 mapping"""
        owasp_cats = [v.get("owasp_category") for v in vulns if v.get("owasp_category")]
        owasp_counts = Counter(owasp_cats)

        return {
            "total_owasp_categories": len(owasp_counts),
            "distribution": [
                {"category": cat, "count": count}
                for cat, count in owasp_counts.most_common()
            ]
        }

    def _generate_remediation_roadmap(self, vulns: List[Dict]) -> Dict:
        """Generate remediation roadmap"""
        # Sort by risk score
        sorted_vulns = sorted(vulns, key=lambda x: x.get("risk_score", 0), reverse=True)

        roadmap = {
            "phase1_immediate": {
                "timeframe": "24-48 hours",
                "vulnerabilities": [
                    {
                        "file": v.get("file_path"),
                        "issue": v.get("title"),
                        "severity": v.get("severity")
                    }
                    for v in sorted_vulns if v.get("severity") == "critical"
                ][:5]
            },
            "phase2_urgent": {
                "timeframe": "1 week",
                "vulnerabilities": [
                    {
                        "file": v.get("file_path"),
                        "issue": v.get("title"),
                        "severity": v.get("severity")
                    }
                    for v in sorted_vulns if v.get("severity") == "high"
                ][:10]
            },
            "phase3_important": {
                "timeframe": "2-4 weeks",
                "vulnerabilities": [
                    {
                        "file": v.get("file_path"),
                        "issue": v.get("title"),
                        "severity": v.get("severity")
                    }
                    for v in sorted_vulns if v.get("severity") == "medium"
                ][:15]
            }
        }

        return roadmap

    def _calculate_security_metrics(self, scan: Dict, vulns: List[Dict]) -> Dict:
        """Calculate security metrics"""
        return {
            "total_scanned_files": scan.get("total_files", 0),
            "total_vulnerabilities": len(vulns),
            "vulnerabilities_per_file": round(len(vulns) / scan.get("total_files", 1), 2),
            "security_score": scan.get("security_score", 0),
            "scan_duration": "N/A",  # Could calculate if we store start/end times
            "scanners_executed": len(scan.get("scan_results", {}))
        }
