#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Professional Security Assessment Report Generator
For Enterprise Cybersecurity Testing

Generates compliance-ready reports for client deliverables
"""

import json
import datetime
from dataclasses import dataclass
from typing import List, Dict, Optional
import jinja2
import matplotlib.pyplot as plt
import pandas as pd
from pathlib import Path

@dataclass
class VulnerabilityFinding:
    """Represents a security vulnerability finding"""
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low
    cvss_score: float
    description: str
    impact: str
    recommendation: str
    evidence: List[str]
    affected_assets: List[str]
    
@dataclass
class ClientInfo:
    """Client organization information"""
    company_name: str
    contact_person: str
    email: str
    assessment_date: datetime.date
    scope: str
    methodology: str

class SecurityReportGenerator:
    """Professional security assessment report generator"""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.output_dir = Path(__file__).parent / "output"
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir)
        )
    
    def generate_executive_summary(self, findings: List[VulnerabilityFinding], client: ClientInfo) -> str:
        """Generate executive summary for C-level stakeholders"""
        
        # Risk metrics
        critical_count = len([f for f in findings if f.severity == "Critical"])
        high_count = len([f for f in findings if f.severity == "High"])
        medium_count = len([f for f in findings if f.severity == "Medium"])
        low_count = len([f for f in findings if f.severity == "Low"])
        
        # Overall risk assessment
        if critical_count > 0:
            overall_risk = "Critical"
        elif high_count > 0:
            overall_risk = "High"
        elif medium_count > 0:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"
        
        summary = f"""
# Executive Summary - Wireless Security Assessment

**Client:** {client.company_name}
**Assessment Date:** {client.assessment_date}
**Overall Risk Level:** {overall_risk}

## Key Findings

- **Critical Issues:** {critical_count}
- **High Risk Issues:** {high_count}
- **Medium Risk Issues:** {medium_count}
- **Low Risk Issues:** {low_count}

## Business Impact

The wireless security assessment revealed {len(findings)} security findings that could potentially impact business operations, data confidentiality, and regulatory compliance.

## Immediate Actions Required

1. Address all Critical and High severity findings within 30 days
2. Implement network segmentation for wireless networks
3. Deploy enterprise-grade wireless security monitoring
4. Conduct employee security awareness training

## Compliance Status

Assessment methodology follows NIST Cybersecurity Framework and OWASP standards.
        """
        
        return summary
    
    def generate_technical_report(self, findings: List[VulnerabilityFinding], 
                                client: ClientInfo, test_results: Dict) -> str:
        """Generate detailed technical report"""
        
        template = self.jinja_env.get_template("technical_report.html")
        
        return template.render(
            client=client,
            findings=findings,
            test_results=test_results,
            generation_date=datetime.datetime.now()
        )
    
    def create_risk_charts(self, findings: List[VulnerabilityFinding]) -> str:
        """Create risk visualization charts"""
        
        # Severity distribution
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        # Create pie chart
        plt.figure(figsize=(10, 6))
        plt.subplot(1, 2, 1)
        plt.pie(severity_counts.values(), labels=severity_counts.keys(), autopct='%1.1f%%')
        plt.title('Vulnerability Distribution by Severity')
        
        # CVSS Score histogram
        plt.subplot(1, 2, 2)
        cvss_scores = [f.cvss_score for f in findings]
        plt.hist(cvss_scores, bins=10, alpha=0.7)
        plt.title('CVSS Score Distribution')
        plt.xlabel('CVSS Score')
        plt.ylabel('Count')
        
        chart_path = self.output_dir / f"risk_analysis_{datetime.date.today()}.png"
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def generate_compliance_report(self, findings: List[VulnerabilityFinding], 
                                 client: ClientInfo, framework: str = "NIST") -> str:
        """Generate compliance-specific report (NIST, ISO27001, etc.)"""
        
        if framework == "NIST":
            return self._generate_nist_report(findings, client)
        elif framework == "ISO27001":
            return self._generate_iso27001_report(findings, client)
        else:
            raise ValueError(f"Unsupported framework: {framework}")
    
    def _generate_nist_report(self, findings: List[VulnerabilityFinding], client: ClientInfo) -> str:
        """Generate NIST Cybersecurity Framework aligned report"""
        
        nist_mapping = {
            "Identify": [],
            "Protect": [],
            "Detect": [],
            "Respond": [],
            "Recover": []
        }
        
        # Map findings to NIST categories
        for finding in findings:
            if "authentication" in finding.title.lower():
                nist_mapping["Protect"].append(finding)
            elif "monitoring" in finding.title.lower():
                nist_mapping["Detect"].append(finding)
            elif "encryption" in finding.title.lower():
                nist_mapping["Protect"].append(finding)
            else:
                nist_mapping["Identify"].append(finding)
        
        report = f"""
# NIST Cybersecurity Framework Compliance Report

**Client:** {client.company_name}
**Assessment Date:** {client.assessment_date}

## NIST Framework Alignment

"""
        
        for category, category_findings in nist_mapping.items():
            report += f"\n### {category} ({len(category_findings)} findings)\n"
            for finding in category_findings:
                report += f"- **{finding.title}** (Severity: {finding.severity})\n"
        
        return report

def example_usage():
    """Example usage for generating professional reports"""
    
    # Sample client information
    client = ClientInfo(
        company_name="TechCorp Inc.",
        contact_person="John Smith, CISO",
        email="john.smith@techcorp.com",
        assessment_date=datetime.date.today(),
        scope="Wireless Network Security Assessment",
        methodology="Evil Twin Attack Simulation & Network Penetration Testing"
    )
    
    # Sample findings
    findings = [
        VulnerabilityFinding(
            id="ETA-001",
            title="Unencrypted Wireless Network Detected",
            severity="Critical",
            cvss_score=9.1,
            description="Open wireless network allows unauthorized access",
            impact="Complete network compromise, data exfiltration possible",
            recommendation="Implement WPA3-Enterprise with certificate authentication",
            evidence=["network_scan_results.json", "packet_capture.pcap"],
            affected_assets=["Guest WiFi Network", "Employee Access Points"]
        ),
        VulnerabilityFinding(
            id="ETA-002", 
            title="Weak WiFi Password Policy",
            severity="High",
            cvss_score=7.3,
            description="WiFi passwords do not meet complexity requirements",
            impact="Brute force attacks may succeed",
            recommendation="Enforce minimum 15-character passwords with complexity",
            evidence=["password_audit.txt"],
            affected_assets=["Corporate WiFi"]
        )
    ]
    
    # Generate reports
    generator = SecurityReportGenerator()
    
    # Executive summary
    exec_summary = generator.generate_executive_summary(findings, client)
    print("Executive Summary Generated")
    
    # Risk charts
    chart_path = generator.create_risk_charts(findings)
    print(f"Risk charts saved to: {chart_path}")
    
    # Compliance report
    nist_report = generator.generate_compliance_report(findings, client, "NIST")
    print("NIST Compliance Report Generated")

if __name__ == "__main__":
    example_usage()