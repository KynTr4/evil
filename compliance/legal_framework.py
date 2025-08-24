#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compliance & Legal Framework for Professional Cybersecurity Services
Ensures legal compliance and proper documentation for security testing

Covers regulations, contracts, consent forms, and audit trails
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime, date
from enum import Enum
import json
import hashlib
from pathlib import Path

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    NIST_CSF = "nist_csf"  # NIST Cybersecurity Framework
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    SOX = "sox"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    OWASP = "owasp"

class TestingScope(Enum):
    """Testing scope definitions"""
    NETWORK_INTERNAL = "network_internal"
    NETWORK_EXTERNAL = "network_external"
    WIRELESS_INFRASTRUCTURE = "wireless_infrastructure"
    WEB_APPLICATIONS = "web_applications"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL_SECURITY = "physical_security"

@dataclass
class LegalConsent:
    """Legal consent and authorization documentation"""
    client_company: str
    authorized_representative: str
    title: str
    email: str
    phone: str
    consent_date: date
    scope_of_testing: List[TestingScope]
    ip_ranges: List[str]
    excluded_systems: List[str]
    testing_window: Dict[str, str]  # start_time, end_time
    emergency_contact: str
    notification_requirements: str
    data_handling_agreement: bool
    signed_contract: bool
    consent_hash: str = ""
    
    def __post_init__(self):
        # Generate consent hash for integrity verification
        consent_data = f"{self.client_company}{self.authorized_representative}{self.consent_date}{self.scope_of_testing}"
        self.consent_hash = hashlib.sha256(consent_data.encode()).hexdigest()

@dataclass
class ComplianceRequirement:
    """Individual compliance requirement"""
    framework: ComplianceFramework
    requirement_id: str
    title: str
    description: str
    testing_procedures: List[str]
    evidence_required: List[str]
    severity: str  # mandatory, recommended, optional

@dataclass
class AuditTrail:
    """Audit trail entry for compliance tracking"""
    timestamp: datetime
    user: str
    action: str
    target: str
    details: Dict
    ip_address: str
    session_id: str

class ComplianceManager:
    """Manages compliance requirements and legal documentation"""
    
    def __init__(self):
        self.audit_trail = []
        self.compliance_db = self._load_compliance_requirements()
    
    def _load_compliance_requirements(self) -> Dict[ComplianceFramework, List[ComplianceRequirement]]:
        """Load compliance requirements database"""
        
        nist_requirements = [
            ComplianceRequirement(
                framework=ComplianceFramework.NIST_CSF,
                requirement_id="PR.AC-1",
                title="Identity and Access Management",
                description="Identities and credentials are issued, managed, verified, revoked, and audited",
                testing_procedures=[
                    "Test wireless authentication mechanisms",
                    "Verify access control effectiveness",
                    "Test for unauthorized access paths"
                ],
                evidence_required=[
                    "Authentication test results",
                    "Access control bypass evidence",
                    "Credential harvesting logs"
                ],
                severity="mandatory"
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.NIST_CSF,
                requirement_id="PR.DS-1",
                title="Data Security",
                description="Data-at-rest is protected",
                testing_procedures=[
                    "Test data encryption on wireless networks",
                    "Verify data transmission security",
                    "Test for data leakage"
                ],
                evidence_required=[
                    "Encryption strength analysis",
                    "Data interception logs",
                    "Transmission security assessment"
                ],
                severity="mandatory"
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.NIST_CSF,
                requirement_id="DE.CM-1",
                title="Security Monitoring",
                description="The network is monitored to detect potential cybersecurity events",
                testing_procedures=[
                    "Test detection of rogue access points",
                    "Verify intrusion detection capabilities",
                    "Test alerting mechanisms"
                ],
                evidence_required=[
                    "Detection system logs",
                    "Alert generation records",
                    "Response time measurements"
                ],
                severity="mandatory"
            )
        ]
        
        iso27001_requirements = [
            ComplianceRequirement(
                framework=ComplianceFramework.ISO27001,
                requirement_id="A.11.2.6",
                title="Secure disposal or reuse of equipment",
                description="All items of equipment containing storage media shall be verified",
                testing_procedures=[
                    "Test for data remnants on wireless devices",
                    "Verify secure configuration procedures"
                ],
                evidence_required=[
                    "Device configuration analysis",
                    "Data recovery attempts"
                ],
                severity="mandatory"
            )
        ]
        
        return {
            ComplianceFramework.NIST_CSF: nist_requirements,
            ComplianceFramework.ISO27001: iso27001_requirements
        }
    
    def generate_consent_form(self, client_info: Dict, scope: List[TestingScope]) -> str:
        """Generate legal consent form"""
        
        template = f"""
CYBERSECURITY TESTING AUTHORIZATION AND CONSENT FORM

CLIENT INFORMATION:
Company: {client_info['company_name']}
Authorized Representative: {client_info['contact_person']}
Title: {client_info['title']}
Email: {client_info['email']}
Phone: {client_info['phone']}

SCOPE OF TESTING:
The authorized cybersecurity testing will include:
{chr(10).join(f"• {scope_item.value.replace('_', ' ').title()}" for scope_item in scope)}

TESTING PARAMETERS:
IP Ranges: {', '.join(client_info.get('ip_ranges', ['To be defined']))}
Excluded Systems: {', '.join(client_info.get('excluded_systems', ['None specified']))}
Testing Window: {client_info.get('testing_window', 'To be agreed upon')}

LEGAL AUTHORIZATION:
I, {client_info['contact_person']}, as an authorized representative of {client_info['company_name']}, 
hereby grant permission to conduct cybersecurity testing as outlined above. I understand that:

1. Testing may temporarily disrupt normal business operations
2. Testing will simulate real-world attack scenarios
3. All findings will be documented and reported confidentially
4. Testing personnel will follow industry best practices
5. Emergency contact procedures are established

COMPLIANCE REQUIREMENTS:
This testing is conducted in accordance with:
• NIST Cybersecurity Framework
• ISO 27001 standards
• OWASP testing methodology
• Applicable data protection regulations

DATA HANDLING:
• All captured data will be handled according to our data protection policy
• Client data will not be retained beyond the assessment period
• All evidence will be securely destroyed after final report delivery
• Access to client systems is limited to authorized testing personnel only

EMERGENCY PROCEDURES:
Emergency Contact: {client_info.get('emergency_contact', 'To be provided')}
If testing causes unexpected issues, contact immediately: [Testing Team Contact]

SIGNATURES:
Client Representative: _________________________ Date: _________
{client_info['contact_person']}, {client_info['title']}

Testing Provider: _________________________ Date: _________
[Consultant Name], Lead Security Consultant

This form must be signed before any testing activities commence.
        """
        
        return template
    
    def verify_consent(self, consent: LegalConsent) -> Dict[str, bool]:
        """Verify legal consent completeness"""
        
        checks = {
            "authorized_representative_provided": bool(consent.authorized_representative),
            "contact_information_complete": bool(consent.email and consent.phone),
            "scope_defined": len(consent.scope_of_testing) > 0,
            "testing_window_specified": bool(consent.testing_window),
            "emergency_contact_provided": bool(consent.emergency_contact),
            "data_handling_agreed": consent.data_handling_agreement,
            "contract_signed": consent.signed_contract,
            "consent_hash_valid": len(consent.consent_hash) == 64
        }
        
        return checks
    
    def generate_compliance_checklist(self, frameworks: List[ComplianceFramework], 
                                    testing_scope: List[TestingScope]) -> Dict:
        """Generate compliance testing checklist"""
        
        checklist = {
            "frameworks": [f.value for f in frameworks],
            "testing_scope": [s.value for s in testing_scope],
            "requirements": [],
            "generated_date": datetime.now().isoformat()
        }
        
        for framework in frameworks:
            if framework in self.compliance_db:
                for requirement in self.compliance_db[framework]:
                    checklist["requirements"].append({
                        "framework": requirement.framework.value,
                        "id": requirement.requirement_id,
                        "title": requirement.title,
                        "description": requirement.description,
                        "procedures": requirement.testing_procedures,
                        "evidence": requirement.evidence_required,
                        "severity": requirement.severity,
                        "status": "pending"  # pending, completed, not_applicable
                    })
        
        return checklist
    
    def log_audit_event(self, user: str, action: str, target: str, 
                       details: Dict, ip_address: str, session_id: str):
        """Log audit trail event"""
        
        event = AuditTrail(
            timestamp=datetime.now(),
            user=user,
            action=action,
            target=target,
            details=details,
            ip_address=ip_address,
            session_id=session_id
        )
        
        self.audit_trail.append(event)
    
    def generate_legal_report(self, consent: LegalConsent, 
                            compliance_results: Dict) -> str:
        """Generate legal compliance report"""
        
        template = f"""
LEGAL COMPLIANCE REPORT
Cybersecurity Assessment

EXECUTIVE SUMMARY:
Assessment Date: {datetime.now().strftime('%Y-%m-%d')}
Client: {consent.client_company}
Authorized by: {consent.authorized_representative}

LEGAL AUTHORIZATION:
✓ Written consent obtained on {consent.consent_date}
✓ Authorized representative: {consent.authorized_representative} ({consent.title})
✓ Testing scope clearly defined
✓ Emergency procedures established
✓ Data handling agreement in place

COMPLIANCE FRAMEWORKS:
{chr(10).join(f"• {result['framework'].upper()}" for result in compliance_results.get('frameworks_tested', []))}

SCOPE VERIFICATION:
Testing was limited to authorized scope:
{chr(10).join(f"• {scope.value.replace('_', ' ').title()}" for scope in consent.scope_of_testing)}

Excluded systems were respected:
{chr(10).join(f"• {system}" for system in consent.excluded_systems)}

DATA PROTECTION COMPLIANCE:
• No unauthorized data access occurred
• All captured data handled according to agreement
• Data retention limits observed
• Secure disposal procedures followed

AUDIT TRAIL:
{len(self.audit_trail)} audit events recorded during assessment
All testing activities logged and traceable

LEGAL ATTESTATION:
This assessment was conducted in full compliance with:
• Signed testing authorization
• Applicable legal requirements
• Industry ethical standards
• Client-specified constraints

Report prepared by: [Consultant Name]
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        return template
    
    def export_audit_trail(self, start_date: date, end_date: date) -> List[Dict]:
        """Export audit trail for specified period"""
        
        filtered_events = [
            {
                "timestamp": event.timestamp.isoformat(),
                "user": event.user,
                "action": event.action,
                "target": event.target,
                "details": event.details,
                "ip_address": event.ip_address,
                "session_id": event.session_id
            }
            for event in self.audit_trail
            if start_date <= event.timestamp.date() <= end_date
        ]
        
        return filtered_events

class ContractGenerator:
    """Generates professional service contracts"""
    
    @staticmethod
    def generate_service_agreement(client_info: Dict, services: List[str], 
                                 pricing: Dict) -> str:
        """Generate professional services agreement"""
        
        template = f"""
CYBERSECURITY PROFESSIONAL SERVICES AGREEMENT

PARTIES:
Service Provider: [Your Company Name]
Address: [Your Address]
Contact: [Your Contact Information]

Client: {client_info['company_name']}
Address: {client_info.get('address', '[Client Address]')}
Contact: {client_info['contact_person']} ({client_info['email']})

SERVICES:
The following cybersecurity services will be provided:
{chr(10).join(f"• {service}" for service in services)}

PRICING:
{chr(10).join(f"• {item}: ${amount}" for item, amount in pricing.items())}

TERMS AND CONDITIONS:

1. SCOPE OF WORK
   Services will be performed according to industry best practices and applicable standards.

2. DELIVERABLES
   - Executive summary report
   - Detailed technical findings
   - Remediation recommendations
   - Evidence documentation

3. TIMELINE
   Services to be completed within agreed timeframe.

4. CONFIDENTIALITY
   All client information will be treated as strictly confidential.

5. LIABILITY
   Liability is limited to the amount paid for services.

6. DATA PROTECTION
   All testing will comply with applicable data protection regulations.

SIGNATURES:
Client: _________________________ Date: _________
Service Provider: _________________________ Date: _________
        """
        
        return template

def example_compliance_workflow():
    """Example compliance workflow for cybersecurity services"""
    
    # Initialize compliance manager
    cm = ComplianceManager()
    
    # Create legal consent
    consent = LegalConsent(
        client_company="TechCorp Industries",
        authorized_representative="John Smith",
        title="Chief Information Security Officer",
        email="john.smith@techcorp.com",
        phone="+1-555-0123",
        consent_date=date.today(),
        scope_of_testing=[TestingScope.WIRELESS_INFRASTRUCTURE, TestingScope.NETWORK_INTERNAL],
        ip_ranges=["192.168.1.0/24", "10.0.0.0/8"],
        excluded_systems=["Production Database Server", "Executive Email Server"],
        testing_window={"start": "2024-08-25 09:00", "end": "2024-08-25 17:00"},
        emergency_contact="Alice Johnson (+1-555-0199)",
        notification_requirements="Email notification for any critical findings",
        data_handling_agreement=True,
        signed_contract=True
    )
    
    # Verify consent
    consent_check = cm.verify_consent(consent)
    print("Consent verification:", consent_check)
    
    # Generate consent form
    client_info = {
        "company_name": consent.client_company,
        "contact_person": consent.authorized_representative,
        "title": consent.title,
        "email": consent.email,
        "phone": consent.phone,
        "ip_ranges": consent.ip_ranges,
        "excluded_systems": consent.excluded_systems,
        "testing_window": consent.testing_window,
        "emergency_contact": consent.emergency_contact
    }
    
    consent_form = cm.generate_consent_form(client_info, consent.scope_of_testing)
    print("Consent form generated")
    
    # Generate compliance checklist
    checklist = cm.generate_compliance_checklist(
        [ComplianceFramework.NIST_CSF, ComplianceFramework.ISO27001],
        consent.scope_of_testing
    )
    print(f"Compliance checklist: {len(checklist['requirements'])} requirements")
    
    # Log audit events
    cm.log_audit_event(
        user="alice.consultant",
        action="start_assessment",
        target=consent.client_company,
        details={"scope": [s.value for s in consent.scope_of_testing]},
        ip_address="10.0.1.100",
        session_id="sess_123456"
    )
    
    # Generate legal report
    compliance_results = {"frameworks_tested": [{"framework": "nist_csf"}]}
    legal_report = cm.generate_legal_report(consent, compliance_results)
    print("Legal compliance report generated")

if __name__ == "__main__":
    example_compliance_workflow()