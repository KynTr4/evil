#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Professional Client Management & Project Tracking System
For Cybersecurity Service Providers

Manages multiple client projects, assessments, and deliverables
"""

import sqlite3
import json
import uuid
from datetime import datetime, date, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any
from enum import Enum
from pathlib import Path
import hashlib

class ProjectStatus(Enum):
    """Project status enumeration"""
    PLANNING = "planning"
    IN_PROGRESS = "in_progress"
    TESTING = "testing"
    REPORTING = "reporting"
    DELIVERED = "delivered"
    CLOSED = "closed"

class AssessmentType(Enum):
    """Assessment type enumeration"""
    WIRELESS_PENTEST = "wireless_pentest"
    NETWORK_SECURITY = "network_security"
    WEB_APPLICATION = "web_application"
    SOCIAL_ENGINEERING = "social_engineering"
    COMPLIANCE_AUDIT = "compliance_audit"
    RED_TEAM = "red_team"

@dataclass
class Client:
    """Client organization information"""
    id: str
    company_name: str
    industry: str
    contact_person: str
    email: str
    phone: str
    address: str
    contract_start: date
    contract_end: date
    billing_rate: float
    notes: str = ""
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass 
class Project:
    """Security assessment project"""
    id: str
    client_id: str
    name: str
    description: str
    assessment_type: AssessmentType
    status: ProjectStatus
    start_date: date
    end_date: date
    budget: float
    scope: str
    methodology: str
    lead_consultant: str
    team_members: List[str]
    deliverables: List[str]
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()

@dataclass
class Assessment:
    """Individual security assessment within a project"""
    id: str
    project_id: str
    name: str
    target_systems: List[str]
    test_date: date
    duration_hours: float
    findings_count: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    report_path: str
    evidence_path: str
    notes: str = ""
    created_at: datetime = None

@dataclass
class Finding:
    """Security finding/vulnerability"""
    id: str
    assessment_id: str
    title: str
    severity: str
    cvss_score: float
    description: str
    impact: str
    recommendation: str
    status: str  # open, mitigated, false_positive, accepted
    evidence_files: List[str]
    affected_systems: List[str]
    discovered_date: date
    remediation_date: Optional[date] = None
    created_at: datetime = None

class ClientManagementSystem:
    """Professional client and project management system"""
    
    def __init__(self, db_path: str = "cybersec_crm.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id TEXT PRIMARY KEY,
                    company_name TEXT NOT NULL,
                    industry TEXT,
                    contact_person TEXT,
                    email TEXT,
                    phone TEXT,
                    address TEXT,
                    contract_start DATE,
                    contract_end DATE,
                    billing_rate REAL,
                    notes TEXT,
                    created_at TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    client_id TEXT,
                    name TEXT NOT NULL,
                    description TEXT,
                    assessment_type TEXT,
                    status TEXT,
                    start_date DATE,
                    end_date DATE,
                    budget REAL,
                    scope TEXT,
                    methodology TEXT,
                    lead_consultant TEXT,
                    team_members TEXT,  -- JSON array
                    deliverables TEXT,  -- JSON array
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients (id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    id TEXT PRIMARY KEY,
                    project_id TEXT,
                    name TEXT NOT NULL,
                    target_systems TEXT,  -- JSON array
                    test_date DATE,
                    duration_hours REAL,
                    findings_count INTEGER,
                    critical_findings INTEGER,
                    high_findings INTEGER,
                    medium_findings INTEGER,
                    low_findings INTEGER,
                    report_path TEXT,
                    evidence_path TEXT,
                    notes TEXT,
                    created_at TIMESTAMP,
                    FOREIGN KEY (project_id) REFERENCES projects (id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    assessment_id TEXT,
                    title TEXT NOT NULL,
                    severity TEXT,
                    cvss_score REAL,
                    description TEXT,
                    impact TEXT,
                    recommendation TEXT,
                    status TEXT,
                    evidence_files TEXT,  -- JSON array
                    affected_systems TEXT,  -- JSON array
                    discovered_date DATE,
                    remediation_date DATE,
                    created_at TIMESTAMP,
                    FOREIGN KEY (assessment_id) REFERENCES assessments (id)
                )
            """)
            
            conn.commit()
    
    # CLIENT MANAGEMENT
    def create_client(self, client_data: Dict) -> str:
        """Create new client"""
        client_id = str(uuid.uuid4())
        
        client = Client(
            id=client_id,
            **client_data
        )
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO clients (id, company_name, industry, contact_person, 
                                   email, phone, address, contract_start, contract_end,
                                   billing_rate, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                client.id, client.company_name, client.industry, client.contact_person,
                client.email, client.phone, client.address, client.contract_start,
                client.contract_end, client.billing_rate, client.notes, client.created_at
            ))
            conn.commit()
        
        return client_id
    
    def get_client(self, client_id: str) -> Optional[Client]:
        """Get client by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,))
            row = cursor.fetchone()
            
            if row:
                data = dict(row)
                return Client(**data)
        return None
    
    def list_clients(self, active_only: bool = True) -> List[Client]:
        """List all clients"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            query = "SELECT * FROM clients"
            if active_only:
                query += " WHERE contract_end >= date('now')"
            query += " ORDER BY company_name"
            
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            
            return [Client(**dict(row)) for row in rows]
    
    # PROJECT MANAGEMENT
    def create_project(self, project_data: Dict) -> str:
        """Create new project"""
        project_id = str(uuid.uuid4())
        
        # Ensure lists are JSON encoded
        team_members = json.dumps(project_data.get('team_members', []))
        deliverables = json.dumps(project_data.get('deliverables', []))
        
        project_data_copy = project_data.copy()
        project_data_copy['team_members'] = team_members
        project_data_copy['deliverables'] = deliverables
        
        project = Project(
            id=project_id,
            **project_data_copy
        )
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO projects (id, client_id, name, description, assessment_type,
                                    status, start_date, end_date, budget, scope, methodology,
                                    lead_consultant, team_members, deliverables, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                project.id, project.client_id, project.name, project.description,
                project.assessment_type.value, project.status.value, project.start_date,
                project.end_date, project.budget, project.scope, project.methodology,
                project.lead_consultant, team_members, deliverables, 
                project.created_at, project.updated_at
            ))
            conn.commit()
        
        return project_id
    
    def update_project_status(self, project_id: str, status: ProjectStatus):
        """Update project status"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE projects 
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, (status.value, datetime.now(), project_id))
            conn.commit()
    
    def get_projects_by_client(self, client_id: str) -> List[Project]:
        """Get all projects for a client"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM projects 
                WHERE client_id = ? 
                ORDER BY created_at DESC
            """, (client_id,))
            rows = cursor.fetchall()
            
            projects = []
            for row in rows:
                data = dict(row)
                # Decode JSON fields
                data['team_members'] = json.loads(data['team_members'])
                data['deliverables'] = json.loads(data['deliverables'])
                data['assessment_type'] = AssessmentType(data['assessment_type'])
                data['status'] = ProjectStatus(data['status'])
                projects.append(Project(**data))
            
            return projects
    
    # ASSESSMENT MANAGEMENT
    def create_assessment(self, assessment_data: Dict) -> str:
        """Create new assessment"""
        assessment_id = str(uuid.uuid4())
        
        # Encode target systems as JSON
        target_systems = json.dumps(assessment_data.get('target_systems', []))
        assessment_data_copy = assessment_data.copy()
        assessment_data_copy['target_systems'] = target_systems
        
        assessment = Assessment(
            id=assessment_id,
            created_at=datetime.now(),
            **assessment_data_copy
        )
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO assessments (id, project_id, name, target_systems, test_date,
                                       duration_hours, findings_count, critical_findings,
                                       high_findings, medium_findings, low_findings,
                                       report_path, evidence_path, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment.id, assessment.project_id, assessment.name, target_systems,
                assessment.test_date, assessment.duration_hours, assessment.findings_count,
                assessment.critical_findings, assessment.high_findings, assessment.medium_findings,
                assessment.low_findings, assessment.report_path, assessment.evidence_path,
                assessment.notes, assessment.created_at
            ))
            conn.commit()
        
        return assessment_id
    
    # DASHBOARD & REPORTING
    def get_dashboard_data(self) -> Dict:
        """Get dashboard overview data"""
        with sqlite3.connect(self.db_path) as conn:
            # Active projects count
            active_projects = conn.execute("""
                SELECT COUNT(*) FROM projects 
                WHERE status IN ('planning', 'in_progress', 'testing', 'reporting')
            """).fetchone()[0]
            
            # This month's assessments
            this_month_assessments = conn.execute("""
                SELECT COUNT(*) FROM assessments 
                WHERE test_date >= date('now', 'start of month')
            """).fetchone()[0]
            
            # Total critical findings this quarter
            critical_findings = conn.execute("""
                SELECT SUM(critical_findings) FROM assessments 
                WHERE test_date >= date('now', 'start of month', '-2 months')
            """).fetchone()[0] or 0
            
            # Revenue this month (estimated)
            revenue_data = conn.execute("""
                SELECT SUM(a.duration_hours * c.billing_rate) 
                FROM assessments a
                JOIN projects p ON a.project_id = p.id
                JOIN clients c ON p.client_id = c.id
                WHERE a.test_date >= date('now', 'start of month')
            """).fetchone()[0] or 0
            
            # Upcoming assessments
            upcoming = conn.execute("""
                SELECT a.name, p.name as project_name, c.company_name, a.test_date
                FROM assessments a
                JOIN projects p ON a.project_id = p.id  
                JOIN clients c ON p.client_id = c.id
                WHERE a.test_date > date('now')
                ORDER BY a.test_date LIMIT 5
            """).fetchall()
            
        return {
            "active_projects": active_projects,
            "this_month_assessments": this_month_assessments,
            "critical_findings": critical_findings,
            "monthly_revenue": revenue_data,
            "upcoming_assessments": upcoming
        }
    
    def generate_monthly_report(self, year: int, month: int) -> Dict:
        """Generate monthly business report"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Revenue by client
            revenue_query = """
                SELECT c.company_name, SUM(a.duration_hours * c.billing_rate) as revenue
                FROM assessments a
                JOIN projects p ON a.project_id = p.id
                JOIN clients c ON p.client_id = c.id
                WHERE strftime('%Y', a.test_date) = ? AND strftime('%m', a.test_date) = ?
                GROUP BY c.id, c.company_name
                ORDER BY revenue DESC
            """
            
            revenue_data = conn.execute(revenue_query, (str(year), f"{month:02d}")).fetchall()
            
            # Findings summary
            findings_query = """
                SELECT 
                    SUM(critical_findings) as critical,
                    SUM(high_findings) as high,
                    SUM(medium_findings) as medium,
                    SUM(low_findings) as low
                FROM assessments
                WHERE strftime('%Y', test_date) = ? AND strftime('%m', test_date) = ?
            """
            
            findings_data = conn.execute(findings_query, (str(year), f"{month:02d}")).fetchone()
            
        return {
            "month": month,
            "year": year,
            "revenue_by_client": [dict(row) for row in revenue_data],
            "findings_summary": dict(findings_data) if findings_data else {},
            "total_revenue": sum(row["revenue"] for row in revenue_data)
        }

def example_usage():
    """Example usage of the client management system"""
    
    # Initialize system
    cms = ClientManagementSystem()
    
    # Create a client
    client_id = cms.create_client({
        "company_name": "TechCorp Industries",
        "industry": "Technology",
        "contact_person": "John Smith",
        "email": "john.smith@techcorp.com",
        "phone": "+1-555-0123",
        "address": "123 Tech Street, Silicon Valley, CA",
        "contract_start": date(2024, 1, 1),
        "contract_end": date(2024, 12, 31),
        "billing_rate": 250.0,
        "notes": "Premium client, requires quarterly assessments"
    })
    
    # Create a project
    project_id = cms.create_project({
        "client_id": client_id,
        "name": "Q3 Wireless Security Assessment",
        "description": "Comprehensive wireless network security testing",
        "assessment_type": AssessmentType.WIRELESS_PENTEST,
        "status": ProjectStatus.PLANNING,
        "start_date": date(2024, 8, 15),
        "end_date": date(2024, 9, 15),
        "budget": 15000.0,
        "scope": "Corporate wireless networks, guest networks, IoT devices",
        "methodology": "NIST Cybersecurity Framework, OWASP Testing",
        "lead_consultant": "Alice Johnson",
        "team_members": ["Alice Johnson", "Bob Wilson", "Carol Davis"],
        "deliverables": ["Executive Summary", "Technical Report", "Remediation Plan"]
    })
    
    # Create an assessment
    assessment_id = cms.create_assessment({
        "project_id": project_id,
        "name": "Evil Twin Attack Testing",
        "target_systems": ["Corporate WiFi", "Guest Network", "Executive Floor WiFi"],
        "test_date": date(2024, 8, 20),
        "duration_hours": 8.0,
        "findings_count": 5,
        "critical_findings": 1,
        "high_findings": 2,
        "medium_findings": 2,
        "low_findings": 0,
        "report_path": "/reports/techcorp_evil_twin_2024_08_20.pdf",
        "evidence_path": "/evidence/techcorp_20240820/",
        "notes": "Successfully demonstrated credential harvesting"
    })
    
    # Get dashboard data
    dashboard = cms.get_dashboard_data()
    print("Dashboard Data:", dashboard)
    
    # Generate monthly report
    monthly_report = cms.generate_monthly_report(2024, 8)
    print("Monthly Report:", monthly_report)

if __name__ == "__main__":
    example_usage()