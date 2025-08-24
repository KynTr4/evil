#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Professional Web Dashboard for Cybersecurity Services
Client Portal & Project Management Interface

Flask-based web application for client interaction and project tracking
"""

from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import json
import os
from datetime import datetime, date
from pathlib import Path
import hashlib
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, role, client_id=None):
        self.id = id
        self.username = username
        self.email = email
        self.role = role  # admin, consultant, client
        self.client_id = client_id

@login_manager.user_loader
def load_user(user_id):
    # Load user from database
    with sqlite3.connect('cybersec_crm.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        
        if user_data:
            return User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                client_id=user_data.get('client_id')
            )
    return None

def init_user_system():
    """Initialize user management system"""
    with sqlite3.connect('cybersec_crm.db') as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,  -- admin, consultant, client
                client_id TEXT,  -- For client users
                created_at TIMESTAMP,
                last_login TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients (id)
            )
        """)
        
        # Create default admin user if none exists
        cursor = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        if cursor.fetchone()[0] == 0:
            admin_id = secrets.token_hex(16)
            password_hash = generate_password_hash('admin123')  # Change this!
            
            conn.execute("""
                INSERT INTO users (id, username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (admin_id, 'admin', 'admin@cybersec.com', password_hash, 'admin', datetime.now()))
        
        conn.commit()

# Initialize on startup
init_user_system()

@app.route('/')
def index():
    """Dashboard home page"""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Import client management system
    from management.client_system import ClientManagementSystem
    cms = ClientManagementSystem()
    
    if current_user.role == 'admin' or current_user.role == 'consultant':
        # Full dashboard for admin/consultants
        dashboard_data = cms.get_dashboard_data()
        return render_template('dashboard.html', 
                             dashboard=dashboard_data,
                             user_role=current_user.role)
    
    elif current_user.role == 'client':
        # Client-specific dashboard
        client_projects = cms.get_projects_by_client(current_user.client_id)
        return render_template('client_dashboard.html',
                             projects=client_projects,
                             client_id=current_user.client_id)
    
    return render_template('dashboard.html', dashboard={}, user_role='guest')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect('cybersec_crm.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
            user_data = cursor.fetchone()
            
            if user_data and check_password_hash(user_data['password_hash'], password):
                user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    email=user_data['email'],
                    role=user_data['role'],
                    client_id=user_data.get('client_id')
                )
                login_user(user)
                
                # Update last login
                conn.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                           (datetime.now(), user.id))
                conn.commit()
                
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/projects')
@login_required
def projects():
    """Projects list page"""
    from management.client_system import ClientManagementSystem
    cms = ClientManagementSystem()
    
    if current_user.role == 'client':
        # Show only client's projects
        client_projects = cms.get_projects_by_client(current_user.client_id)
        return render_template('projects.html', projects=client_projects, user_role='client')
    else:
        # Show all projects for admin/consultants
        # Implementation would fetch all projects
        return render_template('projects.html', projects=[], user_role=current_user.role)

@app.route('/reports/<project_id>')
@login_required
def view_report(project_id):
    """View project report"""
    # Security check - ensure user can access this project
    from management.client_system import ClientManagementSystem
    cms = ClientManagementSystem()
    
    # Get project and verify access
    with sqlite3.connect('cybersec_crm.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        project = cursor.fetchone()
        
        if not project:
            flash('Project not found')
            return redirect(url_for('projects'))
        
        # Check access permissions
        if current_user.role == 'client' and project['client_id'] != current_user.client_id:
            flash('Access denied')
            return redirect(url_for('projects'))
        
        # Get assessments for this project
        cursor = conn.execute("SELECT * FROM assessments WHERE project_id = ?", (project_id,))
        assessments = cursor.fetchall()
        
        return render_template('report_view.html', 
                             project=project, 
                             assessments=assessments)

@app.route('/api/projects/<project_id>/status', methods=['POST'])
@login_required
def update_project_status(project_id):
    """API endpoint to update project status"""
    if current_user.role == 'client':
        return jsonify({'error': 'Access denied'}), 403
    
    if not request.json:
        return jsonify({'error': 'No JSON data provided'}), 400
        
    new_status = request.json.get('status')
    
    from management.client_system import ClientManagementSystem, ProjectStatus
    cms = ClientManagementSystem()
    
    try:
        status_enum = ProjectStatus(new_status)
        cms.update_project_status(project_id, status_enum)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/clients')
@login_required
def clients():
    """Clients management page (admin/consultant only)"""
    if current_user.role == 'client':
        return redirect(url_for('index'))
    
    from management.client_system import ClientManagementSystem
    cms = ClientManagementSystem()
    
    client_list = cms.list_clients()
    return render_template('clients.html', clients=client_list)

@app.route('/upload_report/<project_id>', methods=['POST'])
@login_required
def upload_report(project_id):
    """Upload report file"""
    if current_user.role == 'client':
        return jsonify({'error': 'Access denied'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and file.filename:
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)
        
        # Update database with report path
        with sqlite3.connect('cybersec_crm.db') as conn:
            conn.execute("""
                UPDATE projects 
                SET report_path = ?, updated_at = ?
                WHERE id = ?
            """, (upload_path, datetime.now(), project_id))
            conn.commit()
        
        return jsonify({'success': True, 'filename': filename})

@app.route('/download_report/<project_id>')
@login_required
def download_report(project_id):
    """Download project report"""
    # Verify access and get report path
    with sqlite3.connect('cybersec_crm.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("""
            SELECT p.*, c.company_name 
            FROM projects p 
            JOIN clients c ON p.client_id = c.id 
            WHERE p.id = ?
        """, (project_id,))
        project = cursor.fetchone()
        
        if not project:
            flash('Project not found')
            return redirect(url_for('projects'))
        
        # Check access permissions
        if current_user.role == 'client' and project['client_id'] != current_user.client_id:
            flash('Access denied')
            return redirect(url_for('projects'))
        
        report_path = project.get('report_path')
        if report_path and os.path.exists(report_path):
            return send_file(report_path, as_attachment=True)
        else:
            flash('Report not available')
            return redirect(url_for('view_report', project_id=project_id))

@app.route('/api/dashboard/metrics')
@login_required
def dashboard_metrics():
    """API endpoint for dashboard metrics"""
    if current_user.role == 'client':
        return jsonify({'error': 'Access denied'}), 403
    
    from management.client_system import ClientManagementSystem
    cms = ClientManagementSystem()
    
    metrics = cms.get_dashboard_data()
    return jsonify(metrics)

@app.route('/reports/monthly/<int:year>/<int:month>')
@login_required
def monthly_report(year, month):
    """Monthly business report"""
    if current_user.role == 'client':
        return redirect(url_for('index'))
    
    from management.client_system import ClientManagementSystem
    cms = ClientManagementSystem()
    
    report_data = cms.generate_monthly_report(year, month)
    return render_template('monthly_report.html', report=report_data)

# Create templates directory structure
def create_templates():
    """Create basic HTML templates"""
    templates_dir = Path(__file__).parent / "templates"
    templates_dir.mkdir(exist_ok=True)
    
    # Base template
    base_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSec Professional - {% block title %}Dashboard{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .sidebar { min-height: 100vh; background: #2c3e50; }
        .sidebar .nav-link { color: #ecf0f1; }
        .sidebar .nav-link:hover { background: #34495e; }
        .main-content { background: #f8f9fa; min-height: 100vh; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            {% if current_user.is_authenticated %}
            <nav class="col-md-2 d-none d-md-block sidebar">
                <div class="sidebar-sticky">
                    <div class="p-3">
                        <h4 class="text-light">CyberSec Pro</h4>
                        <p class="text-muted">{{ current_user.username }}</p>
                    </div>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('index') }}">
                                <i class="fas fa-dashboard"></i> Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('projects') }}">
                                <i class="fas fa-project-diagram"></i> Projects
                            </a>
                        </li>
                        {% if current_user.role != 'client' %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('clients') }}">
                                <i class="fas fa-users"></i> Clients
                            </a>
                        </li>
                        {% endif %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('logout') }}">
                                <i class="fas fa-sign-out-alt"></i> Logout
                            </a>
                        </li>
                    </ul>
                </div>
            </nav>
            {% endif %}
            
            <main class="col-md-10 ml-sm-auto main-content">
                <div class="p-4">
                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            {% for message in messages %}
                                <div class="alert alert-info">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    {% block content %}{% endblock %}
                </div>
            </main>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>"""
    
    # Dashboard template
    dashboard_template = """{% extends "base.html" %}

{% block title %}Dashboard{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h1 class="h2">Dashboard</h1>
        <p class="text-muted">Cybersecurity Services Overview</p>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card text-white bg-primary">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ dashboard.active_projects }}</h4>
                        <p>Active Projects</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-project-diagram fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-success">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ dashboard.this_month_assessments }}</h4>
                        <p>This Month's Tests</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-shield-alt fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-warning">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ dashboard.critical_findings }}</h4>
                        <p>Critical Findings</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-exclamation-triangle fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-info">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>${{ "%.0f"|format(dashboard.monthly_revenue) }}</h4>
                        <p>Monthly Revenue</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-dollar-sign fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h5>Upcoming Assessments</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Assessment</th>
                                <th>Project</th>
                                <th>Client</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for assessment in dashboard.upcoming_assessments %}
                            <tr>
                                <td>{{ assessment[0] }}</td>
                                <td>{{ assessment[1] }}</td>
                                <td>{{ assessment[2] }}</td>
                                <td>{{ assessment[3] }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5>Quick Actions</h5>
            </div>
            <div class="card-body">
                <div class="d-grid gap-2">
                    <a href="#" class="btn btn-primary">New Assessment</a>
                    <a href="#" class="btn btn-success">Generate Report</a>
                    <a href="{{ url_for('clients') }}" class="btn btn-info">Manage Clients</a>
                    <a href="#" class="btn btn-warning">View Analytics</a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}"""
    
    # Login template
    login_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSec Professional - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="card mt-5">
                    <div class="card-header text-center">
                        <h3>CyberSec Professional</h3>
                        <p class="text-muted">Secure Access Portal</p>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages() %}
                            {% if messages %}
                                {% for message in messages %}
                                    <div class="alert alert-danger">{{ message }}</div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}
                        
                        <form method="POST">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">Login</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""
    
    # Write templates
    (templates_dir / "base.html").write_text(base_template)
    (templates_dir / "dashboard.html").write_text(dashboard_template)
    (templates_dir / "login.html").write_text(login_template)

if __name__ == '__main__':
    # Create templates on startup
    create_templates()
    
    # Create upload directory
    Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)
    
    # Run development server
    app.run(debug=True, host='0.0.0.0', port=5000)