# Cloud Security Threat Detector
### Wipro COE – WE CPPE | One-Day Capstone Project

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.1-success.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/tests-17%20passed%20%28100%25%29-brightgreen.svg)]()
[![AWS Lab Compatibility](https://img.shields.io/badge/AWS%20Learner%20Lab-Ready%20%28Zero%20Cost%29-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)]()

A professional, full-stack cybersecurity monitoring dashboard and event correlation engine that analyzes cloud authentication logs, detects suspicious login patterns, calculates explainable risk scores (0–100), and provides actionable Tier 1 SOC investigation playbooks.

Designed specifically to run 100% locally on Windows without requiring paid AWS services, while providing serverless CloudFormation templates and boto3 telemetry for AWS Academy Canvas/Learner Lab accounts.

---

## 🌟 Key Features

- **SOC Operations Dashboard**: High-density cybersecurity layout with real-time KPI cards, live UTC clock, collapsible navigation sidebar, and system status indicators.
- **Visual Analytics**: Interactive **Chart.js** time-series line chart (Hourly authentication attempts: Success vs Failure) and threat severity distribution doughnut chart.
- **Dark & Light Mode**: Restrained professional SOC palette (Slate / Navy) with instantaneous theme toggling and browser `localStorage` persistence.
- **Security Detection Engine**: Explainable, real correlation logic covering 6 distinct threat vectors:
  1. `RULE-001`: Brute Force Authentication (Repeated failures against same account/IP).
  2. `RULE-002`: Password Spraying (Single origin attacking multiple accounts).
  3. `RULE-003`: Compromised Account Takeover (Failures followed by a successful login).
  4. `RULE-004`: Authentication Velocity Spike (Rapid burst indicating bot stuffing/DoS).
  5. `RULE-005`: Malformed Log Record / Header Tampering Alert.
  6. `RULE-006`: Impossible Travel / Multi-Region Geographic Anomaly.
- **Explainable AI Reasoning (CPPE Module 3)**: Deep deterministic reasoning engine explaining *What was detected*, *Why flagged*, *Risk justification*, *MITRE ATT&CK® Tactic/Technique mapping*, and a *4-step SOC Analyst checklist*.
- **Data Engineering ETL Pipeline (CPPE Module 2)**: CSV stream parser, timestamp normalization (ISO-8601, Epoch, standard datetime), IPv4 regex validation, deduplication, and export to CSV.
- **Enterprise Distributed ETL**: Standalone `etl_pyspark_pipeline.py` script demonstrating Big Data windowed processing for AWS Glue and Amazon EMR.
- **Cloud Security Controls (CPPE Module 4)**: Parameterized SQL queries, secure file uploads, hardened HTTP security headers, and tamper-evident application audit logging.
- **AWS Academy Learner Lab Integration**: Boto3 client wrapper with automatic fallback to offline simulation mode when credentials are not configured or lab policies restrict services.
- **Comprehensive Testing Suite**: 17 automated Pytest unit tests verifying API endpoints, ETL pipelines, and detection heuristics with 100% passing results.

---

## 📂 Project Structure

```
aws/
├── app.py                     # Main Flask web application & REST API
├── config.py                  # Central configuration & environment defaults
├── database.py                # SQLite persistence (parameterized SQL queries)
├── detector.py                # Security correlation heuristics & risk scoring
├── etl.py                     # Data Engineering ETL pipeline (Extract/Transform/Clean)
├── ai_explain.py              # Explainable AI reasoning engine & MITRE ATT&CK mapping
├── aws_integration.py         # AWS S3 / CloudWatch boto3 client with offline fallback
├── etl_pyspark_pipeline.py    # PySpark / AWS Glue distributed big data simulation
├── seed_data.py               # Database seeder for sample multi-vector attacks
├── requirements.txt           # Project dependencies
├── Dockerfile                 # Multi-stage lightweight container definition
├── docker-compose.yml         # Containerized local launch specification
├── .env.example               # Environment variables template
├── .gitignore                 # Git ignore for caches, databases, credentials
├── data/
│   ├── sample_security_logs.csv  # Synthetic authentication dataset
│   └── uploads/                  # Secure temporary upload directory
├── templates/
│   ├── base.html              # Core layout (Sidebar, Topbar, Clock, Theme manager)
│   ├── index.html             # SOC Dashboard overview & Chart.js panels
│   ├── incidents.html         # Incident Response Queue (Search, filters, drawer)
│   ├── upload.html            # Log Ingestion & ETL Pipeline controls
│   ├── audit.html             # Tamper-evident Security Audit Trail
│   └── settings.html          # Detection rules & threshold tuning page
├── static/
│   ├── css/
│   │   └── dashboard.css      # Custom high-polish cybersecurity UI styles
│   └── js/
│       ├── dashboard.js       # Chart.js charts and real-time KPI updates
│       ├── incidents.js       # Incidents queue, modal drawer, status transitions
│       └── theme.js           # Dark/Light theme manager with localStorage persistence
├── tests/
│   ├── test_detection.py      # Detection heuristic & risk calculation tests
│   ├── test_etl.py            # CSV schema, normalization, and deduplication tests
│   └── test_api.py            # Flask REST endpoints & workflow tests
├── aws/
│   ├── cloudformation_template.yaml  # AWS S3, Lambda, CloudWatch, and IAM template
│   └── lambda_threat_detector.py     # Event-driven serverless log analyzer
└── docs/
    ├── ARCHITECTURE.md        # Technical architecture & AWS migration blueprint
    ├── CPPE_MAPPING.md        # Wipro CPPE Milestones 1 to 4 detailed mapping
    └── DEMO_SCRIPT.md         # 5-minute technical presentation script
```

---

## 🚀 Quick Start Guide (Windows)

### Prerequisites
- Windows 10 or 11
- Python 3.10+ (Verified on Python 3.14)
- Web Browser (Chrome, Edge, Firefox)

### Step 1: Open Terminal in Project Root
Open PowerShell or Command Prompt in the project folder:
```powershell
cd c:\Users\V.logeshwari\OneDrive\Documents\Desktop\aws
```

### Step 2: Install Dependencies
Install all required libraries using pip:
```powershell
python -m pip install -r requirements.txt
```
*(Dependencies: `Flask`, `pandas`, `pytest`, `python-dotenv`, `boto3`, `Werkzeug`)*

### Step 3: Initialize Database & Seed Demonstration Data
Run the database seed script to initialize SQLite tables and load synthetic demonstration attacks:
```powershell
python seed_data.py
```
*Expected Output:*
```text
[+] Initializing database schema...
[+] Running CPPE Module 2 ETL Pipeline...
[+] Ingesting 35 security events into SQLite...
[+] Detected 8 actionable security incidents across correlation rules.
========================================================
  SEED COMPLETE! Ingested: 35 events | Threats Flagged: 8
========================================================
```

### Step 4: Launch the SOC Application
Start the Flask web server:
```powershell
python app.py
```

### Step 5: Open the Dashboard
Open your browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🧪 Running Automated Tests

Execute the automated test suite with pytest:
```powershell
python -m pytest -v
```

**Actual Test Results:**
```text
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.0.3, pluggy-1.6.0
collected 17 items

tests/test_api.py::test_health_check_endpoint PASSED                     [  5%]
tests/test_api.py::test_dashboard_stats_endpoint PASSED                  [ 11%]
tests/test_api.py::test_incidents_listing_and_filtering PASSED           [ 17%]
tests/test_api.py::test_incident_status_update PASSED                    [ 23%]
tests/test_api.py::test_incident_explainability_endpoint PASSED          [ 29%]
tests/test_api.py::test_csv_export_endpoint PASSED                       [ 35%]
tests/test_detection.py::test_empty_dataset PASSED                       [ 41%]
tests/test_detection.py::test_repeated_failed_logins_brute_force PASSED  [ 47%]
tests/test_detection.py::test_password_spraying_detection PASSED         [ 52%]
tests/test_detection.py::test_compromised_account_post_bruteforce PASSED [ 58%]
tests/test_detection.py::test_velocity_spike_detection PASSED            [ 64%]
tests/test_detection.py::test_risk_score_calculation PASSED              [ 70%]
tests/test_etl.py::test_valid_csv_processing PASSED                      [ 76%]
tests/test_etl.py::test_missing_required_columns PASSED                  [ 82%]
tests/test_etl.py::test_timestamp_normalization PASSED                   [ 88%]
tests/test_etl.py::test_ip_validation PASSED                             [ 94%]
tests/test_etl.py::test_duplicate_row_removal PASSED                     [100%]

============================= 17 passed in 1.47s ==============================
```

---

## 🐳 Docker Deployment (Optional)

To run the application inside a container:
```powershell
# Build and run with Docker Compose
docker-compose up --build
```
Then visit `http://localhost:5000`.

---

## ☁️ AWS Academy Learner Lab Deployment

The application is engineered to operate in **Zero-Cost Simulation Mode** by default. When AWS temporary credentials are configured in `~/.aws/credentials` or through environment variables, the application can interface with live AWS services:

1. **Amazon S3**: Ingested CSV files are automatically archived to the configured S3 bucket (`wipro-security-threat-logs-demo`).
2. **Amazon CloudWatch**: Emits custom metrics (`IngestedEventsCount`, `ThreatsDetectedCount`, `Incident_Investigating`) in namespace `Wipro/CloudSecurityThreatDetector`.
3. **AWS Lambda**: The serverless handler in `aws/lambda_threat_detector.py` provides event-driven threat analysis triggered upon S3 object upload.
4. **CloudFormation**: Deploy the complete cloud stack via:
   ```bash
   aws cloudformation deploy \
     --template-file aws/cloudformation_template.yaml \
     --stack-name Wipro-CloudSecurityThreatDetector \
     --capabilities CAPABILITY_IAM
   ```

---

## 📊 Wipro CPPE Milestones Summary

- **Module 1 (Cloud Product Engineering)**: Modular architecture, REST API, health check `/health`, `.env` configuration, Dockerfile, and Pytest coverage.
- **Module 2 (Data Engineering)**: Comprehensive ETL pipeline (`etl.py`), timestamp normalization, deduplication, CSV export, and distributed PySpark scaling script (`etl_pyspark_pipeline.py`).
- **Module 3 (Generative AI & Explainability)**: Transparent explainability reasoning engine (`ai_explain.py`), MITRE ATT&CK® matrix mapping, and Tier 1 SOC investigation checklists.
- **Module 4 (Cloud Security & AWS)**: Parameterized SQL queries, input sanitization, security headers, tamper-evident audit logging (`/audit`), and AWS Academy least-privilege architecture.

---

## 📜 5-Minute Presentation Script

For step-by-step presentation instructions for your evaluation panel, refer to:  
👉 **[docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)**
