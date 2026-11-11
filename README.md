# 🛡️ Cloud Security Threat Detector & SIEM Event Correlation Engine

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.14-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.1-success.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-17%20Passed%20%28100%25%29-brightgreen.svg?logo=pytest&logoColor=white)](tests/)
[![Security Standards](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%C2%AE-red.svg)](https://attack.mitre.org/)
[![Cloud Ready](https://img.shields.io/badge/AWS-S3%20%7C%20CloudWatch%20%7C%20Lambda-orange.svg?logo=amazon-aws&logoColor=white)](aws/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

An enterprise-grade, full-stack Cloud Security Information and Event Management (SIEM) dashboard and event correlation platform. Engineered for modern Security Operations Centers (SOC), it continuously ingests distributed cloud authentication streams, detects sophisticated adversary attack patterns in real time, computes granular risk scores (0–100), and delivers automated Tier 1 investigation playbooks mapped directly to the **MITRE ATT&CK® Enterprise Matrix**.

Built with a flexible, cloud-native hybrid architecture: capable of running completely self-contained in local environments with zero external service dependencies, while offering turnkey integration with enterprise AWS cloud infrastructure (Amazon S3, Amazon CloudWatch, AWS Lambda, and CloudFormation).

---

## 🌟 Key Capabilities

- **SOC Operations Command Center**: High-density security dashboard featuring real-time KPI metrics, live UTC operations clock, threat triage queues, and reactive telemetry indicators.
- **Visual Threat Analytics**: Interactive **Chart.js** time-series authentication timelines (Hourly Attempts: Success vs. Failure) and categorical threat severity distribution matrices.
- **Accessible Dark & Light UI**: Precision-engineered SOC palette (Slate / Deep Navy) with sub-millisecond theme toggling and browser `localStorage` state persistence.
- **Multi-Vector Correlation Engine**: Deterministic, high-fidelity correlation rules covering critical cloud identity attack vectors:
  1. `RULE-001`: **Brute Force Authentication** (Repeated credential failures against targeted accounts/IP origins).
  2. `RULE-002`: **Password Spraying Attack** (Horizontal credential stuffing across multiple identities from a single origin).
  3. `RULE-003`: **Compromised Account Takeover (ATO)** (Anomalous successful login immediately following sustained brute force failures).
  4. `RULE-004`: **Authentication Velocity Spike** (Volumetric bursts indicating automated botnets or denial-of-service).
  5. `RULE-005`: **Malformed Log / Header Tampering** (Protocol-level header manipulation and log spoofing).
  6. `RULE-006`: **Impossible Travel Anomaly** (Simultaneous or temporally infeasible logins across disparate geographic regions).
- **Explainable AI & MITRE ATT&CK® Mapping**: Transparent, deterministic reasoning engine providing clear forensic narratives: *What was detected*, *Trigger conditions*, *Risk justification*, *Tactics & Techniques (T1110, T1078, etc.)*, and step-by-step *SOC Analyst Playbooks*.
- **High-Throughput Data Engineering ETL Pipeline**: Resilient stream parser supporting multi-format timestamps (ISO-8601, Unix epoch, standard datetime), IPv4 regex sanitization, deduplication, and structured CSV export.
- **Enterprise Distributed Big Data Processing**: Standalone PySpark pipeline (`etl_pyspark_pipeline.py`) modeling enterprise-scale windowed batch processing for AWS Glue and Amazon EMR.
- **Zero-Trust Hardened Security Controls**: Strict parameterized SQL queries preventing injection, secure file ingestion policies, hardened HTTP security response headers, and tamper-evident audit logging.
- **Turnkey AWS Cloud Integration**: Native Boto3 client wrapper with automated offline fallback for local evaluation, coupled with event-driven serverless log processing via AWS Lambda and S3.
- **Production-Grade Automated Testing**: 100% passing test coverage (17/17 automated Pytest unit tests) validating REST APIs, ETL transformation rules, and detection heuristics.

---

## 📂 Project Architecture

```
CLOUD-SECURITY-THREAT-DETECTOR/
├── app.py                     # Primary Flask application & REST API endpoints
├── config.py                  # Production configuration & environment defaults
├── database.py                # Persistence layer with parameterized SQL queries
├── detector.py                # Security correlation heuristics & risk evaluation engine
├── etl.py                     # Data Engineering ETL pipeline (Extract/Transform/Clean)
├── ai_explain.py              # Explainable AI engine & MITRE ATT&CK taxonomy mapping
├── aws_integration.py         # AWS S3 & CloudWatch client wrapper with offline fallback
├── etl_pyspark_pipeline.py    # PySpark / AWS Glue distributed stream simulation
├── seed_data.py               # Database seeder for threat vectors and demo attack logs
├── requirements.txt           # Python application dependencies
├── Dockerfile                 # Multi-stage lightweight production container
├── docker-compose.yml         # Container orchestration manifest
├── .env.example               # Environment configuration template
├── .gitignore                 # Exclusion rules for credentials, DBs, and caches
├── data/
│   ├── sample_security_logs.csv  # Synthetic multi-vector authentication log dataset
│   └── uploads/                  # Secure temporary ingestion staging directory
├── templates/
│   ├── base.html              # Base layout (Navigation, Topbar, Clock, Theme manager)
│   ├── index.html             # SOC Dashboard overview & Chart.js visual telemetry
│   ├── incidents.html         # Incident Response Queue (Search, filters, drawer modal)
│   ├── upload.html            # Log Ingestion & Data Engineering ETL interface
│   ├── audit.html             # Tamper-evident SOC Audit Trail & Access Logging
│   └── settings.html          # Dynamic detection threshold configuration
├── static/
│   ├── css/
│   │   └── dashboard.css      # Custom high-polish cybersecurity UI styling
│   └── js/
│       ├── dashboard.js       # Real-time KPI feeds & Chart.js visualizations
│       ├── incidents.js       # Triage workflow, status transitions, and drawer modals
│       └── theme.js           # Dark/Light theme manager with persistent storage
├── tests/
│   ├── test_detection.py      # Detection heuristic & risk calculation test suite
│   ├── test_etl.py            # CSV schema, normalization, and deduplication tests
│   └── test_api.py            # Flask REST endpoints & health check tests
├── aws/
│   ├── cloudformation_template.yaml  # Infrastructure-as-Code for AWS S3, Lambda, & CloudWatch
│   └── lambda_threat_detector.py     # Event-driven serverless threat detection handler
└── docs/
    ├── ARCHITECTURE.md        # Technical architecture, threat modeling, & cloud migration
    ├── CPPE_MAPPING.md        # Engineering competency & milestone documentation
    └── DEMO_SCRIPT.md         # Technical demonstration & operational walkthrough guide
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10+ (Verified on Python 3.10, 3.11, and 3.14)
- Git
- Modern Web Browser (Chrome, Edge, Firefox, Safari)

### Step 1: Clone Repository & Navigate
```bash
git clone https://github.com/krishnaprasathV/CLOUD-SECURITY-THREAT-DETECTOR.git
cd CLOUD-SECURITY-THREAT-DETECTOR
```

### Step 2: Install Dependencies
```bash
python -m pip install -r requirements.txt
```
*(Core packages: `Flask`, `pandas`, `pytest`, `python-dotenv`, `boto3`, `Werkzeug`)*

### Step 3: Initialize Database & Seed Demonstration Data
Initialize the SQLite database schema and ingest demonstration threat vectors:
```bash
python seed_data.py
```
*Expected Terminal Output:*
```text
[+] Initializing database schema...
[+] Running Security ETL Pipeline (Extract -> Transform -> Validate -> Clean)...
[+] Ingesting 35 security events into SQLite...
[+] Detected 8 actionable security incidents across correlation rules.
========================================================
  SEED COMPLETE! Ingested: 35 events | Threats Flagged: 8
========================================================
```

### Step 4: Launch the SOC Application
```bash
python app.py
```

### Step 5: Access the Dashboard
Open your web browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🧪 Automated Testing Suite

Execute the full suite of unit and integration tests using pytest:
```bash
python -m pytest -v
```

**Verified Test Results:**
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

## 🐳 Container Deployment

Deploy using Docker and Docker Compose for fully isolated environments:
```bash
docker-compose up --build
```
The application will be accessible at `http://localhost:5000`.

---

## ☁️ Enterprise Cloud Deployment & Telemetry

The platform includes production-ready cloud telemetry connectors. By default, it runs in **Autonomous Simulation Mode** with zero cloud billing requirements. When AWS credentials are provided via environment variables or IAM instance profiles, the system streams live security telemetry:

1. **Amazon S3 (`cloud-security-threat-logs`)**: Ingested log files and raw forensic evidence are securely archived with SSE-S3 encryption.
2. **Amazon CloudWatch (`CloudSecurity/ThreatDetector`)**: Real-time emission of SOC metrics (`IngestedEventsCount`, `ThreatsDetectedCount`, `Incident_Investigating`) for alert triggering.
3. **AWS Lambda (`lambda_threat_detector.py`)**: Serverless microservice handler executing real-time log ingestion and correlation upon S3 bucket `ObjectCreated` events.
4. **AWS CloudFormation (`aws/cloudformation_template.yaml`)**: Automated Infrastructure-as-Code (IaC) deployment:
   ```bash
   aws cloudformation deploy \
     --template-file aws/cloudformation_template.yaml \
     --stack-name CloudSecurity-ThreatDetector \
     --capabilities CAPABILITY_IAM
   ```

---

## 🏛️ Engineering Architecture & Design Principles

- **Modular Product Architecture**: Clean separation of concerns across presentation (Flask/Jinja2), business logic (`detector.py`), data ingestion (`etl.py`), and storage (`database.py`).
- **Resilient Data Engineering**: Automated ingestion pipeline supporting diverse multi-regional log dialects, RFC 5952 IPv4 validation, missing-field imputation, and Big Data windowed processing.
- **Explainable Machine Reasoning**: Deterministic AI-assisted decision trees mapping every detected incident to standardized MITRE ATT&CK® matrix techniques with quantifiable risk scoring.
- **Defense-in-Depth Security**: Parameterized queries preventing SQL injection, strict filename sanitization preventing directory traversal, secure HTTP headers (CSP, HSTS, X-Frame-Options), and an append-only audit trail.

---

## 📚 Documentation & Technical References

- **[System Architecture & Threat Modeling](docs/ARCHITECTURE.md)**: In-depth engineering specifications, data flow diagrams, and AWS migration blueprints.
- **[Demonstration & Operational Walkthrough](docs/DEMO_SCRIPT.md)**: Comprehensive end-to-end walkthrough for technical evaluations and SOC analyst onboarding.
- **[Engineering Competency & Milestone Mapping](docs/CPPE_MAPPING.md)**: Detailed technical mapping covering cloud engineering, data pipelines, explainable AI, and security controls.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
