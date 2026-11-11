# Wipro COE – WE CPPE Milestone Mapping

This document provides a formal mapping of the **Cloud Security Threat Detector** application to the learning outcomes and deliverables across all four CPPE Milestones.

---

## Milestone 1: Cloud Product Engineering

| Requirement | Implementation in Project | Source Code Reference |
| :--- | :--- | :--- |
| **Modular Flask Backend** | Decoupled architecture separating persistence, detection, ingestion, and presentation. | `app.py`, `config.py`, `database.py` |
| **RESTful Endpoints** | Clean JSON endpoints for stats, incidents, status updates, file ingestion, and health checks. | `app.py` (`/api/stats`, `/api/incidents`, `/api/upload`, `/health`) |
| **Centralized Error Handling** | Structured JSON error handlers for HTTP 400, 404, 500 status codes. | `app.py` (`@app.errorhandler`) |
| **Configuration Management** | Dynamic environment variables with `.env` and `python-dotenv`. | `config.py`, `.env.example` |
| **Containerization** | Production-ready multi-stage Dockerfile and Docker Compose definition. | `Dockerfile`, `docker-compose.yml` |
| **Automated Testing** | Comprehensive Pytest suite covering API endpoints and status updates. | `tests/test_api.py` (100% pass rate) |

---

## Milestone 2: Data Engineering

| Requirement | Implementation in Project | Source Code Reference |
| :--- | :--- | :--- |
| **CSV Log Ingestion** | Robust stream reader parsing diverse authentication and access log streams. | `etl.py` (`process_csv_stream`) |
| **Timestamp Normalization** | Converts ISO-8601, Epoch timestamps, and custom date strings into UTC ISO format. | `etl.py` (`normalize_timestamp`) |
| **Data Cleaning & Deduplication** | Removes duplicate authentication attempts and quarantines malformed records. | `etl.py` (`deduplicated_count`, `validate_ip`) |
| **Grouping & Aggregations** | Sliding window aggregations and frequency counters using Pandas. | `detector.py`, `database.py` |
| **Export Analyzed Telemetry** | High-performance CSV export of analyzed incidents and sanitized logs. | `app.py` (`/api/export`), `etl.py` |
| **Enterprise Big Data Scaling** | Standalone PySpark / AWS Glue distributed script for terabyte-scale log lakes. | `etl_pyspark_pipeline.py` |

---

## Milestone 3: Generative AI & Explainability

| Requirement | Implementation in Project | Source Code Reference |
| :--- | :--- | :--- |
| **Explainable Threat Reasoning** | Deterministic local SOC analyst breakdown: What detected, Why flagged, Risk reasoning. | `ai_explain.py` (`explain_incident`) |
| **MITRE ATT&CK® Mapping** | Direct mapping of each detection rule to MITRE ATT&CK tactics, techniques, and IDs. | `ai_explain.py` (`SOC_RUNBOOK_KNOWLEDGE_BASE`) |
| **Actionable Playbooks** | Step-by-step Tier 1 triage checklist and defensive containment remediation steps. | `ai_explain.py` (`investigation_checklist`) |
| **Zero-Cost Local Execution** | 100% reliable local rule-based reasoning engine requiring zero paid API keys. | `ai_explain.py` (`IncidentExplainer`) |
| **RAG Architecture Simulation** | Documented vector embedding retrieval simulation for security runbooks. | `ai_explain.py` (`rag_context`), `docs/ARCHITECTURE.md` |

---

## Milestone 4: Cloud Security & AWS Integration

| Requirement | Implementation in Project | Source Code Reference |
| :--- | :--- | :--- |
| **SQL Injection Prevention** | 100% parameterized SQLite SQL queries across all reads and writes. | `database.py` (No raw string formatting) |
| **Secure File Handling** | `secure_filename`, extension whitelist (`.csv`), file size limits (16MB). | `app.py` (`api_upload`), `config.py` |
| **Application Audit Trail** | Tamper-evident security audit log recording analyst and system actions. | `database.py` (`log_audit`), `templates/audit.html` |
| **Security Headers** | Hardened response headers (`X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`). | `app.py` (`add_security_headers`) |
| **AWS Academy Lab Compatibility** | Non-breaking offline simulation mode with boto3 integration for S3 & CloudWatch. | `aws_integration.py` |
| **Serverless Architecture** | AWS Lambda event handler and CloudFormation infrastructure template. | `aws/lambda_threat_detector.py`, `aws/cloudformation_template.yaml` |
