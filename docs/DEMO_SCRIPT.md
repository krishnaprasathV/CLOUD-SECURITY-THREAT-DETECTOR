# 5-Minute Technical Project Demonstration Script
## Wipro COE – WE CPPE Capstone Presentation

**Project:** Cloud Security Threat Detector  
**Target Audience:** Evaluation Panel / Technical Assessors  
**Total Allocated Time:** 5 Minutes  

---

### Minute 0:00 – 0:45 | Introduction & Problem Statement
- **Speaker Action:** Open browser to `http://127.0.0.1:5000` (Dashboard).
- **Speaking Track:**
  > "Respected mentors and evaluators, welcome to the demonstration of my Wipro CPPE Capstone Project: **Cloud Security Threat Detector**.
  > In enterprise cloud environments like AWS, organizations process millions of authentication events daily. Identifying credential stuffing, brute force spikes, and password spraying among legitimate logins is a critical SOC challenge.
  > Today, I will demonstrate a production-grade SOC dashboard built on Python, Flask, Pandas, and SQLite, integrated with an explainable AI reasoning engine, complete ETL pipeline, and AWS cloud integration designed specifically for Learner Lab environments."

---

### Minute 0:45 – 1:45 | Dashboard Walkthrough & Visual Analytics
- **Speaker Action:** Point out Top Navigation, Theme Toggle, KPI Cards, and Charts.
- **Speaking Track:**
  > "Here on the **SOC Overview Dashboard**, all KPI metrics reflect real database records, not static mockups.
  > In the top bar, notice our live UTC clock and Cloud Status indicator showing active telemetry.
  > Let's test the theme: with one click, our toggle switches between a crisp Light Mode and this restrained dark navy SOC palette, persisted via browser `localStorage`.
  > We have six core KPI cards: Total Logs Ingested, Successful vs Failed attempts, High & Critical alerts, and an Explainable Average Risk Score.
  > Below, Chart.js powers our **Authentication Events Over Time** timeline, contrasting failures with successful logins, while the donut chart categorizes threats by severity.
  > Notice our Top Targeted Accounts (e.g., `admin`) and Top Suspicious IPs with geographic origin flags."

---

### Minute 1:45 – 2:45 | Security Detection Engine & Explainable AI (Module 3)
- **Speaker Action:** Navigate to **Incidents Queue** (`/incidents`), demonstrate filters, and click **Investigate** on `INC-COMP-XXXX`.
- **Speaking Track:**
  > "Next, let's explore our **Security Detection Engine**. We implement real, explainable correlation heuristics covering 6 threat vectors: Brute Force, Password Spraying, Account Takeover, Velocity Spikes, Malformed Records, and Impossible Travel.
  > In our Incident Response Queue, analysts can filter by status, search by IP or username, and sort by risk score.
  > Clicking **Investigate** opens our SOC Investigation Drawer.
  > Notice our **Explainable Reasoning Engine (CPPE Module 3)**: It breaks down *What was detected*, *Why it was flagged*, justifies the *Risk Score*, maps directly to **MITRE ATT&CK® T1078 (Valid Accounts)**, and provides a 4-step Tier 1 investigation checklist.
  > Notice the workflow controls: An analyst can transition an incident from **New** to **Investigating** and **Resolved**, persisting changes and logging tamper-evident audit records."

---

### Minute 2:45 – 3:45 | Data Engineering ETL Pipeline (Module 2)
- **Speaker Action:** Navigate to **Log Ingestion & ETL** (`/upload`), demonstrate the drag & drop zone, and show ETL metrics.
- **Speaking Track:**
  > "Under **Log Ingestion & ETL (CPPE Module 2)**, we demonstrate a robust pipeline: Extract, Transform, Validate, and Deduplicate.
  > The pipeline normalizes non-standard timestamps into UTC ISO-8601, validates IPv4 syntaxes, filters malformed records, and cleanses data.
  > Analysts can upload custom CSV logs or click **Load Synthetic Multi-Vector Dataset** with one click.
  > Furthermore, for enterprise big data scaling to AWS Glue and Amazon EMR, we provide `etl_pyspark_pipeline.py` which demonstrates distributed windowed aggregations across worker nodes."

---

### Minute 3:45 – 4:30 | Cloud Security, AWS Integration & Audit Trail (Module 4)
- **Speaker Action:** Navigate to **Audit Trail** (`/audit`) and **Settings & Rules** (`/settings`).
- **Speaking Track:**
  > "For **Cloud Security (Module 4)**, the entire application implements parameterized SQL queries, secure file validation, and hardened HTTP headers.
  > Every operator action is recorded here in the **Audit Trail**.
  > Under **Settings**, detection thresholds (such as failed attempt limits and correlation windows) are fully tunable at runtime.
  > For AWS Learner Lab, our `aws_integration.py` runs in graceful offline simulation mode without failing or demanding paid API keys, while our CloudFormation template and AWS Lambda handler in `aws/` provide the full serverless blueprint."

---

### Minute 4:30 – 5:00 | Conclusion & QA
- **Speaker Action:** Return to SOC Dashboard overview.
- **Speaking Track:**
  > "To ensure enterprise quality, our automated Pytest suite runs 17 unit tests with a 100% pass rate.
  > The application is containerized with Docker, fully documented in our README, and ready for deployment.
  > Thank you, and I look forward to your questions."
