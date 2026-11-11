"""
Seed script for Cloud Security Threat Detector.
Loads synthetic sample logs, executes the ETL pipeline, and runs detection rules.
"""

from pathlib import Path
from config import BASE_DIR
from database import init_db, insert_events_batch, insert_incidents_batch, log_audit, reset_database
from detector import SecurityDetector
from etl import LogETLPipeline


def run_seed(reset: bool = True):
    """Initializes tables and seeds synthetic security logs."""
    print("[+] Initializing database schema...")
    init_db()

    if reset:
        print("[+] Resetting previous demo data...")
        reset_database(actor="SeedScript")

    sample_csv_path = BASE_DIR / "data" / "sample_security_logs.csv"
    if not sample_csv_path.exists():
        print(f"[-] Sample CSV file not found at {sample_csv_path}")
        return

    print(f"[+] Loading sample security dataset: {sample_csv_path}...")
    with open(sample_csv_path, "r", encoding="utf-8") as f:
        content = f.read()

    print("[+] Running CPPE Module 2 ETL Pipeline (Extract -> Transform -> Validate -> Clean)...")
    etl = LogETLPipeline()
    result = etl.process_csv_stream(content)

    if not result["success"]:
        print(f"[-] ETL failed: {result.get('error')}")
        return

    events = result["valid_records"]
    print(f"[+] Ingesting {len(events)} security events into SQLite...")
    inserted = insert_events_batch(events)
    print(f"[+] Successfully inserted {inserted} records.")

    print("[+] Running CPPE Module 1 & 4 Security Correlation Engine...")
    detector = SecurityDetector()
    incidents = detector.analyze_events(events)
    print(f"[+] Detected {len(incidents)} actionable security incidents across correlation rules.")

    print("[+] Storing incidents into persistent storage...")
    insert_incidents_batch(incidents)

    log_audit("SeedScript", "SEED_DATA_COMPLETED", f"Ingested {inserted} events, generated {len(incidents)} incidents")
    print("\n========================================================")
    print(f"  SEED COMPLETE! Ingested: {inserted} events | Threats Flagged: {len(incidents)}")
    print("========================================================\n")


if __name__ == "__main__":
    run_seed()
