"""
Data Engineering ETL Pipeline for Cloud Security Threat Detector.
Maps to Wipro CPPE Module 2 (Data Engineering).
Handles ingestion, schema validation, timestamp normalization,
deduplication, aggregations, and export.
"""

import csv
import io
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
import pandas as pd


class LogETLPipeline:
    """ETL Pipeline for security authentication and access logs."""

    REQUIRED_COLUMNS = {"timestamp", "username", "source_ip", "event_type", "status"}
    OPTIONAL_COLUMNS = {"user_agent", "service_name", "city", "country", "event_id"}

    @staticmethod
    def normalize_timestamp(raw_ts: Any) -> Tuple[str, bool]:
        """
        Normalizes varying timestamp formats into UTC ISO-8601.
        Returns: (normalized_iso_str, is_valid)
        """
        if raw_ts is None or pd.isna(raw_ts):
            return datetime.now(timezone.utc).isoformat(), False

        raw_str = str(raw_ts).strip()
        if not raw_str:
            return datetime.now(timezone.utc).isoformat(), False

        # 1. Unix epoch (seconds or milliseconds)
        if raw_str.replace(".", "").isdigit():
            try:
                val = float(raw_str)
                if val > 1e11:  # Milliseconds
                    val /= 1000.0
                dt = datetime.fromtimestamp(val, tz=timezone.utc)
                return dt.isoformat(), True
            except Exception:
                pass

        # 2. Common datetime formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
            "%Y/%m/%d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(raw_str.replace("Z", ""), fmt.replace("Z", ""))
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat(), True
            except ValueError:
                continue

        # 3. Fallback: Pandas parser
        try:
            dt = pd.to_datetime(raw_str, utc=True)
            if not pd.isna(dt):
                return dt.isoformat(), True
        except Exception:
            pass

        return raw_str, False

    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        """Validates IPv4 string format."""
        if not ip_str or not isinstance(ip_str, str):
            return False
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(pattern, ip_str.strip()))

    def process_csv_stream(self, file_content: str) -> Dict[str, Any]:
        """
        Executes complete ETL pipeline on raw CSV text:
        Extract -> Transform -> Validate -> Clean -> Aggregate -> Load ready.
        """
        try:
            # Step 1: Extract (Read CSV with pandas)
            df = pd.read_csv(io.StringIO(file_content), skipinitialspace=True, dtype=str)
        except Exception as e:
            return {
                "success": False,
                "error": f"CSV Extraction failed: {str(e)}",
                "total_rows": 0,
                "valid_records": [],
                "malformed_count": 0,
                "metrics": {},
            }

        # Normalize column headers (lowercase, trim)
        df.columns = [c.strip().lower() for c in df.columns]

        # Verify required schema
        missing_cols = self.REQUIRED_COLUMNS - set(df.columns)
        if missing_cols:
            return {
                "success": False,
                "error": f"Schema mismatch! Missing required columns: {', '.join(missing_cols)}",
                "total_rows": len(df),
                "valid_records": [],
                "malformed_count": len(df),
                "metrics": {},
            }

        # Step 2: Transform & Clean
        total_raw = len(df)
        cleaned_records: List[Dict[str, Any]] = []
        malformed_count = 0

        # Fill optional columns with defaults
        if "user_agent" not in df.columns:
            df["user_agent"] = "Unknown Agent"
        if "service_name" not in df.columns:
            df["service_name"] = "AWS_CONSOLE"
        if "city" not in df.columns:
            df["city"] = "Unknown"
        if "country" not in df.columns:
            df["country"] = "Unknown"
        if "event_id" not in df.columns:
            df["event_id"] = None

        df = df.fillna("")

        for idx, row in df.iterrows():
            raw_ts = row["timestamp"]
            norm_ts, ts_valid = self.normalize_timestamp(raw_ts)

            username = str(row["username"]).strip()
            source_ip = str(row["source_ip"]).strip()
            status = str(row["status"]).strip().upper()
            event_type = str(row["event_type"]).strip().upper()

            # Malformed flag
            is_malformed = False
            if not ts_valid or not self.validate_ip(source_ip) or not username or username == "nan":
                is_malformed = True
                malformed_count += 1

            # Standardize status
            if status in ("SUCCESS", "PASS", "ALLOWED", "OK", "200"):
                clean_status = "SUCCESS"
            else:
                clean_status = "FAILED"

            event_id = row["event_id"] if row["event_id"] else f"EVT-{idx+1:06d}-{abs(hash(f'{username}-{norm_ts}')) % 100000}"

            record = {
                "event_id": str(event_id),
                "timestamp": norm_ts,
                "username": username if username else "UNKNOWN",
                "source_ip": source_ip if source_ip else "0.0.0.0",
                "event_type": event_type if event_type else "AUTHENTICATION",
                "status": clean_status,
                "user_agent": str(row["user_agent"]).strip() or "Standard Client",
                "service_name": str(row["service_name"]).strip() or "AWS_CONSOLE",
                "city": str(row["city"]).strip() or "Unknown",
                "country": str(row["country"]).strip() or "Unknown",
                "is_malformed": is_malformed,
            }
            cleaned_records.append(record)

        # Step 3: Deduplication
        clean_df = pd.DataFrame(cleaned_records)
        dedup_subset = ["timestamp", "username", "source_ip", "event_type", "status"]
        initial_len = len(clean_df)
        clean_df = clean_df.drop_duplicates(subset=dedup_subset)
        dedup_dropped = initial_len - len(clean_df)
        final_records = clean_df.to_dict(orient="records")

        # Step 4: Summary aggregations (CPPE Module 2 analytics)
        success_count = int((clean_df["status"] == "SUCCESS").sum())
        failed_count = int((clean_df["status"] == "FAILED").sum())
        unique_users = int(clean_df["username"].nunique())
        unique_ips = int(clean_df["source_ip"].nunique())

        metrics = {
            "total_extracted": total_raw,
            "deduplicated_count": dedup_dropped,
            "malformed_count": malformed_count,
            "valid_processed": len(final_records),
            "success_logins": success_count,
            "failed_logins": failed_count,
            "unique_users": unique_users,
            "unique_ips": unique_ips,
        }

        return {
            "success": True,
            "total_rows": total_raw,
            "valid_records": final_records,
            "malformed_count": malformed_count,
            "metrics": metrics,
        }

    @staticmethod
    def export_incidents_to_csv(incidents: List[Dict[str, Any]]) -> str:
        """Converts analyzed incidents list into a formatted CSV string."""
        output = io.StringIO()
        fieldnames = [
            "incident_id",
            "title",
            "rule_id",
            "rule_name",
            "severity",
            "risk_score",
            "username",
            "source_ip",
            "attempt_count",
            "time_window_start",
            "time_window_end",
            "status",
            "created_at",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for inc in incidents:
            writer.writerow(inc)

        return output.getvalue()
