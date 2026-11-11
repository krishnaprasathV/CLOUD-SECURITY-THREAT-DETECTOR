"""
Security Detection Engine for Cloud Security Threat Detector.
Implements explainable, rule-based cybersecurity correlation heuristics.
Calculates transparent risk scores (0-100) and actionable SOC recommendations.
"""

import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple
import pandas as pd

from config import Config
from database import get_settings


class SecurityDetector:
    """Detection engine for security event log correlation."""

    def __init__(self, thresholds: Dict[str, Any] = None):
        """Initializes detector with configurable thresholds."""
        db_settings = {}
        try:
            db_settings = get_settings()
        except Exception:
            pass

        self.failed_attempt_threshold = int(
            (thresholds or {}).get(
                "failed_attempt_threshold",
                db_settings.get("failed_attempt_threshold", Config.DEFAULT_FAILED_ATTEMPT_THRESHOLD),
            )
        )
        self.time_window_minutes = int(
            (thresholds or {}).get(
                "time_window_minutes",
                db_settings.get("time_window_minutes", Config.DEFAULT_TIME_WINDOW_MINUTES),
            )
        )
        self.spray_user_count = int(
            (thresholds or {}).get(
                "spray_user_count",
                db_settings.get("spray_user_count", Config.DEFAULT_SPRAY_USER_COUNT),
            )
        )
        self.velocity_threshold = int(
            (thresholds or {}).get(
                "velocity_threshold",
                db_settings.get("velocity_threshold", Config.DEFAULT_VELOCITY_THRESHOLD),
            )
        )
        self.velocity_window_minutes = int(
            (thresholds or {}).get(
                "velocity_window_minutes",
                db_settings.get("velocity_window_minutes", Config.DEFAULT_VELOCITY_WINDOW_MINUTES),
            )
        )

    def analyze_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs all correlation rules over the ingested events list.
        Returns a list of structured security incidents.
        """
        if not events:
            return []

        df = pd.DataFrame(events)

        # Standardize DataFrame columns
        for col in ["timestamp", "username", "source_ip", "status", "event_type", "city", "country"]:
            if col not in df.columns:
                df[col] = "UNKNOWN"

        # Convert timestamps safely to datetime objects
        df["dt"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        # Drop rows where datetime completely failed to parse for time-based rules
        valid_df = df.dropna(subset=["dt"]).sort_values("dt").copy()

        incidents: List[Dict[str, Any]] = []

        # Rule 1: Brute Force Authentication (Same user + Same IP)
        incidents.extend(self._detect_brute_force(valid_df))

        # Rule 2: Password Spraying (Single IP -> Multiple distinct Users)
        incidents.extend(self._detect_password_spraying(valid_df))

        # Rule 3: Account Compromise (Repeated Failures followed by Success)
        incidents.extend(self._detect_compromised_account(valid_df))

        # Rule 4: Anomalous Velocity Spike (High request frequency in short burst)
        incidents.extend(self._detect_velocity_spike(valid_df))

        # Rule 5: Malformed Records / Header Tampering
        incidents.extend(self._detect_malformed_records(df))

        # Rule 6: Impossible Travel / Multi-Region Geographic Anomaly
        incidents.extend(self._detect_impossible_travel(valid_df))

        return incidents

    def _calculate_risk_score(
        self,
        base_score: int,
        attempt_count: int,
        is_privileged_user: bool = False,
        velocity_factor: float = 1.0,
    ) -> Tuple[int, str]:
        """
        Calculates explainable risk score (0-100) and severity level.
        Formula: min(100, Base + LogScale(attempts) + PrivilegedBonus) * velocity
        """
        multiplier = math.log2(max(attempt_count, 1)) * 4.0
        bonus = 15 if is_privileged_user else 0
        raw_score = (base_score + multiplier + bonus) * velocity_factor
        score = int(max(0, min(100, round(raw_score))))

        if score >= 85:
            severity = "CRITICAL"
        elif score >= 65:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return score, severity

    def _is_privileged_user(self, username: str) -> bool:
        """Checks if account matches high-value or privileged keywords."""
        privileged_keywords = {"root", "admin", "administrator", "devops", "cloudadmin", "aws_root", "finance"}
        return any(keyword in str(username).lower() for keyword in privileged_keywords)

    def _detect_brute_force(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detects repeated failed logins by the same user from the same IP."""
        incidents = []
        failed_df = df[df["status"] == "FAILED"]

        grouped = failed_df.groupby(["username", "source_ip"])
        for (username, source_ip), group in grouped:
            if len(group) < self.failed_attempt_threshold:
                continue

            # Sliding window check within time_window_minutes
            group_sorted = group.sort_values("dt").reset_index(drop=True)
            for i in range(len(group_sorted)):
                start_time = group_sorted.loc[i, "dt"]
                end_window = start_time + timedelta(minutes=self.time_window_minutes)
                window_matches = group_sorted[(group_sorted["dt"] >= start_time) & (group_sorted["dt"] <= end_window)]

                if len(window_matches) >= self.failed_attempt_threshold:
                    attempts = len(window_matches)
                    is_priv = self._is_privileged_user(username)
                    score, severity = self._calculate_risk_score(base_score=68, attempt_count=attempts, is_privileged_user=is_priv)

                    incident_id = f"INC-BF-{abs(hash(f'{username}-{source_ip}-{start_time}')) % 100000:05d}"
                    evidence = [
                        {
                            "timestamp": row["timestamp"],
                            "event_type": row["event_type"],
                            "source_ip": row["source_ip"],
                            "city": row.get("city", "Unknown"),
                            "status": row["status"],
                        }
                        for _, row in window_matches.iterrows()
                    ]

                    incidents.append({
                        "incident_id": incident_id,
                        "title": f"Brute Force Authentication Spike on '{username}'",
                        "rule_id": "RULE-001",
                        "rule_name": "Repeated Failed Logins (Brute Force)",
                        "severity": severity,
                        "risk_score": score,
                        "username": username,
                        "source_ip": source_ip,
                        "attempt_count": attempts,
                        "time_window_start": window_matches["dt"].min().isoformat(),
                        "time_window_end": window_matches["dt"].max().isoformat(),
                        "evidence": evidence,
                        "recommendations": [
                            "Examine authentication attempts in AWS CloudTrail / Auth logs for this IP.",
                            "Notify the target user to confirm if this activity is authorized.",
                            "If unauthorized, enforce step-up MFA or temporarily disable the compromised credential.",
                            "Inspect WAF/Security Group logs for wider scanning activity originating from this IP.",
                        ],
                        "status": "New",
                    })
                    break  # Avoid duplicate incidents for this entity in the same run

        return incidents

    def _detect_password_spraying(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detects single IP attempting authentication across multiple distinct usernames."""
        incidents = []
        failed_df = df[df["status"] == "FAILED"]

        grouped = failed_df.groupby("source_ip")
        for source_ip, group in grouped:
            unique_users = group["username"].unique()
            if len(unique_users) >= self.spray_user_count:
                attempts = len(group)
                score, severity = self._calculate_risk_score(base_score=75, attempt_count=attempts)
                min_dt = group["dt"].min()
                incident_id = f"INC-SPRAY-{abs(hash(f'{source_ip}-{min_dt}')) % 100000:05d}"
                evidence = [
                    {
                        "timestamp": row["timestamp"],
                        "username": row["username"],
                        "source_ip": row["source_ip"],
                        "status": row["status"],
                    }
                    for _, row in group.iterrows()
                ]

                incidents.append({
                    "incident_id": incident_id,
                    "title": f"Password Spray Attack from IP {source_ip}",
                    "rule_id": "RULE-002",
                    "rule_name": "Horizontal Password Spraying",
                    "severity": severity,
                    "risk_score": score,
                    "username": f"Multiple ({len(unique_users)} accounts: {', '.join(unique_users[:3])}...)",
                    "source_ip": source_ip,
                    "attempt_count": attempts,
                    "time_window_start": group["dt"].min().isoformat(),
                    "time_window_end": group["dt"].max().isoformat(),
                    "evidence": evidence[:15],  # Cap evidence payload
                    "recommendations": [
                        "Investigate source IP reputation and ISP in Threat Intelligence feeds.",
                        "Verify whether any targeted user had an associated successful login.",
                        "Audit AWS IAM password policies for compliance with NIST 800-63B standards.",
                        "Review rate-limiting thresholds on the identity provider or login portal.",
                    ],
                    "status": "New",
                })

        return incidents

    def _detect_compromised_account(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detects successful login immediately following consecutive failed attempts."""
        incidents = []
        grouped = df.groupby(["username", "source_ip"])

        for (username, source_ip), group in grouped:
            group_sorted = group.sort_values("dt").reset_index(drop=True)
            consecutive_failures = 0
            failure_rows = []

            for _, row in group_sorted.iterrows():
                if row["status"] == "FAILED":
                    consecutive_failures += 1
                    failure_rows.append(row)
                elif row["status"] == "SUCCESS":
                    if consecutive_failures >= 3:
                        # Critical Alert: Compromise after brute-force
                        score, severity = self._calculate_risk_score(
                            base_score=90, attempt_count=consecutive_failures + 1, is_privileged_user=self._is_privileged_user(username)
                        )
                        row_dt = row["dt"]
                        incident_id = f"INC-COMP-{abs(hash(f'{username}-{source_ip}-{row_dt}')) % 100000:05d}"

                        evidence = [
                            {"timestamp": f["timestamp"], "status": "FAILED", "event_type": f["event_type"]}
                            for f in failure_rows[-5:]
                        ]
                        evidence.append({"timestamp": row["timestamp"], "status": "SUCCESS (BREACH INDICATOR)", "event_type": row["event_type"]})

                        incidents.append({
                            "incident_id": incident_id,
                            "title": f"Potential Account Breach: Successful Auth after {consecutive_failures} Failures",
                            "rule_id": "RULE-003",
                            "rule_name": "Brute Force Followed by Successful Login",
                            "severity": "CRITICAL",
                            "risk_score": max(score, 92),
                            "username": username,
                            "source_ip": source_ip,
                            "attempt_count": consecutive_failures + 1,
                            "time_window_start": failure_rows[0]["dt"].isoformat(),
                            "time_window_end": row["dt"].isoformat(),
                            "evidence": evidence,
                            "recommendations": [
                                "IMMEDIATE ACTION: Revoke active session tokens and invalidate AWS STS temporary credentials.",
                                "Force password reset and rotate IAM access keys immediately.",
                                "Isolate any EC2 instances or resources accessed by this user session.",
                                "Audit CloudWatch logs and CloudTrail event history for post-login lateral movement.",
                            ],
                            "status": "New",
                        })
                        break
                    # Reset failure count if legitimate success
                    consecutive_failures = 0
                    failure_rows = []

        return incidents

    def _detect_velocity_spike(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detects unusually high authentication request velocity within a short time window."""
        incidents = []
        grouped = df.groupby("source_ip")

        for source_ip, group in grouped:
            group_sorted = group.sort_values("dt").reset_index(drop=True)
            for i in range(len(group_sorted)):
                start_time = group_sorted.loc[i, "dt"]
                end_time = start_time + timedelta(minutes=self.velocity_window_minutes)
                window_df = group_sorted[(group_sorted["dt"] >= start_time) & (group_sorted["dt"] <= end_time)]

                if len(window_df) >= self.velocity_threshold:
                    attempts = len(window_df)
                    score, severity = self._calculate_risk_score(base_score=70, attempt_count=attempts, velocity_factor=1.1)

                    incident_id = f"INC-VEL-{abs(hash(f'{source_ip}-{start_time}')) % 100000:05d}"
                    incidents.append({
                        "incident_id": incident_id,
                        "title": f"Abnormal Authentication Velocity ({attempts} requests / {self.velocity_window_minutes}m) from {source_ip}",
                        "rule_id": "RULE-004",
                        "rule_name": "High Velocity Authentication Spike (DoS / Stuffing)",
                        "severity": severity,
                        "risk_score": score,
                        "username": f"{window_df['username'].nunique()} targeted users",
                        "source_ip": source_ip,
                        "attempt_count": attempts,
                        "time_window_start": window_df["dt"].min().isoformat(),
                        "time_window_end": window_df["dt"].max().isoformat(),
                        "evidence": [
                            {"timestamp": r["timestamp"], "user": r["username"], "status": r["status"]}
                            for _, r in window_df.head(10).iterrows()
                        ],
                        "recommendations": [
                            "Inspect web server / API Gateway rate-limit and throttled metrics.",
                            "Verify if automated bots or load-testing scripts are executing against the endpoint.",
                            "Apply WAF rate-limiting rule (e.g. AWS WAF Rate-based Rule) for the source IP CIDR.",
                        ],
                        "status": "New",
                    })
                    break

        return incidents

    def _detect_malformed_records(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        incidents = []
        if "is_malformed" not in df.columns:
            return incidents

        malformed_df = df[df["is_malformed"] == 1]

        if not malformed_df.empty:
            count = len(malformed_df)
            incident_id = f"INC-MALF-{uuid.uuid4().hex[:5]}"
            incidents.append({
                "incident_id": incident_id,
                "title": f"Data Integrity Alert: {count} Corrupt / Malformed Security Records",
                "rule_id": "RULE-005",
                "rule_name": "Malformed Log Record / Tamper Alert",
                "severity": "LOW" if count < 3 else "MEDIUM",
                "risk_score": min(count * 15 + 25, 60),
                "username": "N/A (Header or Format Error)",
                "source_ip": "0.0.0.0",
                "attempt_count": count,
                "time_window_start": datetime.now(timezone.utc).isoformat(),
                "time_window_end": datetime.now(timezone.utc).isoformat(),
                "evidence": [
                    {
                        "sample": {
                            k: (str(v) if pd.notna(v) else None)
                            for k, v in row.to_dict().items()
                            if k != "dt"
                        }
                    }
                    for _, row in malformed_df.head(5).iterrows()
                ],
                "recommendations": [
                    "Inspect logging shipper (e.g., CloudWatch Agent, FluentBit) for serialization issues.",
                    "Verify file encoding and CSV schema formatting.",
                    "Check if log tampering or injection characters exist in raw security streams.",
                ],
                "status": "New",
            })

        return incidents

    def _detect_impossible_travel(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detects logins for the same user from different countries in an impossible time window (< 60m)."""
        incidents = []
        users_with_country = df[(df["country"] != "Unknown") & (df["country"] != "") & (df["status"] == "SUCCESS")]
        grouped = users_with_country.groupby("username")

        for username, group in grouped:
            if len(group) < 2:
                continue

            group_sorted = group.sort_values("dt").reset_index(drop=True)
            for i in range(len(group_sorted) - 1):
                first_event = group_sorted.iloc[i]
                second_event = group_sorted.iloc[i + 1]

                time_diff_minutes = (second_event["dt"] - first_event["dt"]).total_seconds() / 60.0

                # If country changed and occurred in less than 60 minutes
                if first_event["country"] != second_event["country"] and 0 <= time_diff_minutes < 60:
                    first_dt = first_event["dt"]
                    incident_id = f"INC-TRAV-{abs(hash(f'{username}-{first_dt}')) % 100000:05d}"
                    score = 88
                    incidents.append({
                        "incident_id": incident_id,
                        "title": f"Impossible Travel Anomaly for User '{username}' ({first_event['country']} -> {second_event['country']})",
                        "rule_id": "RULE-006",
                        "rule_name": "Geographic Velocity Anomaly (Impossible Travel)",
                        "severity": "CRITICAL",
                        "risk_score": score,
                        "username": username,
                        "source_ip": f"{first_event['source_ip']} / {second_event['source_ip']}",
                        "attempt_count": 2,
                        "time_window_start": first_event["dt"].isoformat(),
                        "time_window_end": second_event["dt"].isoformat(),
                        "evidence": [
                            {
                                "timestamp": first_event["timestamp"],
                                "country": first_event["country"],
                                "city": first_event.get("city", "Unknown"),
                                "ip": first_event["source_ip"],
                            },
                            {
                                "timestamp": second_event["timestamp"],
                                "country": second_event["country"],
                                "city": second_event.get("city", "Unknown"),
                                "ip": second_event["source_ip"],
                                "transit_time_minutes": round(time_diff_minutes, 1),
                            },
                        ],
                        "recommendations": [
                            "Immediate outreach to user via out-of-band channel (phone/Slack) to verify location.",
                            "Check for commercial VPN or corporate proxy usage.",
                            "Terminate both active sessions and enforce hardware token MFA re-authentication.",
                        ],
                        "status": "New",
                    })
                    break

        return incidents
