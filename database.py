"""
Database persistence module for Cloud Security Threat Detector.
Uses SQLite with parameterized SQL queries for injection resistance.
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from config import Config


def get_db_connection() -> sqlite3.Connection:
    """Creates a database connection with row factory enabled."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db():
    """Initializes database tables, indexes, and default settings."""
    Config.ensure_directories()
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Security Ingested Events
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                user_agent TEXT,
                service_name TEXT DEFAULT 'AWS_CONSOLE',
                city TEXT DEFAULT 'Unknown',
                country TEXT DEFAULT 'Unknown',
                is_malformed INTEGER DEFAULT 0,
                raw_data TEXT,
                created_at TEXT NOT NULL
            );
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_user ON security_events(username);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(source_ip);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_status ON security_events(status);"
        )

        # 2. Security Incidents / Alerts
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attempt_count INTEGER NOT NULL,
                time_window_start TEXT,
                time_window_end TEXT,
                evidence TEXT,
                recommendations TEXT,
                status TEXT DEFAULT 'New',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_score ON incidents(risk_score);"
        )

        # 3. Application Security Audit Logs
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT
            );
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp);"
        )

        # 4. System Settings (Risk thresholds, weights)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS system_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL,
                description TEXT,
                updated_at TEXT NOT NULL
            );
        """
        )

        # Seed default settings if empty
        defaults = [
            ("failed_attempt_threshold", str(Config.DEFAULT_FAILED_ATTEMPT_THRESHOLD), "Failed attempts required to trigger brute force alert"),
            ("time_window_minutes", str(Config.DEFAULT_TIME_WINDOW_MINUTES), "Time window in minutes for correlative detection"),
            ("spray_user_count", str(Config.DEFAULT_SPRAY_USER_COUNT), "Distinct usernames targeted from one IP for spray alert"),
            ("velocity_threshold", str(Config.DEFAULT_VELOCITY_THRESHOLD), "Total requests in short window indicating velocity spike"),
            ("aws_offline_mode", "true" if Config.AWS_OFFLINE_MODE else "false", "Run in offline SOC mode without calling active AWS APIs"),
            ("llm_provider", Config.LLM_PROVIDER, "Engine for incident analysis (local_rule_based or external)")
        ]

        now_iso = datetime.now(timezone.utc).isoformat()
        for key, val, desc in defaults:
            cursor.execute(
                """
                INSERT OR IGNORE INTO system_settings (setting_key, setting_value, description, updated_at)
                VALUES (?, ?, ?, ?)
            """,
                (key, val, desc, now_iso),
            )

        conn.commit()


def log_audit(actor: str, action: str, details: str, ip_address: str = "127.0.0.1"):
    """Appends an event to the security audit trail."""
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (timestamp, actor, action, details, ip_address)
                VALUES (?, ?, ?, ?, ?)
            """,
                (now_iso, actor, action, details, ip_address),
            )
            conn.commit()
    except Exception as e:
        print(f"[AUDIT LOG FAILURE] Could not record audit log: {e}")


def insert_events_batch(events: List[Dict[str, Any]]) -> int:
    """Inserts a batch of parsed security events using parameterized queries."""
    if not events:
        return 0

    now_iso = datetime.now(timezone.utc).isoformat()
    inserted = 0

    with get_db_connection() as conn:
        cursor = conn.cursor()
        for ev in events:
            try:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO security_events (
                        event_id, timestamp, username, source_ip, event_type, status,
                        user_agent, service_name, city, country, is_malformed, raw_data, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        ev.get("event_id"),
                        ev.get("timestamp"),
                        ev.get("username", "UNKNOWN"),
                        ev.get("source_ip", "0.0.0.0"),
                        ev.get("event_type", "AUTHENTICATION"),
                        ev.get("status", "FAILED"),
                        ev.get("user_agent", "Mozilla/5.0"),
                        ev.get("service_name", "AWS_CONSOLE"),
                        ev.get("city", "Unknown"),
                        ev.get("country", "Unknown"),
                        1 if ev.get("is_malformed") else 0,
                        json.dumps(ev),
                        now_iso,
                    ),
                )
                if cursor.rowcount > 0:
                    inserted += 1
            except Exception as e:
                print(f"[DB ERROR] Error inserting event {ev.get('event_id')}: {e}")

        conn.commit()
    return inserted


def insert_incidents_batch(incidents: List[Dict[str, Any]]) -> int:
    """Inserts or updates security incidents."""
    if not incidents:
        return 0

    now_iso = datetime.now(timezone.utc).isoformat()
    inserted = 0

    with get_db_connection() as conn:
        cursor = conn.cursor()
        for inc in incidents:
            evidence_str = (
                json.dumps(inc.get("evidence", []), default=str)
                if isinstance(inc.get("evidence"), (list, dict))
                else str(inc.get("evidence", ""))
            )
            recs_str = (
                json.dumps(inc.get("recommendations", []), default=str)
                if isinstance(inc.get("recommendations"), (list, dict))
                else str(inc.get("recommendations", ""))
            )

            try:
                cursor.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, title, rule_id, rule_name, severity, risk_score,
                        username, source_ip, attempt_count, time_window_start, time_window_end,
                        evidence, recommendations, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        risk_score = excluded.risk_score,
                        severity = excluded.severity,
                        attempt_count = excluded.attempt_count,
                        evidence = excluded.evidence,
                        updated_at = excluded.updated_at
                """,
                    (
                        inc.get("incident_id"),
                        inc.get("title"),
                        inc.get("rule_id"),
                        inc.get("rule_name"),
                        inc.get("severity"),
                        inc.get("risk_score"),
                        inc.get("username"),
                        inc.get("source_ip"),
                        inc.get("attempt_count", 1),
                        inc.get("time_window_start"),
                        inc.get("time_window_end"),
                        evidence_str,
                        recs_str,
                        inc.get("status", "New"),
                        now_iso,
                        now_iso,
                    ),
                )
                inserted += 1
            except Exception as e:
                print(f"[DB ERROR] Error inserting incident {inc.get('incident_id')}: {e}")

        conn.commit()
    return inserted


def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "risk_score",
    sort_order: str = "DESC",
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Retrieves filtered, sorted, and paginated incident records."""
    allowed_sort_fields = {"risk_score", "created_at", "severity", "attempt_count", "username", "source_ip"}
    if sort_by not in allowed_sort_fields:
        sort_by = "risk_score"
    sort_order = "DESC" if sort_order.upper() == "DESC" else "ASC"

    query = "SELECT * FROM incidents WHERE 1=1"
    params: List[Any] = []

    if status and status.lower() != "all":
        query += " AND status = ?"
        params.append(status)

    if severity and severity.lower() != "all":
        query += " AND severity = ?"
        params.append(severity.upper())

    if search:
        query += " AND (incident_id LIKE ? OR username LIKE ? OR source_ip LIKE ? OR rule_name LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])

    # Count total matching
    count_query = f"SELECT COUNT(*) as count FROM ({query})"
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()["count"]

        # Order and pagination
        query += f" ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        incidents_list = []
        for r in rows:
            d = dict(r)
            try:
                d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else []
            except Exception:
                pass
            try:
                d["recommendations"] = json.loads(d["recommendations"]) if d["recommendations"] else []
            except Exception:
                pass
            incidents_list.append(d)

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "incidents": incidents_list,
    }


def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Gets details for a single incident."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else []
        except Exception:
            pass
        try:
            d["recommendations"] = json.loads(d["recommendations"]) if d["recommendations"] else []
        except Exception:
            pass
        return d


def update_incident_status(incident_id: str, new_status: str, actor: str = "SOC Analyst") -> bool:
    """Updates the lifecycle status of an incident (New, Investigating, Resolved)."""
    valid_statuses = {"New", "Investigating", "Resolved"}
    if new_status not in valid_statuses:
        return False

    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE incidents
            SET status = ?, updated_at = ?
            WHERE incident_id = ?
        """,
            (new_status, now_iso, incident_id),
        )
        affected = cursor.rowcount
        conn.commit()

    if affected > 0:
        log_audit(actor, "UPDATE_INCIDENT_STATUS", f"Changed incident {incident_id} status to {new_status}")
        return True
    return False


def get_dashboard_metrics() -> Dict[str, Any]:
    """Calculates all live SOC dashboard KPIs from actual database records."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Total events
        cursor.execute("SELECT COUNT(*) as c FROM security_events")
        total_events = cursor.fetchone()["c"]

        # Successful logins
        cursor.execute("SELECT COUNT(*) as c FROM security_events WHERE status = 'SUCCESS'")
        successful_logins = cursor.fetchone()["c"]

        # Failed logins
        cursor.execute("SELECT COUNT(*) as c FROM security_events WHERE status = 'FAILED'")
        failed_logins = cursor.fetchone()["c"]

        # Total incidents
        cursor.execute("SELECT COUNT(*) as c FROM incidents")
        total_incidents = cursor.fetchone()["c"]

        # Incidents by severity
        cursor.execute(
            """
            SELECT severity, COUNT(*) as count 
            FROM incidents 
            GROUP BY severity
        """
        )
        sev_counts = {r["severity"].upper(): r["count"] for r in cursor.fetchall()}

        # Incidents by status
        cursor.execute(
            """
            SELECT status, COUNT(*) as count 
            FROM incidents 
            GROUP BY status
        """
        )
        status_counts = {r["status"]: r["count"] for r in cursor.fetchall()}

        # Unique entities
        cursor.execute("SELECT COUNT(DISTINCT username) as c FROM security_events")
        unique_users = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(DISTINCT source_ip) as c FROM security_events")
        unique_ips = cursor.fetchone()["c"]

        # Average risk score
        cursor.execute("SELECT AVG(risk_score) as avg_score FROM incidents")
        avg_row = cursor.fetchone()
        avg_risk_score = round(avg_row["avg_score"] or 0, 1)

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "total_incidents": total_incidents,
        "critical_incidents": sev_counts.get("CRITICAL", 0),
        "high_incidents": sev_counts.get("HIGH", 0),
        "medium_incidents": sev_counts.get("MEDIUM", 0),
        "low_incidents": sev_counts.get("LOW", 0),
        "new_incidents": status_counts.get("New", 0),
        "investigating_incidents": status_counts.get("Investigating", 0),
        "resolved_incidents": status_counts.get("Resolved", 0),
        "unique_users": unique_users,
        "unique_ips": unique_ips,
        "avg_risk_score": avg_risk_score,
    }


def get_timeline_data() -> Dict[str, Any]:
    """Generates hourly timeline statistics for events and threats."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Group events by date/hour (extract substring YYYY-MM-DD HH:00)
        cursor.execute(
            """
            SELECT SUBSTR(timestamp, 1, 13) || ':00' as time_bucket,
                   SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success_count,
                   SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
                   COUNT(*) as total_count
            FROM security_events
            WHERE timestamp IS NOT NULL AND timestamp != ''
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
            LIMIT 24
        """
        )
        rows = cursor.fetchall()

        labels = [r["time_bucket"] for r in rows]
        success_series = [r["success_count"] for r in rows]
        failed_series = [r["failed_count"] for r in rows]
        total_series = [r["total_count"] for r in rows]

    return {
        "labels": labels,
        "success": success_series,
        "failed": failed_series,
        "total": total_series,
    }


def get_top_threats() -> Dict[str, Any]:
    """Returns top targeted users and top suspicious IPs."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Top targeted users by failed attempts
        cursor.execute(
            """
            SELECT username, COUNT(*) as failed_attempts,
                   COUNT(DISTINCT source_ip) as distinct_ips
            FROM security_events
            WHERE status = 'FAILED' AND username != 'UNKNOWN'
            GROUP BY username
            ORDER BY failed_attempts DESC
            LIMIT 5
        """
        )
        top_users = [dict(r) for r in cursor.fetchall()]

        # Top suspicious source IPs
        cursor.execute(
            """
            SELECT source_ip, COUNT(*) as attempt_count,
                   COUNT(DISTINCT username) as targeted_users,
                   country
            FROM security_events
            WHERE status = 'FAILED'
            GROUP BY source_ip
            ORDER BY attempt_count DESC
            LIMIT 5
        """
        )
        top_ips = [dict(r) for r in cursor.fetchall()]

    return {
        "top_users": top_users,
        "top_ips": top_ips,
    }


def get_all_events(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Fetches ingested security events."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT event_id, timestamp, username, source_ip, event_type, status, service_name, city, country
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """,
            (limit, offset),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent security audit log entries."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, actor, action, details, ip_address
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """,
            (limit,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_settings() -> Dict[str, str]:
    """Retrieves all configuration settings from the database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT setting_key, setting_value FROM system_settings")
        return {r["setting_key"]: r["setting_value"] for r in cursor.fetchall()}


def update_setting(key: str, value: str, actor: str = "Admin") -> bool:
    """Updates a system setting with audit logging."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE system_settings
            SET setting_value = ?, updated_at = ?
            WHERE setting_key = ?
        """,
            (value, now_iso, key),
        )
        affected = cursor.rowcount
        conn.commit()

    if affected > 0:
        log_audit(actor, "UPDATE_SETTING", f"Updated {key} to {value}")
        return True
    return False


def reset_database(actor: str = "Admin"):
    """Completely resets events and incidents tables for demo purposes."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_events;")
        cursor.execute("DELETE FROM incidents;")
        conn.commit()

    log_audit(actor, "RESET_DATABASE", "Flushed all security events and incident tables")
