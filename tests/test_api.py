"""
Unit tests for Flask Application REST API endpoints (app.py).
Tests health check, stats, status transitions, explainability, and error handling.
"""

import json
import pytest
from app import app
from database import init_db, insert_events_batch, insert_incidents_batch, reset_database
from detector import SecurityDetector


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            init_db()
            reset_database(actor="PyTest")
            # Seed a sample event and incident
            events = [
                {"event_id": "TEST-EVT-1", "timestamp": "2026-10-15T10:00:00Z", "username": "test.user", "source_ip": "1.2.3.4", "event_type": "AUTH", "status": "FAILED"},
                {"event_id": "TEST-EVT-2", "timestamp": "2026-10-15T10:01:00Z", "username": "test.user", "source_ip": "1.2.3.4", "event_type": "AUTH", "status": "FAILED"},
                {"event_id": "TEST-EVT-3", "timestamp": "2026-10-15T10:02:00Z", "username": "test.user", "source_ip": "1.2.3.4", "event_type": "AUTH", "status": "FAILED"},
                {"event_id": "TEST-EVT-4", "timestamp": "2026-10-15T10:03:00Z", "username": "test.user", "source_ip": "1.2.3.4", "event_type": "AUTH", "status": "FAILED"},
            ]
            insert_events_batch(events)
            detector = SecurityDetector(thresholds={"failed_attempt_threshold": 3})
            incidents = detector.analyze_events(events)
            insert_incidents_batch(incidents)
        yield client


def test_health_check_endpoint(client):
    """Tests /health endpoint returns 200 and healthy system state."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["database_connected"] is True


def test_dashboard_stats_endpoint(client):
    """Tests /api/stats returns actual numbers from database."""
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.get_json()
    assert "total_events" in stats
    assert stats["total_events"] >= 4
    assert stats["failed_logins"] >= 4
    assert stats["total_incidents"] >= 1


def test_incidents_listing_and_filtering(client):
    """Tests /api/incidents returns paginated incident array."""
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.get_json()
    assert "incidents" in data
    assert len(data["incidents"]) >= 1
    assert data["total"] >= 1


def test_incident_status_update(client):
    """Tests /api/incidents/<id>/status transitions status and prevents invalid transitions."""
    list_res = client.get("/api/incidents")
    incident_id = list_res.get_json()["incidents"][0]["incident_id"]

    # Valid update
    update_res = client.post(
        f"/api/incidents/{incident_id}/status",
        data=json.dumps({"status": "Investigating"}),
        content_type="application/json",
    )
    assert update_res.status_code == 200
    assert update_res.get_json()["new_status"] == "Investigating"

    # Invalid status
    invalid_res = client.post(
        f"/api/incidents/{incident_id}/status",
        data=json.dumps({"status": "INVALID_STATE"}),
        content_type="application/json",
    )
    assert invalid_res.status_code == 400


def test_incident_explainability_endpoint(client):
    """Tests /api/incidents/<id>/explain returns explainable SOC reasoning without external API keys."""
    list_res = client.get("/api/incidents")
    incident_id = list_res.get_json()["incidents"][0]["incident_id"]

    res = client.get(f"/api/incidents/{incident_id}/explain")
    assert res.status_code == 200
    data = res.get_json()
    assert "why_flagged" in data
    assert "investigation_checklist" in data
    assert "mitre_mapping" in data
    assert "technique" in data["mitre_mapping"]


def test_csv_export_endpoint(client):
    """Tests /api/export returns a valid downloadable CSV response."""
    res = client.get("/api/export?type=incidents")
    assert res.status_code == 200
    assert res.mimetype == "text/csv"
    assert b"incident_id" in res.data
