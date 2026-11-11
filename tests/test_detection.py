"""
Unit tests for Security Detection Engine (detector.py).
Tests explainable correlation heuristics and risk scoring.
"""

import pytest
from datetime import datetime, timezone
from detector import SecurityDetector


@pytest.fixture
def detector():
    """Provides detector instance with fixed threshold config."""
    return SecurityDetector(
        thresholds={
            "failed_attempt_threshold": 3,
            "time_window_minutes": 15,
            "spray_user_count": 3,
            "velocity_threshold": 5,
            "velocity_window_minutes": 5,
        }
    )


def test_empty_dataset(detector):
    """Verifies that analyzing an empty events list returns an empty incident list without crashing."""
    incidents = detector.analyze_events([])
    assert incidents == []


def test_repeated_failed_logins_brute_force(detector):
    """Tests RULE-001: Repeated failed logins by same user from same IP triggers alert."""
    events = [
        {"timestamp": "2026-10-15T10:00:00Z", "username": "admin", "source_ip": "192.0.2.10", "event_type": "AUTHENTICATION", "status": "FAILED"},
        {"timestamp": "2026-10-15T10:02:00Z", "username": "admin", "source_ip": "192.0.2.10", "event_type": "AUTHENTICATION", "status": "FAILED"},
        {"timestamp": "2026-10-15T10:04:00Z", "username": "admin", "source_ip": "192.0.2.10", "event_type": "AUTHENTICATION", "status": "FAILED"},
    ]
    incidents = detector.analyze_events(events)
    assert len(incidents) >= 1
    bf = next(i for i in incidents if i["rule_id"] == "RULE-001")
    assert bf["username"] == "admin"
    assert bf["source_ip"] == "192.0.2.10"
    assert bf["attempt_count"] == 3
    assert 60 <= bf["risk_score"] <= 100
    assert bf["severity"] in ("HIGH", "CRITICAL")


def test_password_spraying_detection(detector):
    """Tests RULE-002: Single IP targeting >= 3 distinct users triggers password spraying."""
    events = [
        {"timestamp": "2026-10-15T10:00:00Z", "username": "user1", "source_ip": "198.51.100.99", "event_type": "AUTHENTICATION", "status": "FAILED"},
        {"timestamp": "2026-10-15T10:01:00Z", "username": "user2", "source_ip": "198.51.100.99", "event_type": "AUTHENTICATION", "status": "FAILED"},
        {"timestamp": "2026-10-15T10:02:00Z", "username": "user3", "source_ip": "198.51.100.99", "event_type": "AUTHENTICATION", "status": "FAILED"},
    ]
    incidents = detector.analyze_events(events)
    spray = next(i for i in incidents if i["rule_id"] == "RULE-002")
    assert spray["source_ip"] == "198.51.100.99"
    assert spray["attempt_count"] == 3
    assert spray["severity"] in ("HIGH", "CRITICAL")


def test_compromised_account_post_bruteforce(detector):
    """Tests RULE-003: Failed attempts directly followed by success triggers critical breach alert."""
    events = [
        {"timestamp": "2026-10-15T10:00:00Z", "username": "victim.user", "source_ip": "203.0.113.5", "event_type": "AUTHENTICATION", "status": "FAILED"},
        {"timestamp": "2026-10-15T10:01:00Z", "username": "victim.user", "source_ip": "203.0.113.5", "event_type": "AUTHENTICATION", "status": "FAILED"},
        {"timestamp": "2026-10-15T10:02:00Z", "username": "victim.user", "source_ip": "203.0.113.5", "event_type": "AUTHENTICATION", "status": "FAILED"},
        {"timestamp": "2026-10-15T10:03:00Z", "username": "victim.user", "source_ip": "203.0.113.5", "event_type": "AUTHENTICATION", "status": "SUCCESS"},
    ]
    incidents = detector.analyze_events(events)
    comp = next(i for i in incidents if i["rule_id"] == "RULE-003")
    assert comp["username"] == "victim.user"
    assert comp["severity"] == "CRITICAL"
    assert comp["risk_score"] >= 90


def test_velocity_spike_detection(detector):
    """Tests RULE-004: Rapid authentication bursts trigger velocity spike."""
    events = [
        {"timestamp": f"2026-10-15T10:0{i}:00Z", "username": f"u{i}", "source_ip": "192.0.2.77", "event_type": "AUTHENTICATION", "status": "FAILED"}
        for i in range(6)
    ]
    incidents = detector.analyze_events(events)
    vel = next(i for i in incidents if i["rule_id"] == "RULE-004")
    assert vel["source_ip"] == "192.0.2.77"
    assert vel["attempt_count"] >= 5


def test_risk_score_calculation(detector):
    """Verifies that risk score calculation remains bounded between 0 and 100."""
    score, sev = detector._calculate_risk_score(base_score=70, attempt_count=100, is_privileged_user=True)
    assert 0 <= score <= 100
    assert sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
