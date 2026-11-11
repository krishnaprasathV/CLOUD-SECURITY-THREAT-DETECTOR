"""
Unit tests for Data Engineering ETL pipeline (etl.py).
Tests schema validation, normalization, deduplication, and malformed handling.
"""

import pytest
from etl import LogETLPipeline


@pytest.fixture
def etl():
    return LogETLPipeline()


def test_valid_csv_processing(etl):
    """Verifies that a valid CSV is correctly parsed and transformed."""
    csv_text = """timestamp,username,source_ip,event_type,status
2026-10-15 10:00:00,alice,192.168.1.1,AUTHENTICATION,SUCCESS
2026-10-15 10:05:00,bob,192.168.1.2,AUTHENTICATION,FAILED
"""
    res = etl.process_csv_stream(csv_text)
    assert res["success"] is True
    assert res["total_rows"] == 2
    assert len(res["valid_records"]) == 2
    assert res["metrics"]["success_logins"] == 1
    assert res["metrics"]["failed_logins"] == 1


def test_missing_required_columns(etl):
    """Verifies that a CSV missing required columns returns schema mismatch error."""
    csv_text = """random_col,another_col
val1,val2
"""
    res = etl.process_csv_stream(csv_text)
    assert res["success"] is False
    assert "Schema mismatch" in res["error"]


def test_timestamp_normalization(etl):
    """Verifies that diverse timestamp representations are normalized to UTC ISO-8601."""
    # 1. Standard datetime
    iso1, valid1 = etl.normalize_timestamp("2026-10-15 14:30:00")
    assert valid1 is True
    assert "2026-10-15" in iso1

    # 2. ISO with Z
    iso2, valid2 = etl.normalize_timestamp("2026-10-15T14:30:00Z")
    assert valid2 is True

    # 3. Unix epoch
    iso3, valid3 = etl.normalize_timestamp("1792072200")
    assert valid3 is True


def test_ip_validation(etl):
    """Verifies IPv4 syntax validation."""
    assert etl.validate_ip("192.168.1.1") is True
    assert etl.validate_ip("8.8.8.8") is True
    assert etl.validate_ip("999.999.999.999") is False
    assert etl.validate_ip("not_an_ip") is False
    assert etl.validate_ip("") is False


def test_duplicate_row_removal(etl):
    """Verifies that identical authentication rows are deduplicated."""
    csv_text = """timestamp,username,source_ip,event_type,status
2026-10-15 10:00:00,alice,192.168.1.1,AUTHENTICATION,SUCCESS
2026-10-15 10:00:00,alice,192.168.1.1,AUTHENTICATION,SUCCESS
"""
    res = etl.process_csv_stream(csv_text)
    assert res["success"] is True
    assert res["metrics"]["total_extracted"] == 2
    assert res["metrics"]["deduplicated_count"] == 1
    assert len(res["valid_records"]) == 1
