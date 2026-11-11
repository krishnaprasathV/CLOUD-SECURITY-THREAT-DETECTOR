"""
Main Flask Web Application and REST API for Cloud Security Threat Detector.
Maps to Wipro CPPE Module 1 (Cloud Product Engineering) and Module 4 (Security).
"""

import io
import os
from typing import Any, Dict
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from ai_explain import IncidentExplainer
from aws_integration import AWSIntegrationService
from config import Config
from database import (
    get_all_events,
    get_audit_logs,
    get_dashboard_metrics,
    get_db_connection,
    get_incident_by_id,
    get_incidents,
    get_settings,
    get_timeline_data,
    get_top_threats,
    init_db,
    insert_events_batch,
    insert_incidents_batch,
    log_audit,
    reset_database,
    update_incident_status,
    update_setting,
)
from detector import SecurityDetector
from etl import LogETLPipeline

# Create Flask application
app = Flask(__name__)
app.config.from_object(Config)
Config.ensure_directories()

# Initialize core services
explainer = IncidentExplainer()
aws_service = AWSIntegrationService()

# Ensure database is initialized on startup
with app.app_context():
    init_db()


# -----------------------------------------------------------------------------
# Security Headers Middleware
# -----------------------------------------------------------------------------
@app.after_request
def add_security_headers(response: Response) -> Response:
    """Appends hardened cybersecurity headers to all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# -----------------------------------------------------------------------------
# Error Handling
# -----------------------------------------------------------------------------
@app.errorhandler(400)
def bad_request(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Bad Request", "message": str(error)}), 400
    return render_template("index.html", error=str(error)), 400


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not Found", "message": "The requested resource was not found"}), 404
    return render_template("index.html", error="Resource not found"), 404


@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500
    return render_template("index.html", error="Internal server error"), 500


# -----------------------------------------------------------------------------
# Web Page Routes
# -----------------------------------------------------------------------------
@app.route("/")
def dashboard_view():
    """Renders main SOC monitoring dashboard."""
    stats = get_dashboard_metrics()
    top_threats = get_top_threats()
    recent_incidents = get_incidents(limit=6)["incidents"]
    aws_status = aws_service.get_cloud_status()
    return render_template(
        "index.html",
        stats=stats,
        top_threats=top_threats,
        recent_incidents=recent_incidents,
        aws_status=aws_status,
        active_page="dashboard",
    )


@app.route("/incidents")
def incidents_view():
    """Renders incident response queue with filters and pagination."""
    return render_template("incidents.html", active_page="incidents")


@app.route("/upload")
def upload_view():
    """Renders data ingestion and ETL pipeline controls."""
    stats = get_dashboard_metrics()
    return render_template("upload.html", stats=stats, active_page="upload")


@app.route("/audit")
def audit_view():
    """Renders security audit trail page."""
    logs = get_audit_logs(limit=100)
    return render_template("audit.html", logs=logs, active_page="audit")


@app.route("/settings")
def settings_view():
    """Renders configuration and detection threshold tuning page."""
    current_settings = get_settings()
    aws_status = aws_service.get_cloud_status()
    return render_template(
        "settings.html",
        settings=current_settings,
        aws_status=aws_status,
        active_page="settings",
    )


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health_check():
    """System health check endpoint."""
    try:
        with get_db_connection() as conn:
            conn.execute("SELECT 1").fetchone()
        db_healthy = True
    except Exception:
        db_healthy = False

    return jsonify({
        "status": "healthy" if db_healthy else "degraded",
        "service": "Cloud Security Threat Detector",
        "version": "1.0.0",
        "database_connected": db_healthy,
        "aws_mode": "Offline/Simulation" if Config.AWS_OFFLINE_MODE else "Live",
    }), (200 if db_healthy else 503)


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Returns real-time dashboard KPI metrics."""
    stats = get_dashboard_metrics()
    return jsonify(stats)


@app.route("/api/timeline", methods=["GET"])
def api_timeline():
    """Returns chronological timeline metrics for Chart.js."""
    timeline = get_timeline_data()
    return jsonify(timeline)


@app.route("/api/top-threats", methods=["GET"])
def api_top_threats():
    """Returns top attacker IPs and targeted users."""
    top_threats = get_top_threats()
    return jsonify(top_threats)


@app.route("/api/incidents", methods=["GET"])
def api_incidents():
    """
    Retrieves filtered, sorted, paginated incidents.
    Query params: status, severity, search, sort_by, sort_order, page, limit
    """
    status = request.args.get("status")
    severity = request.args.get("severity")
    search = request.args.get("search")
    sort_by = request.args.get("sort_by", "risk_score")
    sort_order = request.args.get("sort_order", "DESC")
    limit = min(int(request.args.get("limit", 20)), 100)
    page = max(int(request.args.get("page", 1)), 1)
    offset = (page - 1) * limit

    data = get_incidents(
        status=status,
        severity=severity,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        limit=limit,
        offset=offset,
    )
    data["page"] = page
    data["total_pages"] = (data["total"] + limit - 1) // limit if data["total"] > 0 else 1
    return jsonify(data)


@app.route("/api/incidents/<incident_id>", methods=["GET"])
def api_incident_detail(incident_id: str):
    """Returns single incident metadata and evidence."""
    inc = get_incident_by_id(incident_id)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(inc)


@app.route("/api/incidents/<incident_id>/explain", methods=["GET"])
def api_incident_explain(incident_id: str):
    """
    Generates explainable SOC analyst reasoning using CPPE Module 3 explainer.
    Works 100% offline with zero external API key requirements.
    """
    inc = get_incident_by_id(incident_id)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404

    explanation = explainer.explain_incident(inc)
    log_audit("SOC Analyst", "GENERATE_AI_EXPLANATION", f"Generated explanation for incident {incident_id}")
    return jsonify(explanation)


@app.route("/api/incidents/<incident_id>/status", methods=["POST"])
def api_update_incident_status(incident_id: str):
    """Updates the workflow status of an incident (New -> Investigating -> Resolved)."""
    payload = request.get_json(silent=True) or {}
    new_status = payload.get("status", "").strip()
    actor = payload.get("actor", "SOC Analyst").strip()

    if new_status not in {"New", "Investigating", "Resolved"}:
        return jsonify({"error": "Invalid status. Allowed values: New, Investigating, Resolved"}), 400

    success = update_incident_status(incident_id, new_status, actor=actor)
    if not success:
        return jsonify({"error": "Incident not found or status unchanged"}), 404

    # Publish CloudWatch metric
    aws_service.publish_threat_metric(f"Incident_{new_status}", 1.0)

    return jsonify({"success": True, "incident_id": incident_id, "new_status": new_status})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """
    Handles CSV file upload, executes ETL pipeline, runs detection rules,
    and returns processing metrics.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith(".csv"):
        return jsonify({"error": "Invalid file format. Only CSV files are allowed."}), 400

    try:
        content = file.read().decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"error": f"Failed to read file content: {str(e)}"}), 400

    # Execute CPPE Module 2 ETL Pipeline
    etl = LogETLPipeline()
    etl_result = etl.process_csv_stream(content)

    if not etl_result["success"]:
        return jsonify({"error": etl_result.get("error")}), 400

    records = etl_result["valid_records"]
    inserted_count = insert_events_batch(records)

    # Execute Security Detection Engine
    detector = SecurityDetector()
    incidents = detector.analyze_events(records)
    inserted_incidents = insert_incidents_batch(incidents)

    # Upload copy to S3 / offline simulator
    s3_result = aws_service.upload_log_to_s3(content, filename)
    aws_service.publish_threat_metric("IngestedEventsCount", float(len(records)))
    aws_service.publish_threat_metric("ThreatsDetectedCount", float(len(incidents)))

    log_audit("SOC Analyst", "UPLOAD_LOGS", f"Uploaded {filename}: {inserted_count} events, {len(incidents)} threats detected")

    return jsonify({
        "success": True,
        "filename": filename,
        "etl_metrics": etl_result["metrics"],
        "events_inserted": inserted_count,
        "threats_detected": len(incidents),
        "s3_storage": s3_result,
    })


@app.route("/api/seed", methods=["POST"])
def api_seed():
    """Loads sample demonstration dataset and runs correlation."""
    sample_path = os.path.join(Config.BASE_DIR, "data", "sample_security_logs.csv")
    if not os.path.exists(sample_path):
        return jsonify({"error": "Sample data file not found"}), 404

    with open(sample_path, "r", encoding="utf-8") as f:
        content = f.read()

    etl = LogETLPipeline()
    res = etl.process_csv_stream(content)
    if not res["success"]:
        return jsonify({"error": res["error"]}), 500

    events = res["valid_records"]
    inserted = insert_events_batch(events)

    detector = SecurityDetector()
    incidents = detector.analyze_events(events)
    insert_incidents_batch(incidents)

    log_audit("SOC Analyst", "SEED_DATASET", f"Loaded sample dataset ({inserted} events, {len(incidents)} alerts)")

    return jsonify({
        "success": True,
        "message": f"Successfully ingested {inserted} sample security events and flagged {len(incidents)} threats.",
        "events_count": inserted,
        "threats_count": len(incidents),
    })


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Resets all events and incident tables for demo."""
    reset_database(actor="SOC Analyst")
    return jsonify({"success": True, "message": "Demo database cleared successfully."})


@app.route("/api/export", methods=["GET"])
def api_export():
    """Exports analyzed incidents or raw security events to CSV."""
    export_type = request.args.get("type", "incidents")

    if export_type == "events":
        events = get_all_events(limit=5000)
        output = io.StringIO()
        if events:
            import csv
            writer = csv.DictWriter(output, fieldnames=list(events[0].keys()))
            writer.writeheader()
            writer.writerows(events)
        csv_data = output.getvalue()
        filename = "sanitized_security_events.csv"
    else:
        incidents = get_incidents(limit=5000)["incidents"]
        csv_data = LogETLPipeline.export_incidents_to_csv(incidents)
        filename = "analyzed_security_incidents.csv"

    log_audit("SOC Analyst", "EXPORT_CSV", f"Exported {export_type} to CSV")
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


@app.route("/api/settings", methods=["POST"])
def api_update_settings():
    """Updates detection thresholds and application configuration."""
    data = request.get_json(silent=True) or {}
    updated = []

    for key, val in data.items():
        if key in {"failed_attempt_threshold", "time_window_minutes", "spray_user_count", "velocity_threshold", "aws_offline_mode", "llm_provider"}:
            if update_setting(key, str(val)):
                updated.append(key)

    return jsonify({"success": True, "updated_keys": updated})


@app.route("/api/aws/status", methods=["GET"])
def api_aws_status():
    """Returns AWS integration state."""
    return jsonify(aws_service.get_cloud_status())


# -----------------------------------------------------------------------------
# Main Application Runner
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"[*] Starting Cloud Security Threat Detector on http://{Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
