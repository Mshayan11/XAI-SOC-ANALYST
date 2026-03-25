import os
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, redirect, url_for

from app.alert_store import get_all_alerts, add_uploaded_alerts, find_alert_by_id
from app.csv_loader import allowed_csv_file, load_alerts_from_csv
from app.risk_engine import predict_threat_from_features, build_triage_report
from app.log_parser import parse_raw_log, build_alert_from_input
from app.feedback_store import (
    add_feedback,
    get_feedback_for_alert,
    get_feedback_summary
)
from app.llm_service import generate_llm_triage
from app.mitre_mapper import get_mitre_mapping
from app.threat_intel import lookup_ip_reputation

main = Blueprint("main", __name__)

UPLOAD_FOLDER = "uploads"


def build_attack_timeline(alert, result):
    event_type = alert.get("event_type", "Suspicious Activity")
    timestamp = alert.get("timestamp", "Unknown Time")
    src_ip = alert.get("src_ip", "Unknown Source")
    dst_ip = alert.get("dst_ip", "Unknown Destination")

    timeline = [
        f"{timestamp} — Alert ingested into AI Cyber Radar queue.",
        f"{timestamp} — Event '{event_type}' detected from {src_ip} targeting {dst_ip}.",
        f"{timestamp} — ML engine classified the alert as {result['severity']} severity with risk score {result['score']}/5.",
        f"{timestamp} — Explainable AI identified the top contributing behavioural features.",
        f"{timestamp} — Claude generated analyst-focused triage guidance and next steps."
    ]

    if result["severity"] == "High":
        timeline.append(f"{timestamp} — Escalation recommended due to high-risk behaviour and investigation priority.")
    elif result["severity"] == "Medium":
        timeline.append(f"{timestamp} — Manual analyst review recommended before escalation.")
    else:
        timeline.append(f"{timestamp} — Alert marked for monitoring and low-priority review.")

    return timeline


@main.route("/", methods=["GET"])
def home():
    severity_filter = request.args.get("severity", "").strip()
    search_query = request.args.get("search", "").strip()

    all_alerts = get_all_alerts()
    enriched_alerts = []

    for alert in all_alerts:
        result = predict_threat_from_features(alert)
        merged = {**alert, **result}

        if severity_filter and merged["severity"] != severity_filter:
            continue

        searchable_text = f"{merged.get('event_type', '')} {merged.get('src_ip', '')} {merged.get('dst_ip', '')}"
        if search_query and search_query.lower() not in searchable_text.lower():
            continue

        enriched_alerts.append(merged)

    total_alerts = len(enriched_alerts)
    high_count = sum(1 for a in enriched_alerts if a["severity"] == "High")
    medium_count = sum(1 for a in enriched_alerts if a["severity"] == "Medium")
    low_count = sum(1 for a in enriched_alerts if a["severity"] == "Low")

    feedback_summary = get_feedback_summary()

    return render_template(
        "index.html",
        alerts=enriched_alerts,
        total_alerts=total_alerts,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        feedback_summary=feedback_summary,
        upload_message="",
        current_search=search_query,
        current_severity=severity_filter
    )


@main.route("/upload-csv", methods=["POST"])
def upload_csv():
    file = request.files.get("alerts_file")

    if not file or file.filename == "":
        return render_dashboard_with_message("No CSV file was selected.")

    if not allowed_csv_file(file.filename):
        return render_dashboard_with_message("Only CSV files are supported.")

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    try:
        alerts = load_alerts_from_csv(filepath)
        add_uploaded_alerts(alerts)
        return render_dashboard_with_message(
            f"CSV uploaded successfully. {len(alerts)} alerts added to the queue."
        )
    except Exception as e:
        return render_dashboard_with_message(f"CSV processing failed: {str(e)}")


@main.route("/alert/<alert_id>", methods=["GET"])
def alert_detail(alert_id):
    alert = find_alert_by_id(alert_id)

    if not alert:
        return redirect(url_for("main.home"))

    result = predict_threat_from_features(alert)
    llm_output = generate_llm_triage(alert, result)
    mitre = get_mitre_mapping(alert["event_type"])
    ip_intel = lookup_ip_reputation(alert["src_ip"])
    attack_timeline = build_attack_timeline(alert, result)

    feedback_history = get_feedback_for_alert(alert_id)

    return render_template(
        "result.html",
        alert=alert,
        result=result,
        saved_message="",
        feedback_history=feedback_history,
        raw_log="",
        llm_output=llm_output,
        mitre=mitre,
        ip_intel=ip_intel,
        attack_timeline=attack_timeline
    )


@main.route("/analyse-user-alert", methods=["POST"])
def analyse_user_alert():
    raw_log = request.form.get("raw_log", "").strip()
    parsed_log = parse_raw_log(raw_log)
    alert = build_alert_from_input(request.form, parsed_log)

    result = predict_threat_from_features(alert)
    llm_output = generate_llm_triage(alert, result)
    mitre = get_mitre_mapping(alert["event_type"])
    ip_intel = lookup_ip_reputation(alert["src_ip"])
    attack_timeline = build_attack_timeline(alert, result)

    feedback_history = get_feedback_for_alert(alert["id"])

    return render_template(
        "result.html",
        alert=alert,
        result=result,
        saved_message="User-submitted alert analysed successfully.",
        feedback_history=feedback_history,
        raw_log=raw_log,
        llm_output=llm_output,
        mitre=mitre,
        ip_intel=ip_intel,
        attack_timeline=attack_timeline
    )


@main.route("/submit-triage/<alert_id>", methods=["POST"])
def submit_triage(alert_id):
    analyst_notes = request.form.get("analyst_notes", "").strip()
    verdict = request.form.get("verdict", "").strip()
    raw_log = request.form.get("raw_log", "").strip()

    if alert_id == "USER-ALERT":
        parsed_log = parse_raw_log(raw_log)
        alert = build_alert_from_input(request.form, parsed_log)
    else:
        alert = find_alert_by_id(alert_id)

    if not alert:
        return redirect(url_for("main.home"))

    result = predict_threat_from_features(alert)
    llm_output = generate_llm_triage(alert, result)
    mitre = get_mitre_mapping(alert["event_type"])
    ip_intel = lookup_ip_reputation(alert["src_ip"])
    attack_timeline = build_attack_timeline(alert, result)

    if verdict:
        add_feedback(
            alert_id=alert["id"],
            event_type=alert["event_type"],
            severity=result["severity"],
            verdict=verdict,
            analyst_notes=analyst_notes
        )

    feedback_history = get_feedback_for_alert(alert["id"])

    return render_template(
        "result.html",
        alert=alert,
        result=result,
        saved_message="Analyst feedback saved successfully.",
        feedback_history=feedback_history,
        raw_log=raw_log,
        llm_output=llm_output,
        mitre=mitre,
        ip_intel=ip_intel,
        attack_timeline=attack_timeline
    )


def render_dashboard_with_message(message):
    severity_filter = request.args.get("severity", "").strip()
    search_query = request.args.get("search", "").strip()

    all_alerts = get_all_alerts()
    enriched_alerts = []

    for alert in all_alerts:
        result = predict_threat_from_features(alert)
        merged = {**alert, **result}

        if severity_filter and merged["severity"] != severity_filter:
            continue

        searchable_text = f"{merged.get('event_type', '')} {merged.get('src_ip', '')} {merged.get('dst_ip', '')}"
        if search_query and search_query.lower() not in searchable_text.lower():
            continue

        enriched_alerts.append(merged)

    total_alerts = len(enriched_alerts)
    high_count = sum(1 for a in enriched_alerts if a["severity"] == "High")
    medium_count = sum(1 for a in enriched_alerts if a["severity"] == "Medium")
    low_count = sum(1 for a in enriched_alerts if a["severity"] == "Low")

    feedback_summary = get_feedback_summary()

    return render_template(
        "index.html",
        alerts=enriched_alerts,
        total_alerts=total_alerts,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        feedback_summary=feedback_summary,
        upload_message=message,
        current_search=search_query,
        current_severity=severity_filter
    )