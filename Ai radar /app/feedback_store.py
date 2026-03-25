import json
import os
from datetime import datetime

FEEDBACK_PATH = "storage/feedback.json"


def ensure_feedback_file():
    os.makedirs("storage", exist_ok=True)

    if not os.path.exists(FEEDBACK_PATH):
        with open(FEEDBACK_PATH, "w", encoding="utf-8") as f:
            json.dump([], f)


def load_feedback():
    ensure_feedback_file()

    with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save_feedback(entries):
    ensure_feedback_file()

    with open(FEEDBACK_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def add_feedback(alert_id, event_type, severity, verdict, analyst_notes):
    entries = load_feedback()

    new_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "alert_id": alert_id,
        "event_type": event_type,
        "severity": severity,
        "verdict": verdict,
        "analyst_notes": analyst_notes
    }

    entries.append(new_entry)
    save_feedback(entries)

    return new_entry


def get_feedback_for_alert(alert_id):
    entries = load_feedback()
    return [entry for entry in entries if entry["alert_id"] == alert_id]


def get_feedback_summary():
    entries = load_feedback()

    summary = {
        "total_feedback": len(entries),
        "false_positive_count": 0,
        "confirmed_malicious_count": 0,
        "benign_count": 0,
        "needs_review_count": 0
    }

    for entry in entries:
        verdict = entry.get("verdict", "").strip().lower()

        if verdict == "likely false positive":
            summary["false_positive_count"] += 1
        elif verdict == "confirmed malicious":
            summary["confirmed_malicious_count"] += 1
        elif verdict == "benign activity":
            summary["benign_count"] += 1
        elif verdict == "suspicious - needs more investigation":
            summary["needs_review_count"] += 1

    return summary