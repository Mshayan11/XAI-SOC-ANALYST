import csv
import os

REQUIRED_COLUMNS = [
    "id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "event_type",
    "src_bytes",
    "dst_bytes",
    "duration",
    "failed_logins",
    "num_compromised",
]


def allowed_csv_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() == "csv"


def normalize_column_name(name):
    return name.strip().lower().replace(" ", "_")


def load_alerts_from_csv(filepath):
    alerts = []

    if not os.path.exists(filepath):
        return alerts

    with open(filepath, "r", encoding="utf-8-sig", newline="") as csvfile:
        reader = csv.DictReader(csvfile)

        if not reader.fieldnames:
            raise ValueError("CSV file has no header row.")

        normalized_map = {
            normalize_column_name(field): field
            for field in reader.fieldnames
        }

        for column in REQUIRED_COLUMNS:
            if column not in normalized_map:
                raise ValueError(f"Missing required CSV column: {column}")

        for row in reader:
            alert = {
                "id": row[normalized_map["id"]].strip(),
                "timestamp": row[normalized_map["timestamp"]].strip(),
                "src_ip": row[normalized_map["src_ip"]].strip(),
                "dst_ip": row[normalized_map["dst_ip"]].strip(),
                "protocol": row[normalized_map["protocol"]].strip(),
                "event_type": row[normalized_map["event_type"]].strip(),
                "src_bytes": float(row[normalized_map["src_bytes"]] or 0),
                "dst_bytes": float(row[normalized_map["dst_bytes"]] or 0),
                "duration": float(row[normalized_map["duration"]] or 0),
                "failed_logins": float(row[normalized_map["failed_logins"]] or 0),
                "num_compromised": float(row[normalized_map["num_compromised"]] or 0),
            }
            alerts.append(alert)

    return alerts