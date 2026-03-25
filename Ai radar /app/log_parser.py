def parse_raw_log(raw_log: str):
    """
    Parses simple key=value logs into a dictionary.
    Example:
    timestamp=2026-03-10 14:22:10
    src_ip=185.223.91.44
    dst_ip=10.0.0.12
    protocol=TCP
    event_type=failed_login
    src_bytes=5400
    dst_bytes=6200
    duration=78
    failed_logins=6
    num_compromised=2
    """
    parsed = {}

    if not raw_log:
        return parsed

    lines = raw_log.strip().splitlines()

    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key.strip()] = value.strip()

    return parsed


def build_alert_from_input(form_data, parsed_log):
    """
    Builds a full alert object from either raw log input
    or manually entered structured fields.
    """
    return {
        "id": "USER-ALERT",
        "timestamp": parsed_log.get("timestamp") or form_data.get("timestamp", "").strip() or "2026-03-10 14:00:00",
        "src_ip": parsed_log.get("src_ip") or form_data.get("src_ip", "").strip() or "0.0.0.0",
        "dst_ip": parsed_log.get("dst_ip") or form_data.get("dst_ip", "").strip() or "0.0.0.0",
        "protocol": parsed_log.get("protocol") or form_data.get("protocol", "").strip() or "TCP",
        "event_type": parsed_log.get("event_type") or form_data.get("event_type", "").strip() or "User Submitted Alert",
        "src_bytes": float(parsed_log.get("src_bytes") or form_data.get("src_bytes", 0) or 0),
        "dst_bytes": float(parsed_log.get("dst_bytes") or form_data.get("dst_bytes", 0) or 0),
        "duration": float(parsed_log.get("duration") or form_data.get("duration", 0) or 0),
        "failed_logins": float(parsed_log.get("failed_logins") or form_data.get("failed_logins", 0) or 0),
        "num_compromised": float(parsed_log.get("num_compromised") or form_data.get("num_compromised", 0) or 0),
    }