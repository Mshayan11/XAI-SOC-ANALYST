from app.mock_data import MOCK_ALERTS

UPLOADED_ALERTS = []


def get_all_alerts():
    return MOCK_ALERTS + UPLOADED_ALERTS


def add_uploaded_alerts(alerts):
    global UPLOADED_ALERTS
    UPLOADED_ALERTS.extend(alerts)


def find_alert_by_id(alert_id):
    all_alerts = get_all_alerts()
    return next((alert for alert in all_alerts if alert["id"] == alert_id), None)