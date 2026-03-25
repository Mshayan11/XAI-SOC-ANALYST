from dotenv import load_dotenv
load_dotenv()

from app.llm_service import generate_llm_triage

alert = {
    "id": "TEST-1001",
    "timestamp": "2026-03-10 15:01:10",
    "event_type": "Multiple Failed Login Attempts",
    "src_ip": "185.223.91.44",
    "dst_ip": "10.0.0.12",
    "protocol": "TCP",
}

result = {
    "severity": "High",
    "score": 5,
    "confidence": {"High": 90.0, "Medium": 10.0, "Low": 0.0},
    "recommended_action": "Escalate immediately and review authentication logs.",
    "false_positive_risk": False,
    "top_factors": [
        {"label": "Source traffic volume", "value": 5400},
        {"label": "Connection duration", "value": 78},
        {"label": "Destination traffic volume", "value": 6200},
    ],
    "ai_explanation": "The traffic behaviour appears abnormal compared with baseline activity."
}

output = generate_llm_triage(alert, result)
print(output)