MITRE_MAPPING = {
    "Multiple Failed Login Attempts": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },
    "Port Scan Activity": {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery"
    },
    "Suspicious Process Communication": {
        "technique": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },
    "Normal Internal Traffic": {
        "technique": "N/A",
        "name": "No Adversary Technique Identified",
        "tactic": "Benign"
    },
    "failed_login": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    }
}


def get_mitre_mapping(event_type):
    return MITRE_MAPPING.get(event_type, {
        "technique": "Unknown",
        "name": "Unknown Technique",
        "tactic": "Unknown"
    })