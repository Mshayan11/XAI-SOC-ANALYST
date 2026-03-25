import random


def lookup_ip_reputation(ip):
    reputation_levels = ["Malicious", "Suspicious", "Unknown", "Clean"]
    countries = [
        "Russia",
        "China",
        "United States",
        "Germany",
        "Netherlands",
        "Brazil"
    ]

    return {
        "ip": ip,
        "reputation": random.choice(reputation_levels),
        "country": random.choice(countries),
        "threat_feeds": random.randint(0, 5)
    }