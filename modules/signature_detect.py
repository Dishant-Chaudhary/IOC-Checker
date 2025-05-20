import re

def detect_attacks(log_lines):
    alerts = []
    for line in log_lines:
        if "nmap" in line.lower() or re.search(r"nmap scan", line, re.IGNORECASE):
            alerts.append(f"[ALERT] Nmap scan detected → {line.strip()}")
    return alerts
