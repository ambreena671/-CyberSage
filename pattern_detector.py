"""
CyberSage - Deterministic Pattern Detector
Rule-based logic to detect suspicious cyber behavior and high-risk events.
"""

import pandas as pd
from typing import List, Dict, Any

REQUIRED_COLUMNS = {'event', 'timestamp', 'user', 'ip'}

SUSPICIOUS_KEYWORDS = [
    'failed', 'admin', 'sensitive', 'large data', 'malicious',
    'suspicious', 'database', 'changed', 'settings', 'multiple'
]

def detect_suspicious_patterns(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Scans parsed logs and identifies suspicious events based on security rules.
    """
    if df.empty:
        return []

    # Validate schema
    missing_cols = REQUIRED_COLUMNS - set(df.columns)
    if missing_cols:
        raise KeyError(f"DataFrame is missing required columns: {missing_cols}")

    suspicious_events = []

    for idx, row in df.iterrows():
        event_str = str(row['event']).lower()
        reasons = []

        if 'failed login' in event_str or 'failed authentication' in event_str:
            reasons.append("Failed authentication attempt")
        if 'admin' in event_str:
            reasons.append("Privileged administrative resource interaction")
        if 'sensitive' in event_str:
            reasons.append("High-value sensitive resource access")
        if 'large data' in event_str:
            reasons.append("Potential data exfiltration volume detected")
        if 'malicious' in event_str or 'suspicious' in event_str:
            reasons.append("Pre-identified threat/phishing indicator")
        if 'database' in event_str:
            reasons.append("Direct database access attempt")
        if 'settings changed' in event_str or 'setting changed' in event_str:
            reasons.append("Account persistence or security configuration change")

        if reasons:
            suspicious_events.append({
                "index": idx,
                "timestamp": row['timestamp'],
                "event": row['event'],
                "user": row['user'],
                "ip": row['ip'],
                "reasons": reasons,
                "is_suspicious": True
            })

    return suspicious_events
