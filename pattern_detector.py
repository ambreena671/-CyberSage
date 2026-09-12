"""
CyberSage - Deterministic Pattern Detector
Rule-based logic to detect suspicious cyber behavior and high-risk events across standard and custom security datasets.
"""

import pandas as pd
from typing import List, Dict, Any

REQUIRED_COLUMNS = {'event', 'timestamp', 'user', 'ip'}

def detect_suspicious_patterns(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Scans parsed logs and identifies suspicious events based on broad security rules.
    """
    if df.empty:
        return []

    # Validate required columns
    missing_cols = REQUIRED_COLUMNS - set(df.columns)
    if missing_cols:
        raise KeyError(f"DataFrame is missing required columns: {missing_cols}")

    suspicious_events = []

    for idx, row in df.iterrows():
        event_str = str(row['event']).lower()
        reasons = []

        # 1. Authentication & Access Failures
        if any(term in event_str for term in ['failed', 'denied', 'unauthorized', 'invalid', 'error', '401', '403', 'refused']):
            reasons.append("Authentication or access permission failure")

        # 2. Administrative & Privilege Activity
        if any(term in event_str for term in ['admin', 'root', 'sudo', 'privileged', 'system_user']):
            reasons.append("Privileged administrative resource interaction")

        # 3. Data Access & Bulk Operations
        if any(term in event_str for term in ['sensitive', 'database', 'exfiltration', 'dump', 'large data', 'export', 'download']):
            reasons.append("High-value data access or potential bulk extraction")

        # 4. Explicit Threat & Malware Indicators
        if any(term in event_str for term in ['malicious', 'suspicious', 'phishing', 'attack', 'exploit', 'injection', 'dos', 'ddos', 'trojan', 'botnet']):
            reasons.append("Pre-identified threat indicator or attack payload")

        # 5. System Modification & Configuration Changes
        if any(term in event_str for term in ['setting changed', 'settings changed', 'config', 'modified', 'deleted', 'cleared logs']):
            reasons.append("Account persistence or security configuration alteration")

        # 6. Numeric/Categorical Attack Flags (Kaggle / Security Datasets)
        if any(term in event_str.split(' | ') for term in ['1', '1.0', 'true', 'anomaly', 'attack']):
            reasons.append("Dataset column flagged positive threat detection indicator")

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
