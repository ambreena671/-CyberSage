"""
CyberSage - Deterministic Risk Engine
Calculates explainable numeric risk scores (0-100) and severity levels entirely in Python.
"""

import pandas as pd
from typing import Dict, Any, List

def calculate_risk(df: pd.DataFrame, suspicious_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates log events against deterministic risk scoring rules.
    Max Score: 100
    """
    score = 0
    factors = []

    events_lower = [e.lower() for e in df['event'].tolist()]

    # Scoring Rules
    failed_count = sum(1 for e in events_lower if 'failed login' in e)
    if failed_count > 0:
        added = min(failed_count * 5, 15)
        score += added
        factors.append(f"Multiple failed login attempts detected (+{added})")

    if any('suspicious email' in e for e in events_lower):
        score += 10
        factors.append("Suspicious email activity observed (+10)")

    if any('malicious link' in e for e in events_lower):
        score += 15
        factors.append("Malicious link interaction logged (+15)")

    if any('admin' in e for e in events_lower):
        score += 20
        factors.append("Privileged administrative resource accessed (+20)")

    if any('sensitive' in e or 'database' in e for e in events_lower):
        score += 20
        factors.append("Access to sensitive/database resources (+20)")

    if any('large data transfer' in e for e in events_lower):
        score += 20
        factors.append("Anomalous large volume data transfer (+20)")

    if any('settings changed' in e for e in events_lower):
        score += 15
        factors.append("Account configuration or security settings altered (+15)")

    # Cap at 100
    final_score = min(score, 100)

    # Determine Severity Level
    if final_score >= 75:
        level = "CRITICAL"
        color = "#ff4b4b"
    elif final_score >= 50:
        level = "HIGH"
        color = "#ffa726"
    elif final_score >= 25:
        level = "MEDIUM"
        color = "#ffee58"
    else:
        level = "LOW"
        color = "#66bb6a"

    return {
        "risk_score": final_score,
        "risk_level": level,
        "risk_color": color,
        "risk_factors": factors,
        "explanation": f"Calculated risk score is {final_score}/100 ({level}) based on {len(factors)} deterministic security risk factors."
    }