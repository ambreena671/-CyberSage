"""
CyberSage - Deterministic Risk Engine
Calculates explainable numeric risk scores (0-100) and severity levels per entity (user or IP).
"""

import pandas as pd
from typing import Dict, Any, List


def _calculate_entity_risk(events_series: pd.Series) -> Dict[str, Any]:
    """Helper: Calculates risk score and factors for a specific subset of events."""
    score = 0
    factors = []

    events_lower = [str(e).lower() for e in events_series.tolist()]

    # Scoring Rules
    failed_count = sum(1 for e in events_lower if 'failed login' in e or 'failed' in e)
    if failed_count > 0:
        added = min(failed_count * 5, 15)
        score += added
        factors.append(f"Multiple failed login attempts detected (+{added})")

    if any('suspicious email' in e or 'phishing' in e for e in events_lower):
        score += 10
        factors.append("Suspicious email activity observed (+10)")

    if any('malicious' in e for e in events_lower):
        score += 15
        factors.append("Malicious link/payload interaction logged (+15)")

    if any('admin' in e for e in events_lower):
        score += 20
        factors.append("Privileged administrative resource accessed (+20)")

    if any('sensitive' in e or 'database' in e for e in events_lower):
        score += 20
        factors.append("Access to sensitive/database resources (+20)")

    if any('large data' in e for e in events_lower):
        score += 20
        factors.append("Anomalous large volume data transfer (+20)")

    if any('settings changed' in e or 'setting changed' in e for e in events_lower):
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


def calculate_risk(df: pd.DataFrame, suspicious_events: List[Dict[str, Any]] = None, group_by: str = "user") -> Dict[str, Any]:
    """
    Evaluates log events grouped by an entity ('user' or 'ip').
    Returns global overall risk alongside breakdown per entity.
    """
    if df.empty:
        return {
            "overall_risk_score": 0,
            "overall_risk_level": "LOW",
            "entity_risk_scores": {}
        }

    if 'event' not in df.columns:
        raise KeyError("DataFrame must contain an 'event' column.")
    
    if group_by not in df.columns:
        raise KeyError(f"Target column '{group_by}' for entity scoring not found in DataFrame.")

    # Calculate risk per target entity (e.g. per user or per IP)
    entity_results = {}
    for entity, group in df.groupby(group_by):
        entity_results[str(entity)] = _calculate_entity_risk(group['event'])

    # Calculate overall dataset score (highest individual entity score)
    max_score = max((res['risk_score'] for res in entity_results.values()), default=0)
    
    if max_score >= 75:
        overall_level = "CRITICAL"
    elif max_score >= 50:
        overall_level = "HIGH"
    elif max_score >= 25:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    return {
        "overall_risk_score": max_score,
        "overall_risk_level": overall_level,
        "entity_key": group_by,
        "entities": entity_results
    }
