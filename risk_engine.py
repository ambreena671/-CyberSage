"""
CyberSage - Deterministic Risk Engine
Calculates explainable numeric risk scores (0-100) and severity levels per entity (user or IP)
and across global dataset context.
"""

import pandas as pd
from typing import Dict, Any, List


def _calculate_entity_risk(events_series: pd.Series) -> Dict[str, Any]:
    """Helper: Calculates risk score and detailed factors for a specific log subset."""
    score = 0
    factors = []

    events_lower = [str(e).lower() for e in events_series.tolist()]

    # 1. Failed Logins & Access Denials
    failed_count = sum(
        1 for e in events_lower 
        if any(term in e for term in ['failed', 'denied', 'unauthorized', 'invalid', 'error', '401', '403'])
    )
    if failed_count > 0:
        added = min(failed_count * 5, 25)
        score += added
        factors.append(f"Multiple access/authentication failures detected ({failed_count} events) (+{added})")

    # 2. Suspicious Email / Phishing
    if any(any(term in e for term in ['suspicious email', 'phishing', 'email_link', 'spam']) for e in events_lower):
        score += 15
        factors.append("Suspicious email or phishing activity observed (+15)")

    # 3. Threat Payload & Malicious Activity
    if any(any(term in e for term in ['malicious', 'exploit', 'injection', 'payload', 'attack', 'dos', 'ddos', 'trojan', 'botnet']) for e in events_lower):
        score += 25
        factors.append("Explicit attack vector or payload activity logged (+25)")

    # 4. Privileged Access
    if any(any(term in e for term in ['admin', 'root', 'sudo', 'privileged']) for e in events_lower):
        score += 20
        factors.append("Privileged administrative resource accessed (+20)")

    # 5. Sensitive Data & Database Interactivity
    if any(any(term in e for term in ['sensitive', 'database', 'exfiltration', 'dump', 'large data', 'export']) for e in events_lower):
        score += 20
        factors.append("Access to sensitive resources or bulk data operation (+20)")

    # 6. Configuration / Persistence Alteration
    if any(any(term in e for term in ['settings changed', 'setting changed', 'config', 'modified', 'cleared logs']) for e in events_lower):
        score += 15
        factors.append("Security configuration or system persistence altered (+15)")

    # 7. Numeric Dataset Labels (e.g., Label: 1 or Attack: True)
    if any(any(term in e.split(' | ') for term in ['1', '1.0', 'true', 'anomaly', 'attack']) for e in events_lower):
        score += 30
        factors.append("Target dataset flagged positive threat label (+30)")

    # Cap Score at 100
    final_score = min(score, 100)

    # Determine Severity Level & Color Mapping
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
        "explanation": f"Risk score calculated as {final_score}/100 ({level}) based on {len(factors)} deterministic threat rules."
    }


def calculate_risk(df: pd.DataFrame, suspicious_events: List[Dict[str, Any]] = None, group_by: str = "user") -> Dict[str, Any]:
    """
    Evaluates log events grouped by an entity ('user' or 'ip') as well as globally.
    """
    if df.empty:
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "risk_color": "#66bb6a",
            "risk_factors": [],
            "overall_risk_score": 0,
            "overall_risk_level": "LOW",
            "entities": {}
        }

    if 'event' not in df.columns:
        raise KeyError("DataFrame must contain an 'event' column.")

    # 1. Compute Global Risk Across Complete Dataset
    global_results = _calculate_entity_risk(df['event'])

    # 2. Compute Entity-Level Risk Breakdown (if target column exists)
    entity_results = {}
    if group_by in df.columns:
        for entity, group in df.groupby(group_by):
            entity_results[str(entity)] = _calculate_entity_risk(group['event'])

    return {
        "risk_score": global_results["risk_score"],
        "risk_level": global_results["risk_level"],
        "risk_color": global_results["risk_color"],
        "risk_factors": global_results["risk_factors"],
        "explanation": global_results["explanation"],
        "overall_risk_score": global_results["risk_score"],
        "overall_risk_level": global_results["risk_level"],
        "entity_key": group_by,
        "entities": entity_results
    }
