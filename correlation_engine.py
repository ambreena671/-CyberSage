"""
CyberSage - Event Correlation Engine
Correlates security events to identify attack sequences and classify primary threat vectors.
"""

import pandas as pd
from typing import List, Dict, Any

def correlate_events(df: pd.DataFrame, suspicious_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlates chronological events to identify logical attack vectors.
    """
    events_list = [e.lower() for e in df['event'].tolist()]
    events_str = " -> ".join(events_list)
    
    correlations = []
    classified_attack = "Unclassified Suspicious Behavior"
    confidence = "Medium"
    
    # Sequence Rule 1: Account Compromise / Credential Stuffing
    if any("failed" in e for e in events_list) and any("successful login" in e for e in events_list):
        correlations.append("Authentication sequence indicates potential Credential Guessing or Brute-Force preceding access.")
    
    # Sequence Rule 2: Phishing Chain
    if any("email" in e or "link" in e for e in events_list) and any("login" in e for e in events_list):
        correlations.append("Initial access appears tied to Email / Web Phishing activity followed by login.")
        
    # Sequence Rule 3: Exfiltration Chain
    if any("sensitive" in e or "database" in e for e in events_list) and any("large data transfer" in e for e in events_list):
        correlations.append("High-value data access directly followed by anomalous outbound data transfer (Exfiltration).")

    # Classification Logic
    if "email" in events_str or "link" in events_str:
        classified_attack = "Phishing leading to Account Access & Persistence"
        confidence = "High"
    elif "database" in events_str or ("sensitive" in events_str and "large data transfer" in events_str and "failed" not in events_str):
        classified_attack = "Unauthorized Sensitive Data Access & Exfiltration"
        confidence = "High"
    elif "failed login" in events_str and "admin" in events_str:
        classified_attack = "Credential Compromise & Privileged Access Escalation"
        confidence = "High"

    return {
        "correlations": correlations,
        "classified_attack": classified_attack,
        "confidence": confidence,
        "affected_users": list(set(df['user'].tolist())),
        "involved_ips": list(set(df['ip'].tolist()))
    }