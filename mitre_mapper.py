"""
CyberSage - MITRE ATT&CK Mapping Engine
Maps observed suspicious behaviors to verified MITRE ATT&CK techniques with non-hallucinated IDs.
"""

import pandas as pd
from typing import List, Dict, Any

VERIFIED_MITRE_MAPPINGS = [
    {
        "keywords": ["failed login"],
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to user accounts."
    },
    {
        "keywords": ["suspicious email", "malicious link"],
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems."
    },
    {
        "keywords": ["admin panel access", "admin"],
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Adversaries may obtain and use credentials of existing accounts to gain access."
    },
    {
        "keywords": ["sensitive file access", "database access", "multiple sensitive files"],
        "id": "T1213",
        "name": "Data from Information Repositories",
        "tactic": "Collection",
        "description": "Adversaries may leverage information repositories to gather sensitive internal data."
    },
    {
        "keywords": ["large data transfer"],
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by transferring it over an anomalous channel or protocol."
    },
    {
        "keywords": ["account settings changed"],
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts to maintain access to victim systems."
    }
]

def map_mitre_techniques(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Analyzes log events and returns matching verified MITRE ATT&CK techniques.
    """
    mapped_techniques = []
    events_str = " ".join(df['event'].str.lower().tolist())
    
    for technique in VERIFIED_MITRE_MAPPINGS:
        if any(kw in events_str for kw in technique["keywords"]):
            mapped_techniques.append({
                "id": technique["id"],
                "name": technique["name"],
                "tactic": technique["tactic"],
                "reason": f"Observed logs matching indicators: {', '.join(technique['keywords'])}",
                "confidence": "High",
                "description": technique["description"]
            })

    return mapped_techniques