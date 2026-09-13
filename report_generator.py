"""
CyberSage - Report Generator Module
Handles dynamic AI narrative generation, mitigation response planning,
and full text report formatting for DFIR & SOC investigations.
"""

import os
from typing import Dict, Any, List
import pandas as pd

# Define the System Prompt for Grok / OpenAI API Calls
SYSTEM_PROMPT = """
You are CyberSage, an elite Digital Forensics & Incident Response (DFIR) and SOC AI Lead.
Analyze the provided log artifacts and summarize the evidence.

Guidelines:
1. Refer to the operational domain as "DFIR Incident Response & SOC Operations".
2. Address both forensic evidence reconstruction and live SOC response actions.
3. If multiple users/IPs are involved, describe it as a 'multi-host/multi-account incident trace'.
4. Do NOT exclusively limit the narrative to basic SOC monitoring; include forensic timeline analysis.
"""


def generate_attack_story(state: Dict[str, Any], df: pd.DataFrame = None) -> str:
    """Generates an executive narrative via LLM API call with a DFIR/SOC neutral fallback."""
    
    # Extract investigation parameters from state
    users = ", ".join(state.get("affected_users", [])) or "Unknown User"
    ips = ", ".join(state.get("involved_ips", [])) or "Unknown IP"
    attack_type = state.get("classified_attack", "Unclassified Suspicious Behavior")
    score = state.get("risk_score", 0)
    level = state.get("risk_level", "LOW")

    # Extract timestamp from dataframe or raw events if available
    timestamp = "00:00"
    raw_events = state.get("raw_events", [])
    if raw_events and isinstance(raw_events, list) and len(raw_events) > 0:
        timestamp = raw_events[0].get("timestamp", "00:00")
    elif df is not None and not df.empty and "timestamp" in df.columns:
        timestamp = str(df["timestamp"].iloc[0])

    # -------------------------------------------------------------------------
    # NEW FALLBACK (DFIR + SOC Neutral Template)
    # -------------------------------------------------------------------------
    fallback_story = (
        f"Artifact Timeline Analysis: At {timestamp}, suspicious forensic artifacts involving identity traces "
        f"'{users}' were captured across network endpoints '{ips}'. The sequence exhibits patterns consistent with "
        f"{attack_type}. Deterministic evidence evaluation scored this incident at {score}/100 ({level}), "
        f"requiring immediate artifact preservation, host isolation, and joint DFIR/SOC incident verification."
    )

    # Attempt LLM API call if API key is configured
    api_key = os.getenv("GROK_API_KEY") or os.getenv("XAI_API_KEY")
    if not api_key:
        return fallback_story

    try:
        from openai import OpenAI
        client = OpenAI(
            api_key=api_key,
            base_url="https://api.x.ai/v1"
        )

        # Truncate log samples to protect context limits
        log_sample = ""
        if df is not None and not df.empty:
            log_sample = df.head(15).to_csv(index=False)
        else:
            log_sample = str(raw_events[:15])

        user_prompt = (
            f"Incident Metadata:\n"
            f"- Timestamp: {timestamp}\n"
            f"- Affected Users: {users}\n"
            f"- Involved IPs: {ips}\n"
            f"- Threat Type: {attack_type}\n"
            f"- Risk Score: {score}/100 ({level})\n\n"
            f"Key Log Artifacts:\n{log_sample}"
        )

        response = client.chat.completions.create(
            model="grok-beta",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content.strip()

    except Exception:
        # Gracefully drop down to DFIR/SOC neutral fallback on API error/timeout
        return fallback_story


def generate_response_plan(state: Dict[str, Any]) -> List[str]:
    """Generates playbook recommendations based on incident risk level."""
    score = state.get("risk_score", 0)
    
    plan = [
        "Isolate affected endpoint host(s) from network segments.",
        "Revoke active session tokens and force password resets for flagged identity traces.",
        "Preserve memory dumps and system log artifacts for deep forensic extraction."
    ]
    
    if score >= 70:
        plan.extend([
            "Initiate Enterprise Escalation Protocol (DFIR Team Lead & CISO notification).",
            "Perform sweep across all domain controllers for unauthorized persistence mechanisms."
        ])
    elif score >= 40:
        plan.append("Monitor peripheral service accounts and correlate active outbound IP traffic.")
        
    return plan


def build_full_report(state: Dict[str, Any]) -> str:
    """Builds a plain-text comprehensive DFIR & SOC incident investigation report."""
    users = ", ".join(state.get("affected_users", [])) or "N/A"
    ips = ", ".join(state.get("involved_ips", [])) or "N/A"
    
    report = f"""================================================================================
CYBERSAGE DFIR & SOC INCIDENT INVESTIGATION REPORT
================================================================================

1. EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Risk Score       : {state.get('risk_score', 0)} / 100 ({state.get('risk_level', 'LOW')})
Threat Type      : {state.get('classified_attack', 'Unclassified')}
Confidence       : {state.get('confidence', 'Low')}
Affected Users   : {users}
Involved IPs     : {ips}

2. INCIDENT & FORENSIC NARRATIVE
--------------------------------------------------------------------------------
{state.get('attack_story', '')}

3. TRIGGERED RISK FACTORS
--------------------------------------------------------------------------------
"""
    for factor in state.get('risk_factors', []):
        report += f"- {factor}\n"

    report += """
4. MITRE ATT&CK MAPPINGS
--------------------------------------------------------------------------------
"""
    for m in state.get('mitre_techniques', []):
        report += f"- [{m.get('id')}] {m.get('name')} ({m.get('tactic')})\n"

    report += """
5. RECOMMENDED MITIGATION PLAYBOOK
--------------------------------------------------------------------------------
"""
    for idx, step in enumerate(state.get('response_plan', []), 1):
        report += f"{idx}. {step}\n"

    report += """
================================================================================
END OF REPORT — CYBERSAGE GENERATIVE FORENSICS ENGINE
================================================================================
"""
    return report
