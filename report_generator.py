"""
CyberSage - Report Generator Engine
Generates human-readable attack narratives, response plans, and exportable incident reports.
"""

from typing import Dict, Any, List
from ai_engine import generate_ai_completion

def generate_attack_story(state: Dict[str, Any]) -> str:
    """Generates a cohesive paragraph explaining the attack progression."""
    prompt = f"""
Given the following correlated security incident findings:
- Attack Classification: {state.get('classified_attack')}
- Affected User(s): {', '.join(state.get('affected_users', []))}
- Involved IP(s): {', '.join(state.get('involved_ips', []))}
- Chronological Sequence: {state.get('event_sequence')}
- Risk Score: {state.get('risk_score')}/100 ({state.get('risk_level')})

Write a professional, 1-paragraph cybersecurity attack narrative explaining:
1. How the initial activity started.
2. How the activity escalated.
3. The potential impact.
Use professional, cautious language (e.g., 'activity is consistent with', 'possible compromise detected').
Do NOT output markdown bullet points. Return ONLY a single cohesive paragraph.
"""
    system_instruction = "You are a Chief Information Security Officer (CISO) writing an executive incident narrative."
    
    story = generate_ai_completion(prompt, system_instruction)
    
    # Fallback narrative if AI key is missing
    if "AI Insight Unavailable" in story or "Service Notice" in story:
        story = (
            f"At {state.get('timeline_start', '00:00')}, suspicious events involving user(s) "
            f"'{', '.join(state.get('affected_users', ['Unknown']))}' were recorded from IP '{', '.join(state.get('involved_ips', ['Unknown']))}'. "
            f"The progression shows key activities consistent with {state.get('classified_attack')}. "
            f"The escalation reached a calculated risk score of {state.get('risk_score')}/100 ({state.get('risk_level')}), "
            f"warranting immediate isolation and verification by SOC analysts."
        )
    return story

def generate_response_plan(state: Dict[str, Any]) -> List[str]:
    """Generates actionable defensive response steps."""
    attack = state.get('classified_attack', '').lower()
    
    recommendations = [
        "Preserve current firewall and host system logs for formal forensic analysis.",
        "Initiate forced session termination for affected user credentials across all active endpoints."
    ]
    
    if "phishing" in attack:
        recommendations.extend([
            "Revoke active OAuth tokens and reset passwords for impacted user account.",
            "Quarantine flagged phishing email domain/IP across secure email gateways (SEG).",
            "Audit recent account setting and forwarding rule changes."
        ])
    elif "exfiltration" in attack or "data" in attack:
        recommendations.extend([
            "Apply temporary network egress blocks on the flagged destination IP address.",
            "Audit database query logs and execute an immediate sensitive file access inventory.",
            "Isolate target database host to inspect active session privileges."
        ])
    else:
        recommendations.extend([
            "Enforce immediate Multi-Factor Authentication (MFA) re-challenge for administrative user.",
            "Restrict access to administrative control panels to trusted VPN subnets only.",
            "Perform anti-malware and host integrity scans on origin host IP."
        ])
        
    return recommendations

def build_full_report(state: Dict[str, Any]) -> str:
    """Compiles a complete plain-text Incident Report for download."""
    report = f"""================================================================================
                    CYBERSAGE INCIDENT INVESTIGATION REPORT
================================================================================
Generated: Auto-Generated SOC Analysis Report
Status: Investigation Complete
Risk Level: {state.get('risk_level')} (Score: {state.get('risk_score')}/100)

1. INCIDENT OVERVIEW
--------------------------------------------------------------------------------
Primary Classification : {state.get('classified_attack')}
Confidence Level       : {state.get('confidence')}
Target User(s)         : {', '.join(state.get('affected_users', []))}
Involved IP(s)         : {', '.join(state.get('involved_ips', []))}
Events Analyzed        : {state.get('events_count')}

2. EXECUTIVE ATTACK NARRATIVE
--------------------------------------------------------------------------------
{state.get('attack_story')}

3. MITRE ATT&CK MAPPINGS
--------------------------------------------------------------------------------
"""
    for m in state.get('mitre_techniques', []):
        report += f" - [{m['id']}] {m['name']} ({m['tactic']}): {m['reason']}\n"

    report += f"""
4. DETERMINISTIC RISK FACTORS
--------------------------------------------------------------------------------
"""
    for factor in state.get('risk_factors', []):
        report += f" - {factor}\n"

    report += f"""
5. OBSERVED EVIDENCE TIMELINE
--------------------------------------------------------------------------------
"""
    for ev in state.get('raw_events', []):
        report += f" [{ev['timestamp']}] User: {ev['user']} | IP: {ev['ip']} | Event: {ev['event']}\n"

    report += f"""
6. RECOMMENDED DEFENSIVE ACTIONS
--------------------------------------------------------------------------------
"""
    for i, rec in enumerate(state.get('response_plan', []), 1):
        report += f" {i}. {rec}\n"

    report += """
================================================================================
                  END OF REPORT - CYBERSAGE DEFENSIVE AI
================================================================================
"""
    return report