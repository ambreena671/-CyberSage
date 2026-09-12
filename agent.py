"""
CyberSage - Agentic AI Orchestrator
Manages multi-step sequential investigation state machine.
Combines Python deterministic security analysis with Generative AI narratives.
"""

from typing import Dict, Any, List
import pandas as pd

from log_parser import parse_logs, extract_log_summary
from pattern_detector import detect_suspicious_patterns
from correlation_engine import correlate_events
from risk_engine import calculate_risk
from mitre_mapper import map_mitre_techniques
from report_generator import generate_attack_story, generate_response_plan, build_full_report

class CyberSageAgent:
    """Agentic Incident Investigator State Machine."""

    def __init__(self):
        self.reset_state()

    def reset_state(self):
        """Initializes an empty investigation state."""
        self.state: Dict[str, Any] = {
            "logs_loaded": False,
            "raw_events": [],
            "events_count": 0,
            "summary": {},
            "suspicious_events": [],
            "correlations": [],
            "classified_attack": "",
            "confidence": "",
            "affected_users": [],
            "involved_ips": [],
            "mitre_techniques": [],
            "risk_score": 0,
            "risk_level": "LOW",
            "risk_color": "#66bb6a",
            "risk_factors": [],
            "event_sequence": "",
            "attack_story": "",
            "response_plan": [],
            "final_report": "",
            "steps_completed": []
        }

    def run_investigation(self, log_input: Any) -> Dict[str, Any]:
        """Executes the autonomous sequential investigation steps."""
        self.reset_state()

        # Step 1: Parse and normalize logs
        success, df, msg = parse_logs(log_input)
        if not success:
            raise ValueError(msg)

        self.state["logs_loaded"] = True
        self.state["raw_events"] = df.to_dict(orient='records')
        self.state["events_count"] = len(df)
        self.state["summary"] = extract_log_summary(df)
        self.state["steps_completed"].append("✓ Logs parsed and validated")

        # Step 2: Detect suspicious patterns (Python Engine)
        suspicious = detect_suspicious_patterns(df)
        self.state["suspicious_events"] = suspicious
        self.state["steps_completed"].append(f"✓ Detected {len(suspicious)} anomalous events")

        # Step 3: Correlate events & classify attack (Python Engine)
        corr_results = correlate_events(df, suspicious)
        self.state["correlations"] = corr_results.get("correlations", [])
        self.state["classified_attack"] = corr_results.get("classified_attack", "Unclassified Activity")
        self.state["confidence"] = corr_results.get("confidence", "Low")
        self.state["affected_users"] = corr_results.get("affected_users", [])
        self.state["involved_ips"] = corr_results.get("involved_ips", [])
        
        # Limit event sequence preview to avoid memory allocation issues on large datasets
        event_samples = df['event'].head(20).astype(str).tolist()
        self.state["event_sequence"] = " ➔ ".join(event_samples)
        if len(df) > 20:
            self.state["event_sequence"] += f" ... (+{len(df) - 20} more events)"
            
        self.state["steps_completed"].append("✓ Event correlation complete")

        # Step 4: Map to MITRE ATT&CK Framework
        mitre_results = map_mitre_techniques(df)
        self.state["mitre_techniques"] = mitre_results
        self.state["steps_completed"].append(f"✓ Mapped to {len(mitre_results)} MITRE ATT&CK techniques")

        # Step 5: Deterministic Risk Calculation
        risk_results = calculate_risk(df, suspicious)
        self.state["risk_score"] = risk_results.get("risk_score", 0)
        self.state["risk_level"] = risk_results.get("risk_level", "LOW")
        self.state["risk_color"] = risk_results.get("risk_color", "#66bb6a")
        self.state["risk_factors"] = risk_results.get("risk_factors", [])
        self.state["steps_completed"].append("✓ Risk score computed")

        # Step 6: Generative AI Executive Narrative
        story = generate_attack_story(self.state)
        self.state["attack_story"] = story
        self.state["steps_completed"].append("✓ Attack story generated")

        # Step 7: Defensive Response Planning
        response = generate_response_plan(self.state)
        self.state["response_plan"] = response
        self.state["steps_completed"].append("✓ Response playbook created")

        # Step 8: Build downloadable final report
        report = build_full_report(self.state)
        self.state["final_report"] = report
        self.state["steps_completed"].append("✓ Incident report generated")

        return self.state
