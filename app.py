"""
CyberSage - DFIR & SOC AI Incident Investigator UI
Custom dark-themed cybersecurity & digital forensics dashboard displaying investigation steps,
risk cards, attack flows, artifact timelines, entity breakdowns, and downloadable reports.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from agent import CyberSageAgent
from demo_data import get_demo_data
from log_parser import parse_logs

# Page Configuration
st.set_page_config(
    page_title="CyberSage | DFIR & SOC Incident Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for ForensicIntel-Style Blue/Purple Glowing Dashboard
CUSTOM_CSS = """
<style>
    /* Main Dashboard Background - Deep Navy Gradient */
    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #0f1629 100%) !important;
        color: #00eeff !important;
    }

    /* Sidebar Background - Deep Navy with Blue Tint */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a0d15 0%, #11152a 100%) !important;
        border-right: 2px solid #00ccff !important;
        box-shadow: inset -10px 0 30px rgba(0, 204, 255, 0.05) !important;
    }

    /* Text Hierarchy - Cyan/Blue Color Usage */
    h1 {
        color: #00eeff !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px !important;
        text-shadow: 0 0 30px rgba(0, 238, 255, 0.4), 0 0 60px rgba(139, 92, 246, 0.2) !important;
    }

    h2, h3 {
        color: #00ccff !important;
        font-weight: 600 !important;
        margin-top: 24px !important;
        margin-bottom: 12px !important;
        text-shadow: 0 0 15px rgba(0, 204, 255, 0.3) !important;
    }

    h4, h5, h6 {
        color: #0099ff !important;
        font-weight: 500 !important;
    }

    p, label, span, div, small, b, strong, caption {
        color: #a8c5dd !important;
    }

    caption, small {
        color: #6b8aaa !important;
        font-size: 0.85em !important;
    }

    /* Primary Investigate Button - Glowing Blue Style */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #00ccff 0%, #0099ff 100%) !important;
        color: #0a0e1a !important;
        border: 1px solid #00eeff !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        padding: 10px 24px !important;
        box-shadow: 0 0 20px rgba(0, 204, 255, 0.4), 0 8px 24px rgba(0, 204, 255, 0.2) !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        font-size: 14px !important;
    }

    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #00eeff 0%, #00ccff 100%) !important;
        box-shadow: 0 0 30px rgba(0, 238, 255, 0.6), 0 12px 32px rgba(0, 204, 255, 0.4) !important;
        transform: translateY(-2px) !important;
    }

    .stButton > button[kind="primary"]:active {
        transform: translateY(0) !important;
    }

    /* Secondary Button */
    .stButton > button:not([kind="primary"]) {
        background-color: rgba(0, 153, 255, 0.1) !important;
        color: #00ccff !important;
        border: 1px solid #0099ff !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
        font-weight: 500 !important;
        box-shadow: 0 0 10px rgba(0, 153, 255, 0.2) !important;
    }

    .stButton > button:not([kind="primary"]):hover {
        background-color: rgba(0, 204, 255, 0.2) !important;
        border-color: #00ccff !important;
        box-shadow: 0 0 15px rgba(0, 204, 255, 0.4) !important;
    }

    /* Metric Cards - Premium Glowing Look */
    [data-testid="stMetricValue"] {
        color: #00eeff !important;
        font-weight: 800 !important;
        font-size: 2.2em !important;
        text-shadow: 0 0 15px rgba(0, 238, 255, 0.5) !important;
    }

    [data-testid="stMetricLabel"] {
        color: #6b8aaa !important;
        font-size: 0.95em !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }

    .stMetric {
        background: linear-gradient(135deg, rgba(10, 15, 35, 0.8) 0%, rgba(20, 30, 60, 0.6) 100%) !important;
        border: 1.5px solid #0099ff !important;
        border-radius: 12px !important;
        padding: 20px !important;
        box-shadow: 0 0 20px rgba(0, 153, 255, 0.15), inset 0 1px 0 rgba(0, 204, 255, 0.1) !important;
        transition: all 0.3s ease !important;
        backdrop-filter: blur(10px) !important;
    }

    .stMetric:hover {
        border-color: #00ccff !important;
        box-shadow: 0 0 30px rgba(0, 204, 255, 0.3), inset 0 1px 0 rgba(0, 238, 255, 0.2) !important;
    }

    /* Attack Flow Cards - Enhanced Blue Glow */
    .flow-card {
        background: linear-gradient(135deg, rgba(10, 15, 35, 0.9) 0%, rgba(20, 30, 60, 0.7) 100%) !important;
        border: 1.5px solid #0099ff !important;
        border-radius: 12px !important;
        padding: 20px 12px !important;
        margin: 8px !important;
        text-align: center !important;
        color: #00ccff !important;
        box-shadow: 0 0 25px rgba(0, 153, 255, 0.2), inset 0 0 15px rgba(0, 204, 255, 0.05) !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        backdrop-filter: blur(10px) !important;
    }

    .flow-card:hover {
        border-color: #00eeff !important;
        box-shadow: 0 0 40px rgba(0, 238, 255, 0.4), inset 0 0 20px rgba(0, 204, 255, 0.1) !important;
        transform: translateY(-4px) !important;
    }

    .flow-card h3 {
        font-size: 2.2em !important;
        margin: 8px 0 !important;
        color: #00eeff !important;
        text-shadow: 0 0 15px rgba(0, 238, 255, 0.4) !important;
    }

    .flow-card b {
        color: #00ccff !important;
        font-weight: 700 !important;
    }

    .flow-card small {
        color: #6b8aaa !important;
        display: block !important;
        margin: 6px 0 !important;
    }

    /* DataFrame Tables - Professional Blue Look */
    [data-testid="stTable"], .stDataFrame {
        background-color: rgba(10, 15, 35, 0.8) !important;
        border: 1px solid #0099ff !important;
        border-radius: 8px !important;
        overflow: hidden !important;
        box-shadow: 0 0 20px rgba(0, 153, 255, 0.15) !important;
    }

    thead th {
        background-color: rgba(10, 20, 50, 0.9) !important;
        color: #00ccff !important;
        font-weight: 700 !important;
        border-bottom: 2px solid #0099ff !important;
        padding: 14px !important;
        text-shadow: 0 0 10px rgba(0, 153, 255, 0.3) !important;
    }

    tbody td {
        border-bottom: 1px solid #1f3a5a !important;
        padding: 12px 14px !important;
        color: #a8c5dd !important;
    }

    tbody tr:hover {
        background-color: rgba(0, 153, 255, 0.08) !important;
    }

    /* Alert Cards - Severity-Based Colors */
    div.stAlert[data-baseweb="notification"] {
        background: linear-gradient(135deg, rgba(10, 15, 35, 0.9) 0%, rgba(20, 30, 60, 0.7) 100%) !important;
        border-left: 4px solid #00ccff !important;
        border-radius: 8px !important;
        padding: 16px !important;
        color: #a8c5dd !important;
        box-shadow: 0 0 20px rgba(0, 153, 255, 0.15) !important;
        backdrop-filter: blur(10px) !important;
    }

    /* Error Alert */
    div.stAlert[data-icon="error"] {
        border-left-color: #ff4466 !important;
    }

    /* Warning Alert */
    div.stAlert[data-icon="warning"] {
        border-left-color: #ffaa33 !important;
    }

    /* Success Alert */
    div.stAlert[data-icon="success"] {
        border-left-color: #00cc88 !important;
    }

    /* Info Alert */
    div.stAlert[data-icon="info"] {
        border-left-color: #00eeff !important;
    }

    /* Expander - Premium Styling */
    details {
        background: linear-gradient(135deg, rgba(10, 15, 35, 0.8) 0%, rgba(20, 30, 60, 0.6) 100%) !important;
        border: 1px solid #0099ff !important;
        border-radius: 8px !important;
        padding: 14px !important;
        margin: 8px 0 !important;
        box-shadow: 0 0 15px rgba(0, 153, 255, 0.1) !important;
        backdrop-filter: blur(10px) !important;
    }

    details summary {
        color: #00ccff !important;
        font-weight: 600 !important;
        cursor: pointer !important;
        text-shadow: 0 0 10px rgba(0, 204, 255, 0.2) !important;
    }

    details summary:hover {
        color: #00eeff !important;
    }

    /* Horizontal Rule */
    hr {
        border: none !important;
        border-top: 1px solid #1f3a5a !important;
        margin: 24px 0 !important;
    }

    /* Input Fields */
    input, select, textarea {
        background-color: rgba(10, 20, 50, 0.6) !important;
        color: #a8c5dd !important;
        border: 1px solid #0099ff !important;
        border-radius: 6px !important;
        padding: 10px 12px !important;
        box-shadow: 0 0 10px rgba(0, 153, 255, 0.1) !important;
    }

    input:focus, select:focus, textarea:focus {
        border-color: #00ccff !important;
        box-shadow: 0 0 0 3px rgba(0, 204, 255, 0.2), 0 0 15px rgba(0, 153, 255, 0.3) !important;
    }

    /* Sidebar Text */
    [data-testid="stSidebar"] h1 {
        color: #00eeff !important;
        margin-bottom: 4px !important;
        text-shadow: 0 0 20px rgba(0, 238, 255, 0.3) !important;
    }

    [data-testid="stSidebar"] .caption {
        color: #6b8aaa !important;
    }

    /* Progress Bar */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #0099ff 0%, #00ccff 100%) !important;
        box-shadow: 0 0 15px rgba(0, 204, 255, 0.5) !important;
    }

    /* Download Button */
    .stDownloadButton > button {
        background: linear-gradient(135deg, #00ccff 0%, #0099ff 100%) !important;
        color: #0a0e1a !important;
        border: 1px solid #00eeff !important;
        border-radius: 8px !important;
        font-weight: 700 !important;
        box-shadow: 0 0 20px rgba(0, 204, 255, 0.3) !important;
    }

    .stDownloadButton > button:hover {
        background: linear-gradient(135deg, #00eeff 0%, #00ccff 100%) !important;
        box-shadow: 0 0 30px rgba(0, 238, 255, 0.5) !important;
    }

    /* Code Block */
    pre {
        background-color: rgba(10, 20, 50, 0.8) !important;
        border: 1px solid #0099ff !important;
        border-radius: 8px !important;
        padding: 16px !important;
        color: #00ccff !important;
        box-shadow: 0 0 15px rgba(0, 153, 255, 0.1) !important;
    }

    code {
        background-color: rgba(10, 20, 50, 0.6) !important;
        color: #00eeff !important;
        border-radius: 4px !important;
        padding: 2px 6px !important;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Initialize Session State
if "agent" not in st.session_state:
    st.session_state.agent = CyberSageAgent()
if "investigation_result" not in st.session_state:
    st.session_state.investigation_result = None

# Sidebar Configuration
with st.sidebar:
    st.title("🛡️ CYBERSAGE")
    st.caption("DFIR & SOC Agentic AI Investigator")
    st.markdown("---")

    input_mode = st.radio("Select Input Data:", ["Demo Incident", "Upload Log File"])

    file_to_investigate = None
    parse_warning = None
    parse_error = None
    can_proceed = False

    if input_mode == "Demo Incident":
        demo_choice = st.selectbox(
            "Choose Scenario:",
            [
                "Scenario 1 — Account Compromise",
                "Scenario 2 — Phishing to Compromise",
                "Scenario 3 — Suspicious Data Access"
            ]
        )
        if "Scenario 1" in demo_choice:
            file_to_investigate = get_demo_data(1)
        elif "Scenario 2" in demo_choice:
            file_to_investigate = get_demo_data(2)
        else:
            file_to_investigate = get_demo_data(3)
        
        can_proceed = True

    else:
        uploaded_file = st.file_uploader("Upload CSV or TXT Log", type=["csv", "txt"])
        
        # Explicit Schema Guidance Notice for Judges & Users
        with st.expander("📋 Required Evidence Schema (DFIR/SOC)", expanded=True):
            st.markdown("""
            **Supported Core Columns:**
            - ⏱️ `timestamp` *(When)* — e.g. `2026-09-13 10:15:00`
            - 👤 `user` *(Who)* — e.g. `admin`, `j_smith`
            - 🌐 `ip` *(Where)* — e.g. `192.168.1.100`
            - ⚡ `event` *(What)* — e.g. `Failed Login`, `Data Exfiltration`

            *Accepts standard SIEM aliases (`src_ip`, `action`, `username`, `time`).*
            """)

        if uploaded_file is not None:
            success, df_parsed, parse_msg = parse_logs(uploaded_file)
            
            if not success:
                parse_error = parse_msg
                can_proceed = False
            else:
                file_to_investigate = df_parsed
                can_proceed = True
                if "Note:" in parse_msg or "auto-filled" in parse_msg:
                    parse_warning = parse_msg

    st.markdown("---")
    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        start_btn = st.button("🚀 Investigate", width='stretch', type="primary", disabled=not can_proceed)
    with col_btn2:
        clear_btn = st.button("🔄 Reset", width='stretch')

    if clear_btn:
        st.session_state.investigation_result = None
        st.rerun()

# Title & Dashboard Header
st.title("🛡️ CYBERSAGE Dashboard")
st.caption("DFIR Artifact Reconstruction, SOC Incident Analysis & Generative Forensics")

if parse_error:
    st.error(f"❌ **Log Parsing Error:** {parse_error}")
    st.info("💡 **Required Columns:** Ensure CSV contains `timestamp`, `user`, `ip`, and `event` (or standard aliases).")

if parse_warning:
    st.warning(f"⚠️ **Schema Notice:** {parse_warning}")

res = st.session_state.investigation_result

# Execution Pipeline
if start_btn:
    if file_to_investigate is not None:
        with st.spinner("🤖 CyberSage Agent analyzing artifacts & building forensic timeline..."):
            try:
                res_output = st.session_state.agent.run_investigation(file_to_investigate)
                st.session_state.investigation_result = res_output
                st.success("Analysis Complete!")
                st.rerun()
            except Exception as e:
                st.error(f"❌ **Investigation Pipeline Error:** {str(e)}")
    else:
        st.warning("Please upload a log file or select a valid demo scenario.")

# Dashboard Visual Render
if res is None:
    st.info("👈 Select a Demo Incident or upload log files in the sidebar, then click **Investigate** to start.")
    
    st.subheader("📋 Core Platform Architecture")
    st.markdown("""
    - 🔍 **DFIR & SIEM Normalization**: Maps raw CSV/TXT logs to standard forensic schemas.
    - ⚡ **Deterministic Risk Engine**: Generates mathematically verifiable threat scores.
    - 🗺️ **MITRE ATT&CK Correlation**: Maps evidence directly to adversary TTPs.
    - 🤖 **Agentic Incident Reasoning**: Multi-stage autonomous forensic reconstruction.
    - 📊 **Executive & Technical Narrative**: AI-synthesized root cause & evidence reports.
    """)
else:
    # 1. Incident Overview Cards
    st.markdown("---")
    st.subheader("🚨 Incident Overview")
    
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Risk Score", f"{res.get('risk_score', 0)} / 100")
    with c2:
        st.metric("Severity Level", res.get('risk_level', 'N/A'))
    with c3:
        st.metric("Confidence", res.get('confidence', 'N/A'))
    with c4:
        st.metric("Events Analyzed", res.get('events_count', 0))
    with c5:
        st.metric("Anomalies Flagged", len(res.get('suspicious_events', [])))

    # 2. Agent Workflow Execution Progress
    with st.expander("🤖 Agentic Investigation Steps Completed", expanded=False):
        for step in res.get('steps_completed', []):
            st.write(step)

    # 3. Dynamic Narrative & Threat Classification (DFIR + SOC Cleaned)
    st.markdown("---")
    col_story, col_summary = st.columns([2, 1])

    with col_story:
        st.subheader("📖 Incident & Forensic Narrative")
        narrative_text = res.get('attack_story', 'No narrative generated.')
        
        # Ensure clean terminology across SOC and DFIR execution
        clean_narrative = narrative_text.replace("SOC Security Operations Center", "Incident Response & Forensics Team")
        st.info(clean_narrative)

    with col_summary:
        st.subheader("🎯 Primary Threat Vector")
        st.warning(f"**Classified Threat:**\n{res.get('classified_attack', 'Unclassified Incident')}")
        st.write(f"**Affected User(s):** {', '.join(res.get('affected_users', [])) or 'N/A'}")
        st.write(f"**Involved IP(s):** {', '.join(res.get('involved_ips', [])) or 'N/A'}")

    # 4. Dynamic Visual Attack Flow
    st.markdown("---")
    st.subheader("🎯 Reconstructed Attack & Evidence Flow")

    raw_events = res.get('raw_events', [])
    if raw_events:
        flow_cols = st.columns(min(len(raw_events), 6))
        
        icon_map = {
            "login": "🔑",
            "failed": "⚠️",
            "admin": "🖥️",
            "sensitive": "📁",
            "large data": "📤",
            "email": "📧",
            "link": "🔗",
            "database": "🗄️",
            "settings": "⚙️"
        }

        for idx, ev in enumerate(raw_events[:6]):
            ev_name = str(ev.get('event', 'Event'))
            icon = "⚡"
            for k, v in icon_map.items():
                if k in ev_name.lower():
                    icon = v
                    break
            
            with flow_cols[idx]:
                st.markdown(
                    f"""
                    <div class="flow-card">
                        <h3>{icon}</h3>
                        <b>Step {idx+1}</b><br/>
                        <small>{ev.get('timestamp', '')}</small><br/>
                        <b>{ev_name}</b><br/>
                        <span style="color:#00dd55">{ev.get('user', '')}</span>
                    </div>
                    """, 
                    unsafe_allow_html=True
                )

    # 5. MITRE ATT&CK & Risk Factors
    st.markdown("---")
    col_mitre, col_risk = st.columns([1, 1])

    with col_mitre:
        st.subheader("🧩 MITRE ATT&CK Mappings")
        mitre_list = res.get('mitre_techniques', [])
        if mitre_list:
            for m in mitre_list:
                st.markdown(f"**[{m.get('id', 'N/A')}] {m.get('name', 'N/A')}** - *{m.get('tactic', 'N/A')}*")
                st.caption(f"Reason: {m.get('reason', '')}")
                st.caption(m.get('description', ''))
                st.markdown("---")
        else:
            st.write("No direct MITRE ATT&CK techniques matched.")

    with col_risk:
        st.subheader("⚠️ Deterministic Risk Analysis")
        score = res.get('risk_score', 0)
        st.progress(min(max(score / 100.0, 0.0), 1.0))
        st.write(f"**Risk Severity:** {res.get('risk_level', 'N/A')}")
        st.markdown("**Triggered Risk Rules:**")
        for factor in res.get('risk_factors', []):
            st.write(f"• {factor}")

    # 6. Evidence Timeline
    st.markdown("---")
    st.subheader("🕒 Forensic Evidence Timeline")
    
    if raw_events:
        df_events = pd.DataFrame(raw_events)
        st.dataframe(
            df_events,
            width='stretch',
            hide_index=True
        )

    # 7. Defensive Response Plan & Report Export
    st.markdown("---")
    col_resp, col_rep = st.columns([1, 1])

    with col_resp:
        st.subheader("🛡️ Recommended Mitigation Plan")
        response_plan = res.get('response_plan', [])
        for idx, rec in enumerate(response_plan, 1):
            st.write(f"**{idx}.** {rec}")

    with col_rep:
        st.subheader("📄 Export Forensic & Incident Report")
        report_text = res.get('final_report', 'No report available.')
        st.download_button(
            label="📥 Download Full Report (TXT)",
            data=report_text,
            file_name="CyberSage_Incident_Report.txt",
            mime="text/plain",
            width='stretch'
        )
        with st.expander("Preview Raw Report Text", expanded=False):
            st.code(report_text, language="text")
