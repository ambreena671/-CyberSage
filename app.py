"""
CyberSage - Streamlit SOC Incident Dashboard UI
Custom dark-themed cybersecurity interface displaying investigation steps, risk cards, 
attack flows, evidence timelines, entity breakdowns, and downloadable reports.
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
    page_title="CyberSage | AI Incident Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cyber Dark Theme & High Contrast Green Accents
CUSTOM_CSS = """
<style>
    /* Main Dashboard Background */
    .stApp {
        background-color: #0a0e14 !important;
        color: #00ff66 !important;
    }

    /* Sidebar Background & Border */
    [data-testid="stSidebar"] {
        background-color: #000000 !important;
        border-right: 2px solid #00ff66 !important;
    }

    /* General Typography */
    h1, h2, h3, h4, h5, h6, p, label, span, div, small, b, strong, caption {
        color: #00ff66 !important;
    }

    /* Streamlit Widget Text Fixes */
    div[data-baseweb="select"] > div, div[data-baseweb="base-input"] {
        background-color: #000000 !important;
        color: #00ff66 !important;
        border: 1px solid #00ff66 !important;
    }
    
    /* Primary Button */
    .stButton > button[kind="primary"] {
        background-color: #000000 !important;
        color: #00ff66 !important;
        border: 2px solid #00ff66 !important;
        border-radius: 8px !important;
        font-weight: bold !important;
        box-shadow: 0 0 10px rgba(0, 255, 102, 0.5) !important;
        transition: all 0.3s ease !important;
    }
    .stButton > button[kind="primary"]:hover {
        background-color: #00ff66 !important;
        color: #000000 !important;
        box-shadow: 0 0 15px rgba(0, 255, 102, 0.9) !important;
    }

    /* Metric Cards */
    [data-testid="stMetricValue"] {
        color: #00ff66 !important;
        font-weight: 800;
    }
    .stMetric {
        background-color: #000000 !important;
        border: 2px solid #00ff66 !important;
        border-radius: 10px;
        padding: 14px;
    }

    /* Custom Flow Cards */
    .flow-card {
        background-color: #000000 !important;
        border: 2px solid #00ff66 !important;
        border-radius: 10px;
        padding: 15px;
        margin: 5px;
        text-align: center;
        color: #00ff66 !important;
        box-shadow: 0 4px 10px rgba(0,255,102,0.2);
    }

    /* Table Styling */
    [data-testid="stTable"], .stDataFrame {
        background-color: #000000 !important;
        border: 1px solid #00ff66 !important;
    }
    
    .streamlit-expanderHeader {
        background-color: #000000 !important;
        border: 1px solid #00ff66 !important;
        border-radius: 5px;
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
    st.caption("Agentic AI Cyber Incident Investigator")
    st.markdown("---")

    input_mode = st.radio("Select Input Data:", ["Demo Incident", "Upload Log File"])

    file_to_investigate = None
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
        scenario_id = 1 if "Scenario 1" in demo_choice else (2 if "Scenario 2" in demo_choice else 3)
        file_to_investigate = get_demo_data(scenario_id)
        can_proceed = True

    else:
        uploaded_file = st.file_uploader("Upload CSV or TXT Log", type=["csv", "txt"])
        if uploaded_file is not None:
            try:
                parsed_res = parse_logs(uploaded_file)
                if isinstance(parsed_res, tuple):
                    df_parsed = parsed_res[1]
                else:
                    df_parsed = parsed_res

                if df_parsed is None or (isinstance(df_parsed, pd.DataFrame) and df_parsed.empty):
                    parse_error = "Could not parse log data or uploaded file is empty."
                    can_proceed = False
                else:
                    file_to_investigate = df_parsed
                    can_proceed = True
            except Exception as e:
                parse_error = f"Error during parsing: {str(e)}"
                can_proceed = False

    st.markdown("---")
    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        start_btn = st.button("🚀 Investigate", width='stretch', type="primary", disabled=not can_proceed)
    with col_btn2:
        clear_btn = st.button("🔄 Reset", width='stretch')

    if clear_btn:
        st.session_state.investigation_result = None
        st.rerun()

# Dashboard Title
st.title("🛡️ CYBERSAGE Dashboard")
st.caption("Autonomous Incident Analysis, Deterministic Scoring & Generative Intelligence")

if parse_error:
    st.error(f"❌ **Log Parsing Error:** {parse_error}")
    st.info("💡 **Format Guidance:** Upload CSV/TXT files containing headers like `timestamp`, `event`, `user`, and `ip`.")

res = st.session_state.investigation_result

# Execution Logic
if start_btn:
    if file_to_investigate is not None:
        with st.spinner("🤖 CyberSage Agent conducting multi-step investigation..."):
            try:
                res_output = st.session_state.agent.run_investigation(file_to_investigate)
                st.session_state.investigation_result = res_output
                st.success("Investigation Complete!")
                st.rerun()
            except Exception as e:
                st.error(f"❌ **Investigation Pipeline Error:** {str(e)}")
    else:
        st.warning("Please upload a log file or select a valid demo scenario.")

# Dashboard Layout
if res is None:
    st.info("👈 Select a Demo Incident or upload log files in the sidebar, then click **Investigate** to start.")
    
    st.subheader("📋 System Capabilities")
    st.markdown("""
    - 🔍 **Log Normalization**: Parses standard CSV/TXT authentication and system logs.
    - ⚡ **Deterministic Risk Engine**: Computes entity-level & global risk scores via Python logic.
    - 🗺️ **MITRE ATT&CK Mapping**: Correlates suspicious behaviors directly to MITRE TTPs.
    - 🤖 **Agentic Reasoning**: Multi-step automated threat investigation pipeline.
    - 📊 **Executive Attack Narrative**: AI-generated incident reports and mitigation playbooks.
    """)
else:
    # Incident Metrics
    st.markdown("---")
    st.subheader("🚨 Incident Overview")
    
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Global Risk Score", f"{res.get('risk_score', 0)} / 100")
    with c2:
        st.metric("Severity Level", res.get('risk_level', 'N/A'))
    with c3:
        st.metric("Confidence", res.get('confidence', 'N/A'))
    with c4:
        st.metric("Events Analyzed", res.get('events_count', 0))
    with c5:
        st.metric("Anomalies Flagged", len(res.get('suspicious_events', [])))

    # Agent Steps
    with st.expander("🤖 Agentic Investigation Steps Completed", expanded=False):
        for step in res.get('steps_completed', []):
            st.write(f"✓ {step}")

    # Attack Story & Vector
    st.markdown("---")
    col_story, col_summary = st.columns([2, 1])

    with col_story:
        st.subheader("📖 Executive Attack Narrative")
        st.info(res.get('attack_story', 'No story generated.'))

    with col_summary:
        st.subheader("🎯 Primary Threat")
        st.warning(f"**Classified Vector:**\n{res.get('classified_attack', 'Unclassified')}")
        st.write(f"**Affected User(s):** {', '.join(res.get('affected_users', []))}")
        st.write(f"**Involved IP(s):** {', '.join(res.get('involved_ips', []))}")

    # Attack Flow
    st.markdown("---")
    st.subheader("🎯 Visual Attack Flow")

    raw_events = res.get('raw_events', [])
    if raw_events:
        display_events = raw_events[:6]
        flow_cols = st.columns(len(display_events))
        
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

        for idx, ev in enumerate(display_events):
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
                        <span style="color:#00ff66">{ev.get('user', '')}</span>
                    </div>
                    """, 
                    unsafe_allow_html=True
                )

    # Tabs
    st.markdown("---")
    tab1, tab2 = st.tabs(["🧩 MITRE ATT&CK & Risk Rules", "👤 Per-User Risk Breakdown"])

    with tab1:
        col_mitre, col_risk = st.columns([1, 1])
        with col_mitre:
            st.subheader("MITRE ATT&CK Mappings")
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
            st.subheader("Risk Factors & Scoring")
            score = res.get('risk_score', 0)
            st.progress(min(max(score / 100.0, 0.0), 1.0))
            st.write(f"**Overall Severity:** {res.get('risk_level', 'N/A')}")
            st.markdown("**Triggered Risk Rules:**")
            for factor in res.get('risk_factors', []):
                st.write(f"• {factor}")

    with tab2:
        st.subheader("Entity-Level Risk Analysis")
        entity_data = res.get('entities', {})
        if entity_data:
            table_rows = []
            for user, details in entity_data.items():
                table_rows.append({
                    "User / Entity": user,
                    "Risk Score": details.get("risk_score", 0),
                    "Severity": details.get("risk_level", "LOW"),
                    "Triggered Factors": ", ".join(details.get("risk_factors", [])) or "None (Normal Behavior)"
                })
            
            df_entities = pd.DataFrame(table_rows)
            st.dataframe(
                df_entities,
                width='stretch',
                hide_index=True
            )
        else:
            st.info("No entity-level breakdown available for this log set.")

    # Evidence Timeline
    st.markdown("---")
    st.subheader("🕒 Evidence Timeline")
    if raw_events:
        df_events = pd.DataFrame(raw_events)
        st.dataframe(
            df_events,
            width='stretch',
            hide_index=True
        )

    # Report Export
    st.markdown("---")
    col_resp, col_rep = st.columns([1, 1])

    with col_resp:
        st.subheader("🛡️ Defensive Response Plan")
        response_plan = res.get('response_plan', [])
        for idx, rec in enumerate(response_plan, 1):
            st.write(f"**{idx}.** {rec}")

    with col_rep:
        st.subheader("📄 Incident Report Export")
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
