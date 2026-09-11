"""
CyberSage - Streamlit SOC Incident Dashboard UI
Custom dark-themed cybersecurity interface displaying investigation steps, risk cards, 
attack flows, evidence timelines, and downloadable reports.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from agent import CyberSageAgent
from demo_data import get_demo_data

# Page Configuration
st.set_page_config(
    page_title="CyberSage | AI Incident Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Dark Purple Sidebar & Light Dusty Main Theme
CUSTOM_CSS = """
<style>
    /* Main App Background (Light Dust / Off-White) */
    .stApp {
        background-color: #f4f3ef;
        color: #2b2b2b;
    }

    /* Sidebar Background (Dark Cyber Purple) */
    [data-testid="stSidebar"] {
        background-color: #1a0b2e;
        color: #f4f3ef;
    }
    
    /* Sidebar Text & Titles */
    [data-testid="stSidebar"] h1, 
    [data-testid="stSidebar"] h2, 
    [data-testid="stSidebar"] h3, 
    [data-testid="stSidebar"] p, 
    [data-testid="stSidebar"] label {
        color: #e9d5ff !important;
    }

    /* Primary Investigate Button (Vibrant Neon Purple) */
    .stButton > button[kind="primary"] {
        background-color: #7e22ce !important;
        color: #ffffff !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: bold !important;
        box-shadow: 0 4px 10px rgba(126, 34, 206, 0.4) !important;
        transition: all 0.3s ease !important;
    }
    .stButton > button[kind="primary"]:hover {
        background-color: #9333ea !important;
        box-shadow: 0 6px 15px rgba(147, 51, 234, 0.6) !important;
        transform: translateY(-1px);
    }

    /* Metric Cards (Dusty Card Background) */
    [data-testid="stMetricValue"] {
        color: #581c87 !important;
        font-weight: 700;
    }
    .stMetric {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 14px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    }

    /* Attack Flow Cards */
    .flow-card {
        background-color: #ffffff;
        border: 1px solid #d8b4fe;
        border-radius: 12px;
        padding: 15px;
        margin: 5px;
        text-align: center;
        color: #2b2b2b;
        box-shadow: 0 4px 10px rgba(126, 34, 206, 0.08);
    }

    /* Information Boxes & Highlights */
    .stAlert {
        border-radius: 10px !important;
    }
</style>
"""
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

    else:
        uploaded_file = st.file_uploader("Upload CSV or TXT Log", type=["csv", "txt"])
        if uploaded_file is not None:
            file_to_investigate = uploaded_file

    st.markdown("---")
    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        start_btn = st.button("🚀 Investigate", use_container_width=True, type="primary")
    with col_btn2:
        clear_btn = st.button("🔄 Reset", use_container_width=True)

    if clear_btn:
        st.session_state.investigation_result = None
        st.rerun()

# Execution Logic
if start_btn:
    if file_to_investigate is not None:
        with st.spinner("🤖 CyberSage Agent conducting multi-step investigation..."):
            try:
                res = st.session_state.agent.run_investigation(file_to_investigate)
                st.session_state.investigation_result = res
                st.success("Investigation Complete!")
            except Exception as e:
                st.error(f"Investigation Error: {str(e)}")
    else:
        st.warning("Please upload a log file or select a valid demo scenario.")

# Main Dashboard
st.title("🛡️ CYBERSAGE Dashboard")
st.caption("Autonomous Incident Analysis, Deterministic Scoring & Generative Intelligence")

res = st.session_state.investigation_result

if res is None:
    st.info("👈 Select a Demo Incident or upload log files in the sidebar, then click **Investigate** to start.")
    
    # Placeholder preview grid
    st.subheader("📋 System Ready")
    st.markdown("""
    **CyberSage Capabilities:**
    - 🔍 **Log Normalization**: Parses standard CSV/TXT auth and system logs.
    - ⚡ **Deterministic Engine**: Computes exact risk scores & flags anomalies via Python.
    - 🗺️ **MITRE ATT&CK Mapping**: Maps behavioral indicators to verified technique IDs.
    - 🤖 **Agentic Reasoning**: Multi-step sequential state progression.
    - 📊 **Executive Attack Narrative**: AI-generated threat storytelling & incident reporting.
    """)
else:
    # 1. Incident Overview Cards
    st.markdown("---")
    st.subheader("🚨 Incident Overview")
    
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Risk Score", f"{res['risk_score']} / 100")
    with c2:
        st.metric("Severity Level", res['risk_level'])
    with c3:
        st.metric("Confidence", res['confidence'])
    with c4:
        st.metric("Events Analyzed", res['events_count'])
    with c5:
        st.metric("Anomalies Flagged", len(res['suspicious_events']))

    # 2. Agent Workflow Execution Progress
    with st.expander("🤖 Agentic Investigation Steps Completed", expanded=False):
        for step in res['steps_completed']:
            st.write(step)

    # 3. Incident Story & Classification
    st.markdown("---")
    col_story, col_summary = st.columns([2, 1])

    with col_story:
        st.subheader("📖 Executive Attack Narrative")
        st.info(res['attack_story'])

    with col_summary:
        st.subheader("🎯 Primary Threat")
        st.warning(f"**Classified Vector:**\n{res['classified_attack']}")
        st.write(f"**Affected User(s):** {', '.join(res['affected_users'])}")
        st.write(f"**Involved IP Address(es):** {', '.join(res['involved_ips'])}")

    # 4. Dynamic Visual Attack Flow
    st.markdown("---")
    st.subheader("🎯 Visual Attack Flow")

    raw_events = res['raw_events']
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
        ev_name = ev['event']
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
                    <small>{ev['timestamp']}</small><br/>
                    <b>{ev_name}</b><br/>
                    <span style="color:#8b949e">{ev['user']}</span>
                </div>
                """, 
                unsafe_allow_html=True
            )

    # 5. MITRE ATT&CK & Risk Factors
    st.markdown("---")
    col_mitre, col_risk = st.columns([1, 1])

    with col_mitre:
        st.subheader("🧩 MITRE ATT&CK Mappings")
        if res['mitre_techniques']:
            for m in res['mitre_techniques']:
                st.markdown(f"**[{m['id']}] {m['name']}** - *{m['tactic']}*")
                st.caption(f"Reason: {m['reason']}")
                st.caption(m['description'])
                st.markdown("---")
        else:
            st.write("No direct MITRE ATT&CK techniques matched.")

    with col_risk:
        st.subheader("⚠️ Risk Analysis & Factors")
        st.progress(res['risk_score'] / 100)
        st.write(f"**Risk Severity:** {res['risk_level']}")
        st.markdown("**Deterministic Factors:**")
        for factor in res['risk_factors']:
            st.write(f"• {factor}")

    # 6. Evidence Timeline
    st.markdown("---")
    st.subheader("🕒 Evidence Timeline")
    
    df_events = pd.DataFrame(res['raw_events'])
    st.dataframe(
        df_events,
        use_container_width=True,
        hide_index=True
    )

    # 7. Defensive Response Plan & Report Export
    st.markdown("---")
    col_resp, col_rep = st.columns([1, 1])

    with col_resp:
        st.subheader("🛡️ Defensive Response Plan")
        for idx, rec in enumerate(res['response_plan'], 1):
            st.write(f"**{idx}.** {rec}")

    with col_rep:
        st.subheader("📄 Incident Report Export")
        st.download_button(
            label="📥 Download Full Report (TXT)",
            data=res['final_report'],
            file_name="CyberSage_Incident_Report.txt",
            mime="text/plain",
            use_container_width=True
        )
        with st.expander("Preview Raw Report Text", expanded=False):
            st.code(res['final_report'], language="text")
