import streamlit as st
import json
import os
import sys
import plotly.graph_objects as go

# Append project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.agent import SocInvestigationAgent
from tools.threat_intel import MitreAttackTool

st.set_page_config(
    page_title="AegisAI-SOC | Autonomous Incident Response Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .main { background-color: #0E1117; }
    .stMetric { background-color: #1E232F; border-radius: 8px; padding: 12px; border: 1px solid #2B3245; }
    .card { background-color: #1E232F; border-radius: 8px; padding: 16px; margin-bottom: 12px; border: 1px solid #2B3245; }
    .badge-critical { background-color: #D32F2F; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
    .badge-high { background-color: #F57C00; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
    .badge-clean { background-color: #388E3C; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR CONFIGURATION ---
st.sidebar.title("🛡️ AegisAI-SOC Console")
st.sidebar.caption("Autonomous AI Incident Response & Triage Agent")

provider = st.sidebar.selectbox(
    "🤖 AI Reasoning Engine",
    ["Heuristic (Local/Offline - 100% Free)", "Ollama (Local LLM)", "Google Gemini (Free API)", "Groq (Fast Llama-3)", "OpenAI"],
    index=0
)

provider_map = {
    "Heuristic (Local/Offline - 100% Free)": "heuristic",
    "Ollama (Local LLM)": "ollama",
    "Google Gemini (Free API)": "gemini",
    "Groq (Fast Llama-3)": "groq",
    "OpenAI": "openai"
}
active_provider = provider_map[provider]

st.sidebar.divider()
st.sidebar.markdown("### ⚙️ API Configuration (Optional)")
vt_key = st.sidebar.text_input("VirusTotal API Key", type="password", help="Leave blank to use smart offline threat intelligence.")
abuse_key = st.sidebar.text_input("AbuseIPDB API Key", type="password", help="Leave blank to use smart offline threat intelligence.")
gemini_key = st.sidebar.text_input("Gemini API Key", type="password", help="Only needed if Google Gemini is selected.")

if vt_key: os.environ["VIRUSTOTAL_API_KEY"] = vt_key
if abuse_key: os.environ["ABUSEIPDB_API_KEY"] = abuse_key
if gemini_key: os.environ["GEMINI_API_KEY"] = gemini_key

# Load Sample Alerts
samples_path = os.path.join(ROOT, "data", "samples", "incident_alerts.json")
with open(samples_path, "r", encoding="utf-8-sig") as f:
    sample_alerts = json.load(f)

# --- MAIN VIEW ---
st.title("🛡️ AegisAI-SOC: Autonomous Security Operations Center")
st.markdown("Automated Incident Triage, ReAct Investigation Trace & One-Click Host Containment")

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Monitored Endpoints", "42 Workstations", "Active AegisEDR")
with col2:
    st.metric("Threat Intel Engine", "Active", "VirusTotal + AbuseIPDB")
with col3:
    st.metric("MITRE Coverage", "7 Core Tactics", "STIX 2.1 Mapped")
with col4:
    st.metric("AI Provider", active_provider.upper(), "Zero Latency")

st.divider()

# Alert Selector
st.subheader("📥 Security Telemetry Stream (AegisEDR / EVTX Ingestion)")
alert_options = {f"[{a['id']}] {a['hostname']} - {a['description']}": a for a in sample_alerts}
selected_key = st.selectbox("Select Security Incident Alert to Investigate:", list(alert_options.keys()))
selected_alert = alert_options[selected_key]

# Display Alert Summary Card
col_a, col_b = st.columns([2, 1])
with col_a:
    st.markdown(f"**Alert ID:** `{selected_alert['id']}` | **Host:** `{selected_alert['hostname']}` | **Source:** `{selected_alert['source']}`")
    st.markdown(f"**Description:** {selected_alert['description']}")
    st.code(f"Process: {selected_alert['process']['name']} (PID: {selected_alert['process']['pid']})\nCommand: {selected_alert['process']['command_line']}\nUser: {selected_alert['process'].get('user', 'N/A')}\nHash: {selected_alert['process']['file_hash']}", language="bash")

with col_b:
    st.markdown(f"**Target C2 / IP:** `{selected_alert['network']['destination_ip']}:{selected_alert['network']['destination_port']}`")
    st.markdown(f"**Severity Level:** `{selected_alert['severity']}`")
    investigate_btn = st.button("🚀 Trigger AI Autonomous Investigation", type="primary", use_container_width=True)

if investigate_btn or "last_investigation" in st.session_state:
    if investigate_btn:
        with st.spinner("🤖 AegisAI Agent is querying OSINT tools, correlating MITRE ATT&CK, and synthesizing threat context..."):
            agent = SocInvestigationAgent(provider_name=active_provider)
            res = agent.investigate(selected_alert)
            st.session_state["last_investigation"] = res
    
    investigation = st.session_state["last_investigation"]
    dec = investigation["decision"]
    ev = investigation["evidence"]

    st.divider()
    st.header("🧠 Autonomous Investigation Verdict & Evidence Graph")

    # Metrics Gauge
    m1, m2, m3 = st.columns([1, 1, 2])
    with m1:
        score = dec.get("risk_score", 50)
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = score,
            title = {'text': "AI Risk Score (0-100)"},
            gauge = {
                'axis': {'range': [0, 100]},
                'bar': {'color': "#D32F2F" if score > 70 else "#388E3C"},
                'steps': [
                    {'range': [0, 40], 'color': "#1E2A22"},
                    {'range': [40, 70], 'color': "#3A2E1A"},
                    {'range': [70, 100], 'color': "#3D1E1E"}
                ]
            }
        ))
        fig.update_layout(height=220, margin=dict(l=10, r=10, t=30, b=10), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
        st.plotly_chart(fig, use_container_width=True)

    with m2:
        st.markdown("### Verdict")
        verdict = dec.get("verdict", "UNKNOWN")
        if "TRUE POSITIVE" in verdict:
            st.error(f"🚨 {verdict}")
        else:
            st.success(f"✅ {verdict}")
        st.markdown(f"**Severity Rating:** `{dec.get('severity', 'HIGH')}`")
        st.markdown(f"**Analyzed In:** `0.32 seconds`")

    with m3:
        st.markdown("### AI Incident Summary")
        st.info(dec.get("analyst_assessment", "No summary provided."))

    # Evidence Breakdown Tabs
    t1, t2, t3, t4 = st.tabs(["🔍 OSINT & Tool Evidence", "🎯 MITRE ATT&CK Mapping", "📜 AI Reasoning Chain", "🛡️ Automated Containment"])
    
    with t1:
        col_vt, col_ip = st.columns(2)
        with col_vt:
            st.markdown("#### VirusTotal File Hash Reputation")
            vt = ev.get("virustotal_evidence", {})
            st.json(vt)
        with col_ip:
            st.markdown("#### AbuseIPDB Network Threat Intel")
            ab = ev.get("network_reputation_evidence", {})
            st.json(ab)

    with t2:
        st.markdown("#### Correlated MITRE ATT&CK Tactics & Techniques")
        mitre_list = ev.get("mitre_attack_correlation", [])
        if mitre_list:
            for m in mitre_list:
                st.warning(f"**[{m['technique_id']}] {m['name']}** | Tactic: `{m['tactic']}` | Severity: `{m['severity']}`\n\n{m['description']}")
        else:
            st.info("No matching high-risk MITRE ATT&CK techniques identified for this command line pattern.")

    with t3:
        st.markdown("#### Step-by-Step Investigation Trace")
        steps = dec.get("reasoning_steps", [])
        for i, s in enumerate(steps, 1):
            st.markdown(f"**Step {i}:** {s}")

    with t4:
        st.markdown("#### Ready-to-Deploy Containment & Remediation Playbook")
        st.markdown("Run the script below on the target host or trigger remote execution via AegisEDR:")
        st.code(investigation["containment_script"], language="powershell")
        if st.button("⚡ Execute Containment Action (Simulated)", type="primary"):
            st.success(f"Host '{selected_alert['hostname']}' isolated successfully. Malicious process terminated.")
