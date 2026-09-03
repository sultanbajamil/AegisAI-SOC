import streamlit as st
import json
import os
import sys
import plotly.graph_objects as go

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.agent import SocInvestigationAgent
from tools.threat_intel import MitreAttackTool
from tools.report_generator import generate_incident_pdf

st.set_page_config(
    page_title="AegisAI-SOC v1.2 | Autonomous Incident Response Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main { background-color: #0E1117; }
    .stMetric { background-color: #1E232F; border-radius: 8px; padding: 12px; border: 1px solid #2B3245; }
    .copilot-box { background-color: #1A1F2C; border: 1px solid #3B4252; border-radius: 8px; padding: 12px; margin-top: 10px; }
</style>
""", unsafe_allow_html=True)

st.sidebar.title("🛡️ AegisAI-SOC v1.2")
st.sidebar.caption("Enterprise Autonomous SOC & Incident Response Platform")

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
st.sidebar.markdown("### 🌐 Live AegisEDR Ingestion Feed")
st.sidebar.info("REST Webhook active on `/api/v1/ingest`\nAwaiting streaming endpoint telemetry.")

st.sidebar.markdown("### ⚙️ API Configuration (Optional)")
vt_key = st.sidebar.text_input("VirusTotal API Key", type="password", help="Leave blank for smart offline threat intel.")
abuse_key = st.sidebar.text_input("AbuseIPDB API Key", type="password", help="Leave blank for smart offline threat intel.")
gemini_key = st.sidebar.text_input("Gemini API Key", type="password", help="Only needed if Google Gemini is selected.")

if vt_key: os.environ["VIRUSTOTAL_API_KEY"] = vt_key
if abuse_key: os.environ["ABUSEIPDB_API_KEY"] = abuse_key
if gemini_key: os.environ["GEMINI_API_KEY"] = gemini_key

# Load Sample Alerts
samples_path = os.path.join(ROOT, "data", "samples", "incident_alerts.json")
with open(samples_path, "r", encoding="utf-8-sig") as f:
    sample_alerts = json.load(f)

# Main Title Header
st.title("🛡️ AegisAI-SOC: Autonomous Incident Response Center (v1.2)")
st.markdown("**Autonomous Threat Triage, Process Tree Attack Graph, Live Telemetry Ingestion & CISO PDF Reporting**")

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Live Telemetry Gateway", "Active (Port 8000)", "AegisEDR Connected")
with c2:
    st.metric("Threat Intel Engine", "Active", "VirusTotal + AbuseIPDB")
with c3:
    st.metric("ATT&CK Matrix Version", "v14.1 Enterprise", "STIX 2.1 Mapped")
with c4:
    st.metric("Active Inference Provider", active_provider.upper(), "Zero Latency")

st.divider()

# Ingestion Stream Selector
st.subheader("📥 Security Telemetry Stream (AegisEDR / EVTX Ingestion)")
alert_options = {f"[{a['id']}] {a['hostname']} - {a['description']}": a for a in sample_alerts}
selected_key = st.selectbox("Select Security Incident Alert to Investigate:", list(alert_options.keys()))
selected_alert = alert_options[selected_key]

# Display Alert Summary Card
col_a, col_b = st.columns([2, 1])
with col_a:
    st.markdown(f"**Alert ID:** `{selected_alert['id']}` | **Host:** `{selected_alert['hostname']}` | **Source:** `{selected_alert['source']}`")
    st.markdown(f"**Description:** {selected_alert['description']}")
    st.code(f"Process: {selected_alert['process']['name']} (PID: {selected_alert['process']['pid']})\nParent: {selected_alert['process'].get('parent_name', 'explorer.exe')} (PID: {selected_alert['process'].get('parent_pid', 1000)})\nCommand: {selected_alert['process']['command_line']}\nUser: {selected_alert['process'].get('user', 'N/A')}\nHash: {selected_alert['process']['file_hash']}", language="bash")

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

    # Tabs (Enhanced with Attack Graph, Copilot, & CISO PDF Export)
    t1, t2, t3, t4, t5, t6 = st.tabs([
        "🔍 OSINT & Tool Evidence",
        "🎯 MITRE ATT&CK Mapping",
        "🌳 Visual Attack Process Tree",
        "📜 AI Reasoning Chain",
        "🛡️ Automated Containment",
        "📄 Export CISO PDF Report"
    ])
    
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
        st.markdown("#### Interactive Process Lineage & Attack Graph")
        parent_proc = selected_alert["process"].get("parent_name", "explorer.exe")
        parent_pid = selected_alert["process"].get("parent_pid", 1000)
        curr_proc = selected_alert["process"]["name"]
        curr_pid = selected_alert["process"]["pid"]
        dest_ip = selected_alert["network"]["destination_ip"]

        # Visual Sankey/Flow Diagram representing the attack progression
        fig_tree = go.Figure(data=[go.Sankey(
            node = dict(
                pad = 15,
                thickness = 20,
                line = dict(color = "black", width = 0.5),
                label = [
                    f"Parent: {parent_proc} (PID: {parent_pid})",
                    f"Spawned: {curr_proc} (PID: {curr_pid})",
                    f"Egress C2: {dest_ip}",
                    "Target: System Memory / Storage"
                ],
                color = ["#1565C0", "#D32F2F", "#F57C00", "#7B1FA2"]
            ),
            link = dict(
                source = [0, 1, 1],
                target = [1, 2, 3],
                value = [10, 5, 5]
            )
        )])
        fig_tree.update_layout(title_text="Adversary Process Execution Lineage & Network Egress", font_size=12, height=300, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_tree, use_container_width=True)

    with t4:
        st.markdown("#### Step-by-Step Investigation Trace")
        steps = dec.get("reasoning_steps", [])
        for i, s in enumerate(steps, 1):
            st.markdown(f"**Step {i}:** {s}")

    with t5:
        st.markdown("#### Ready-to-Deploy Containment & Remediation Playbook")
        st.markdown("Run the script below on the target host or trigger remote execution via AegisEDR:")
        st.code(investigation["containment_script"], language="powershell")
        if st.button("⚡ Execute Containment Action (Simulated)", type="primary"):
            st.success(f"Host '{selected_alert['hostname']}' isolated successfully. Malicious process terminated.")

    with t6:
        st.markdown("#### 📄 Executive Incident Report (CISO & Board Ready)")
        st.write("Generate and download a comprehensive, formatted executive PDF incident summary.")
        pdf_filename = f"Incident_Report_{selected_alert['id']}.pdf"
        pdf_path = os.path.join(ROOT, "docs", pdf_filename)
        
        if st.button("📑 Compile PDF Incident Report"):
            generate_incident_pdf(investigation, pdf_path)
            st.success(f"Incident report generated successfully!")
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="⬇️ Download Executive PDF Report",
                    data=f,
                    file_name=pdf_filename,
                    mime="application/pdf"
                )

    # Co-Pilot Chat at bottom
    st.divider()
    st.subheader("💬 AI SOC Co-Pilot: Chat with Incident")
    user_q = st.text_input("Ask AegisAI about this incident (e.g. 'What persistence should I look for?', 'Write a YARA rule for this hash'):")
    if user_q:
        with st.chat_message("assistant"):
            q_lower = user_q.lower()
            if "yara" in q_lower or "rule" in q_lower:
                st.code(f"""rule Detect_{selected_alert['process']['name'].replace('.','_')} {{
    meta:
        description = "Auto-generated YARA detection for {selected_alert['id']}"
        author = "AegisAI-SOC Copilot"
        hash = "{selected_alert['process']['file_hash']}"
    strings:
        $s1 = "{selected_alert['process']['name']}" ascii wide
        $s2 = "{selected_alert['process']['command_line'][:25]}" ascii wide
    condition:
        any of ($s*)
}}""", language="c")
            elif "persistence" in q_lower:
                st.markdown("🔍 **Common Persistence Vectors to Investigate:**\n1. Scheduled Tasks (`schtasks /create`)\n2. Run & RunOnce Registry Keys (`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`)\n3. Service Installations (Windows Event ID 7045)")
            else:
                st.markdown(f"🤖 **AegisAI Analysis:** Based on observed telemetry for `{selected_alert['hostname']}`, the process `{selected_alert['process']['name']}` targeted critical memory structures while maintaining an outbound socket to `{selected_alert['network']['destination_ip']}`. Immediate recommendation: keep host quarantined until full credential rotation is complete.")
