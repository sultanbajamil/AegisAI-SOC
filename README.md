# 🛡️ AegisAI-SOC (v1.2.0): Autonomous AI Incident Response & Triage Agent

[![Version](https://img.shields.io/badge/Release-v1.2.0-blue.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1-red.svg)](https://attack.mitre.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-v0.100%2B-green.svg)](https://fastapi.tiangolo.com/)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success.svg)]()

**AegisAI-SOC** is an enterprise-grade autonomous Security Operations Center (SOC) agent designed to automate L1/L2 triage, alert correlation, and incident response workflows. It operates as an autonomous ReAct agent that evaluates incoming endpoint/network alerts (e.g. from **AegisEDR** or Windows Event Logs), executes real-time OSINT investigations, maps adversary tactics to **MITRE ATT&CK**, calculates dynamic risk scores, and generates actionable host containment playbooks.

---

## 🚀 What's New in v1.2.0

- 🌳 **Visual Attack Process Tree (Sankey Lineage):** Visualizes the execution progression from parent process (e.g. `explorer.exe`) to target binary (`procdump.exe`), memory injection (`lsass.exe`), and C2 egress IP.
- 📄 **CISO & Executive PDF Report Export:** Generates formatted post-incident reports with executive summaries, technical artifact matrices, and containment scripts.
- 💬 **AI SOC Co-Pilot (Interactive Incident Chat):** Ask questions about the active alert, query persistence vectors, and generate on-the-fly **YARA rules**.
- 🌐 **Real-Time AegisEDR Ingestion API (`/api/v1/ingest`):** Built-in FastAPI webhook gateway allowing external EDR agents to push live telemetry.

---

## 📸 Interactive Web Dashboard Preview

### 1. Alert Ingestion & Security Telemetry Stream
Ingests live process alerts, LOLbin commands, network destinations, and file hashes from AegisEDR or Windows Event Logs.
![Telemetry Stream](docs/images/telemetry_stream.png)

### 2. Autonomous Investigation Verdict & OSINT Evidence
Autonomous ReAct agent checks VirusTotal reputation, queries AbuseIPDB threat intelligence, and calculates a dynamic 0–100 risk score.
![Investigation OSINT](docs/images/investigation_osint.png)

### 3. MITRE ATT&CK Correlation
Adversary tactics and techniques (e.g., T1003 OS Credential Dumping) correlated directly from raw command line arguments.
![MITRE Mapping](docs/images/mitre_mapping.png)

### 4. Automated Host Containment Playbook
Generates target host remediation scripts (process tree termination & firewall isolation) executable with one click.
![Automated Containment](docs/images/automated_containment.png)

---

## 🌟 Core Architecture & Capabilities

- **🤖 Hybrid AI Inference Engine (100% Free or Cloud Powered):**
  - **Local Offline Models:** Seamlessly connects to local **Ollama** models (`llama3.2`, `mistral`, `qwen2.5-coder`) for complete privacy and zero data leakage.
  - **Free Cloud APIs:** Ready toggle for **Google Gemini 1.5 Flash API** or **Groq Llama-3 API**.
  - **Zero-Dependency Heuristic Fallback:** In-memory rule reasoning engine that works immediately without API keys or GPU requirements.
- **🔍 Automated OSINT Threat Intelligence:**
  - **VirusTotal v3 Integration:** Automatic file hash reputation and malware vendor consensus lookups.
  - **AbuseIPDB Integration:** Confidence scoring, ISP, ASN, and historical malicious abuse verification for remote C2 addresses.
  - **Offline MITRE ATT&CK Engine:** Offline STIX-based mapping for credential dumping, LOLbins, defense evasion, and ransomware tactics.
- **⚡ Automated Incident Response Playbooks:**
  - Dynamic **PowerShell / Bash** host containment generation.
  - Automated targeted process tree termination (`Stop-Process`).
  - Outbound C2 network isolation via Windows Firewall rules (`New-NetFirewallRule`).

---

## 📁 Project Architecture

```
AegisAI-SOC/
├── core/
│   ├── agent.py              # Autonomous ReAct SOC investigation loop
│   ├── api.py                # FastAPI real-time EDR ingestion endpoint
│   └── llm_provider.py       # Provider factory: Ollama, Gemini, Groq, Heuristic
├── tools/
│   ├── threat_intel.py       # VirusTotal, AbuseIPDB, MITRE ATT&CK, LOLbin analyzers
│   └── report_generator.py   # Executive PDF incident report compiler
├── dashboard/
│   └── app.py                # Interactive Streamlit SOC Analyst Web Console
├── data/
│   ├── mitre_attack.json     # Offline MITRE ATT&CK database
│   └── samples/              # Pre-configured realistic incident telemetry
├── docs/
│   ├── images/               # Dashboard screenshots and UI walkthroughs
│   └── Sample_Incident_Report_ALT-2026-8801.pdf
├── tests/
│   └── test_investigation.py # Pytest test suite
├── main.py                   # CLI entrypoint
├── requirements.txt          # Python dependencies
└── .env.example              # Environment configuration template
```

---

## 🚀 Quickstart & Usage

### 1. Installation
```powershell
git clone https://github.com/sultanbajamil/AegisAI-SOC.git
cd AegisAI-SOC
pip install -r requirements.txt
```

### 2. Run Autonomous CLI Triage
Run an autonomous investigation on a sample alert with automated containment generation:
```powershell
python main.py --contain
```

### 3. Launch Interactive SOC Dashboard
```powershell
streamlit run dashboard/app.py
```
Open `http://localhost:8501` to access the console.

### 4. Run Real-Time Ingestion Gateway (Optional)
```powershell
uvicorn core.api:app --host 0.0.0.0 --port 8000
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
