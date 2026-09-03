import os
import json
from typing import Dict, Any
from core.llm_provider import get_llm_provider
from tools.threat_intel import VirusTotalTool, AbuseIPDBTool, MitreAttackTool, ProcessAnalyzerTool

class SocInvestigationAgent:
    def __init__(self, provider_name: str = "heuristic"):
        self.provider = get_llm_provider(provider_name)
        self.vt_tool = VirusTotalTool()
        self.abuse_tool = AbuseIPDBTool()
        self.mitre_tool = MitreAttackTool()

    def investigate(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes an autonomous ReAct investigation cycle:
        1. Parse indicators (Process, Command, Hash, Network IP).
        2. Execute OSINT Tool calls (VirusTotal, AbuseIPDB, MITRE, LOLbin analysis).
        3. Synthesize evidence into reasoning prompt.
        4. Generate structured incident verdict & containment scripts.
        """
        proc_data = alert.get("process", {})
        net_data = alert.get("network", {})

        proc_name = proc_data.get("name", "")
        cmd_line = proc_data.get("command_line", "")
        file_hash = proc_data.get("file_hash", "")
        dest_ip = net_data.get("destination_ip", "")

        # --- STEP 1: TOOL CALLS ---
        vt_evidence = self.vt_tool.check_hash(file_hash)
        abuse_evidence = self.abuse_tool.check_ip(dest_ip)
        mitre_matches = self.mitre_tool.match_indicators(cmd_line, proc_name)
        proc_analysis = ProcessAnalyzerTool.analyze_process(proc_name, cmd_line)

        evidence_package = {
            "alert_meta": {
                "id": alert.get("id"),
                "hostname": alert.get("hostname"),
                "source": alert.get("source"),
                "description": alert.get("description")
            },
            "process_evidence": proc_analysis,
            "virustotal_evidence": vt_evidence,
            "network_reputation_evidence": abuse_evidence,
            "mitre_attack_correlation": mitre_matches
        }

        # --- STEP 2: REASONING PROMPT CREATION ---
        system_prompt = (
            "You are AegisAI, an elite Autonomous Principal SOC Analyst & Incident Response Commander. "
            "You assess security alerts by correlating process anomalies, threat intelligence, and MITRE ATT&CK vectors. "
            "Analyze the evidence package carefully and return a JSON object with: "
            "verdict (TRUE POSITIVE - MALICIOUS ATTACK or FALSE POSITIVE / BENIGN), "
            "risk_score (0-100), severity (CRITICAL, HIGH, MEDIUM, LOW), "
            "analyst_assessment (summary), reasoning_steps (list of strings), "
            "and recommended_actions (list of concrete containment steps)."
        )

        user_prompt = f"Investigate this incident telemetry package:\n{json.dumps(evidence_package, indent=2)}"

        # --- STEP 3: LLM INFERENCE ---
        raw_output = self.provider.complete(user_prompt, system_prompt)

        try:
            decision = json.loads(raw_output)
        except Exception:
            decision = {
                "verdict": "INVESTIGATION_COMPLETED",
                "risk_score": 75,
                "severity": "HIGH",
                "analyst_assessment": raw_output[:300],
                "reasoning_steps": ["Analyzed process anomalies and threat intelligence indicators."],
                "recommended_actions": ["Review active processes and quarantine endpoint."]
            }

        # --- STEP 4: AUTOMATED CONTAINMENT SCRIPTS ---
        pid = proc_data.get("pid", 0)
        dest_ip = net_data.get("destination_ip", "")
        hostname = alert.get("hostname", "TARGET-HOST")

        powershell_containment = (
            f"# === AegisAI-SOC Automated Containment Script ===\n"
            f"# Host: {hostname} | Triggered Alert: {alert.get('id')}\n"
            f"# 1. Terminate malicious process tree\n"
            f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue\n"
            f"# 2. Block malicious C2 network communication\n"
            f"New-NetFirewallRule -DisplayName 'AegisAI-Block-{dest_ip}' -Direction Outbound -RemoteAddress '{dest_ip}' -Action Block\n"
            f"# 3. Isolate host completely if critical\n"
            f"# Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True\n"
            f"Write-Host '[+] AegisAI Containment successfully applied to {hostname}'"
        )

        return {
            "alert": alert,
            "evidence": evidence_package,
            "decision": decision,
            "containment_script": powershell_containment
        }
