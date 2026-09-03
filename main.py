import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.agent import SocInvestigationAgent

def main():
    parser = argparse.ArgumentParser(description="AegisAI-SOC: Autonomous AI Incident Response Agent CLI")
    parser.add_argument("--alert", type=str, help="Path to JSON file containing the security alert telemetry")
    parser.add_argument("--provider", type=str, default="heuristic", choices=["heuristic", "gemini", "groq", "ollama"], help="AI Reasoning Provider")
    parser.add_argument("--contain", action="store_true", help="Print automated remediation PowerShell containment script")
    args = parser.parse_args()

    if args.alert:
        with open(args.alert, "r", encoding="utf-8-sig") as f:
            alert = json.load(f)
    else:
        sample_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "samples", "incident_alerts.json")
        with open(sample_path, "r", encoding="utf-8-sig") as f:
            alert = json.load(f)[0]

    print(f"\n[+] AegisAI-SOC Agent Initialized (Provider: {args.provider.upper()})")
    print(f"[+] Ingesting Alert: {alert.get('id')} - {alert.get('description')}")
    print("[*] Performing automated tool calls (VirusTotal, AbuseIPDB, MITRE ATT&CK)...")

    agent = SocInvestigationAgent(provider_name=args.provider)
    result = agent.investigate(alert)

    dec = result["decision"]
    print("\n" + "="*60)
    print(f"VERDICT:   {dec.get('verdict')}")
    print(f"RISK SCORE: {dec.get('risk_score')}/100 ({dec.get('severity')})")
    print(f"ASSESSMENT: {dec.get('analyst_assessment')}")
    print("="*60)

    print("\nMITRE ATT&CK Correlation:")
    mitre_matches = result["evidence"].get("mitre_attack_correlation", [])
    if mitre_matches:
        for m in mitre_matches:
            print(f"  - [{m['technique_id']}] {m['name']} ({m['tactic']})")
    else:
        print("  - No critical ATT&CK matches found.")

    if args.contain:
        print("\nAutomated Containment Script (PowerShell):")
        print("-" * 50)
        print(result["containment_script"])
        print("-" * 50)

if __name__ == "__main__":
    main()
