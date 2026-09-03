import pytest
import os
import sys

# Ensure root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent import SocInvestigationAgent
from core.llm_provider import get_llm_provider, HeuristicProvider
from tools.threat_intel import VirusTotalTool, AbuseIPDBTool, MitreAttackTool, ProcessAnalyzerTool

def test_heuristic_provider_initialization():
    provider = get_llm_provider("heuristic")
    assert isinstance(provider, HeuristicProvider)

def test_virustotal_tool_hash_analysis():
    vt = VirusTotalTool()
    # Test known test/mimikatz hash
    res = vt.check_hash("44d88612fea8a8f36de82e1278abb02f")
    assert res["status"] == "malicious"
    assert res["positives"] > 50

def test_mitre_tool_lsass_correlation():
    mitre = MitreAttackTool()
    matches = mitre.match_indicators("procdump.exe -ma lsass.exe out.dmp", "procdump.exe")
    assert len(matches) > 0
    technique_ids = [m["technique_id"] for m in matches]
    assert "T1003" in technique_ids

def test_end_to_end_agent_investigation():
    agent = SocInvestigationAgent(provider_name="heuristic")
    sample_alert = {
        "id": "TEST-01",
        "hostname": "FINANCE-PC",
        "source": "AegisEDR",
        "description": "LSASS process dump",
        "process": {
            "name": "procdump.exe",
            "pid": 9999,
            "command_line": "procdump.exe -ma lsass.exe dump.dmp",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f"
        },
        "network": {
            "destination_ip": "185.220.101.5",
            "destination_port": 443
        }
    }
    investigation = agent.investigate(sample_alert)
    assert "decision" in investigation
    assert investigation["decision"]["risk_score"] >= 80
    assert "containment_script" in investigation
    assert "Stop-Process -Id 9999" in investigation["containment_script"]
