import os
import sys
import json
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.agent import SocInvestigationAgent

app = FastAPI(
    title="AegisAI-SOC Ingestion Gateway",
    description="Real-time ingestion endpoint for AegisEDR telemetry & SIEM webhook feeds",
    version="1.2.0"
)

agent = SocInvestigationAgent(provider_name="heuristic")

class ProcessModel(BaseModel):
    name: str
    pid: int
    parent_name: Optional[str] = "explorer.exe"
    parent_pid: Optional[int] = 1000
    command_line: str
    file_hash: Optional[str] = "N/A"
    user: Optional[str] = "SYSTEM"

class NetworkModel(BaseModel):
    destination_ip: str
    destination_port: int
    protocol: Optional[str] = "TCP"

class AlertPayload(BaseModel):
    id: str
    hostname: str
    source: str = "AegisEDR Live Sensor"
    alert_type: str = "SUSPICIOUS_EVENT"
    severity: str = "HIGH"
    description: str
    process: ProcessModel
    network: Optional[NetworkModel] = None

@app.get("/health")
def health_check():
    return {"status": "online", "version": "1.2.0", "engine": "AegisAI Autonomous SOC"}

@app.post("/api/v1/ingest")
def ingest_alert(payload: AlertPayload):
    alert_dict = payload.model_dump()
    result = agent.investigate(alert_dict)
    
    # Save to data/samples/live_incoming.json
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    incoming_file = os.path.join(base_dir, "data", "samples", "live_incoming.json")
    try:
        current_data = []
        if os.path.exists(incoming_file):
            with open(incoming_file, "r", encoding="utf-8-sig") as f:
                current_data = json.load(f)
        current_data.insert(0, alert_dict)
        with open(incoming_file, "w", encoding="utf-8") as f:
            json.dump(current_data[:20], f, indent=2)
    except Exception as e:
        print("[!] Storage log error:", e)

    return {
        "status": "investigated",
        "verdict": result["decision"]["verdict"],
        "risk_score": result["decision"]["risk_score"],
        "severity": result["decision"]["severity"],
        "mitre_techniques": [m["technique_id"] for m in result["evidence"].get("mitre_attack_correlation", [])],
        "containment_script": result["containment_script"]
    }
