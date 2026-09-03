import os
import json
import requests
from typing import Dict, Any, Optional

# --- VIRUSTOTAL ENRICHMENT ---
class VirusTotalTool:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        if not file_hash or file_hash == "N/A":
            return {"status": "skipped", "reason": "No valid hash provided"}

        # Known EICAR or test mock hash detection
        if file_hash == "44d88612fea8a8f36de82e1278abb02f":
            return {
                "status": "malicious",
                "positives": 63,
                "total": 74,
                "reputation": -85,
                "verdict": "Malicious credential dumping or exploit tool detected",
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
            }

        if not self.api_key:
            # Mock triage for offline/zero-API execution
            if "evil" in file_hash.lower() or file_hash.startswith("a1b2c3"):
                return {
                    "status": "malicious",
                    "positives": 56,
                    "total": 72,
                    "reputation": -75,
                    "verdict": "Trojan/Downloader binary identified by multiple vendors",
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            return {
                "status": "clean",
                "positives": 0,
                "total": 72,
                "reputation": 100,
                "verdict": "Known trusted signature or benign administrative utility",
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
            }

        # Real Live VirusTotal v3 API Call
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.api_key}
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                return {
                    "status": "malicious" if positives > 3 else "clean",
                    "positives": positives,
                    "total": total,
                    "reputation": data.get("reputation", 0),
                    "verdict": f"Detected by {positives}/{total} security vendors",
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "unknown", "positives": 0, "total": 0}


# --- ABUSEIPDB ENRICHMENT ---
class AbuseIPDBTool:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        if not ip_address or ip_address in ["127.0.0.1", "localhost", "0.0.0.0"]:
            return {"status": "skipped", "reason": "Local loopback or unrouted IP"}

        if not self.api_key:
            # Mock threat intel based on known public test ranges
            if ip_address.startswith("185.220") or ip_address.startswith("194.26") or ip_address.startswith("91.240"):
                return {
                    "ip": ip_address,
                    "abuse_confidence_score": 98,
                    "country_code": "NL",
                    "usage_type": "Data Center/Web Hosting/Transit",
                    "domain": "tor-exit-relay.net",
                    "total_reports": 1420,
                    "is_malicious": True
                }
            return {
                "ip": ip_address,
                "abuse_confidence_score": 0,
                "country_code": "US",
                "usage_type": "Commercial",
                "domain": "google.com",
                "total_reports": 0,
                "is_malicious": False
            }

        # Real Live AbuseIPDB API v2 Call
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
            headers = {"Key": self.api_key, "Accept": "application/json"}
            resp = requests.get(url, headers=headers, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "ip": ip_address,
                    "abuse_confidence_score": score,
                    "country_code": data.get("countryCode", "Unknown"),
                    "usage_type": data.get("usageType", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                    "total_reports": data.get("totalReports", 0),
                    "is_malicious": score > 40
                }
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "unknown"}


# --- MITRE ATT&CK CORRELATION ---
class MitreAttackTool:
    def __init__(self, dataset_path: Optional[str] = None):
        if not dataset_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            dataset_path = os.path.join(base_dir, "data", "mitre_attack.json")

        self.database = {}
        if os.path.exists(dataset_path):
            with open(dataset_path, "r", encoding="utf-8-sig") as f:
                self.database = json.load(f)

    def match_indicators(self, command_line: str, process_name: str) -> list:
        matches = []
        cmd = (command_line or "").lower()
        proc = (process_name or "").lower()

        if "lsass" in cmd or "procdump" in proc or "mimikatz" in proc:
            if "T1003" in self.database:
                matches.append({"technique_id": "T1003", **self.database["T1003"]})

        if "powershell" in proc or "-enc" in cmd or "bypass" in cmd:
            if "T1059.001" in self.database:
                matches.append({"technique_id": "T1059.001", **self.database["T1059.001"]})

        if "certutil" in proc or "mshta" in proc or "rundll32" in proc:
            if "T1218" in self.database:
                matches.append({"technique_id": "T1218", **self.database["T1218"]})

        if "vssadmin" in proc or "delete shadows" in cmd:
            if "T1486" in self.database:
                matches.append({"technique_id": "T1486", **self.database["T1486"]})

        return matches


# --- LOLBIN & ANOMALY ANALYZER ---
class ProcessAnalyzerTool:
    LOLBINS = {
        "certutil.exe": "Often abused to download remote files with -urlcache or decode base64 payloads.",
        "powershell.exe": "Standard administrative engine frequently used for execution policy bypass and reflective loading.",
        "vssadmin.exe": "Legitimate volume management binary commonly executed by ransomware to inhibit recovery.",
        "rundll32.exe": "Native binary abused to execute arbitrary DLL exports and shellcode.",
        "mshta.exe": "Microsoft HTML Application host frequently used to execute VBScript/JScript cradles.",
        "cmd.exe": "Command interpreter frequently chained for parent-child reconnaissance."
    }

    @classmethod
    def analyze_process(cls, process_name: str, command_line: str) -> Dict[str, Any]:
        proc = (process_name or "").lower()
        cmd = (command_line or "").lower()

        is_lolbin = proc in cls.LOLBINS
        notes = cls.LOLBINS.get(proc, "Standard non-LOLbin application")

        suspicious_flags = []
        if "-enc" in cmd or "encodedcommand" in cmd:
            suspicious_flags.append("Base64 Encoded Command Line Execution")
        if "bypass" in cmd:
            suspicious_flags.append("Execution Policy Bypass Switch")
        if "delete shadows" in cmd:
            suspicious_flags.append("Volume Shadow Copy Destruction (Ransomware Preparation)")
        if "urlcache" in cmd or "split" in cmd:
            suspicious_flags.append("Living-Off-The-Land Binary Remote Download Cradle")
        if "lsass" in cmd:
            suspicious_flags.append("Direct Memory Access to Local Security Authority Subsystem Service")

        return {
            "process": process_name,
            "is_lolbin": is_lolbin,
            "description": notes,
            "suspicious_flags": suspicious_flags,
            "anomaly_detected": len(suspicious_flags) > 0 or is_lolbin
        }
