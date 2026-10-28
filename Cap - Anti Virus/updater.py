import json
import urllib.request
import urllib.parse
import os


class Updater:
    def __init__(self, signatures_path="signatures.json", url=None, vt_api_key="", api_version="v3"):
        self.signatures_path = signatures_path
        self.url = url
        self.vt_api_key = vt_api_key
        self.api_version = api_version

    def update(self):
        if not self.url:
            print("Update URL not defined.")
            return False
        try:
            with urllib.request.urlopen(self.url) as resp:
                data = resp.read().decode("utf-8")
            json.loads(data)  # validate JSON
            with open(self.signatures_path, "w", encoding="utf-8") as f:
                f.write(data)
            print("Signature database updated.")
            return True
        except Exception as e:
            print(f"Update error: {e}")
            return False

    def virustotal_check_by_hash(self, file_hash):
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not defined."}
        try:
            if self.api_version == "v3":
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                req = urllib.request.Request(url, headers={"x-apikey": self.vt_api_key})
                with urllib.request.urlopen(req) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                # Normalize v3 response to a common shape
                attrs = data.get("data", {}).get("attributes", {})
                last_analysis = attrs.get("last_analysis_stats", {})
                positives = last_analysis.get("malicious", 0) + last_analysis.get("suspicious", 0)
                total = sum(last_analysis.values()) or 1
                scan_date = attrs.get("last_analysis_date", "Unknown")
                scans = {}
                for av_name, av_data in attrs.get("last_analysis_results", {}).items():
                    scans[av_name] = {
                        "detected": av_data.get("category") in ("malicious", "suspicious"),
                        "result": av_data.get("result", "Clean")
                    }
                return {
                    "response_code": 1 if total > 0 else 0,
                    "positives": positives,
                    "total": total,
                    "scan_date": str(scan_date),
                    "scans": scans,
                    "sha256": attrs.get("sha256", file_hash)
                }
            else:
                # Legacy v2 fallback
                url = "https://www.virustotal.com/vtapi/v2/file/report"
                params = urllib.parse.urlencode({
                    "apikey": self.vt_api_key,
                    "resource": file_hash
                })
                full_url = f"{url}?{params}"
                with urllib.request.urlopen(full_url) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                return data
        except Exception as e:
            return {"error": str(e)}
