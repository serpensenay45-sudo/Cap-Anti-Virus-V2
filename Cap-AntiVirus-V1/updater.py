import json
import urllib.request
import urllib.parse
import os

class Updater:
    def __init__(self, signatures_path="signatures.json", url=None, vt_api_key=""):
        self.signatures_path = signatures_path
        self.url = url
        self.vt_api_key = vt_api_key

    def update(self):
        if not self.url:
            print("Update URL not defined.")
            return False
        try:
            with urllib.request.urlopen(self.url) as resp:
                data = resp.read().decode("utf-8")
            json.loads(data)
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