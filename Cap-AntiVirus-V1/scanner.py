import os
import hashlib
import json
import math
import re
from datetime import datetime

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".scr", ".pif", ".com", ".hta", ".class", ".jar"
]

SUSPICIOUS_KEYWORDS = [
    "keylog", "ransom", "trojan", "backdoor",
    "stealer", "botnet", "reverse_shell", "cmd.exe"
]

POWERSHELL_HIDDEN_KEYWORDS = [
    "-windowstyle hidden",
    "windowstyle hidden",
    "-noprofile",
    "executionpolicy bypass",
    "unblock-file",
    "start-process -filepath",
    "start-process",
    "argumentlist 'silent",
    "silent",
    "kittycraft-installer.bat"
]

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv",
    ".env", "build", "dist", ".vscode", ".idea"
}
SKIP_EXTENSIONS = {
    ".py", ".pyc", ".json", ".txt", ".md", ".log",
    ".ico", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".svg", ".css", ".html"
}

OBFUSCATION_PATTERNS = [
    re.compile(r'[a-z0-9]{16,}', re.IGNORECASE),
    re.compile(r'\$[a-f0-9]{8,}', re.IGNORECASE),
    re.compile(r'[a-z]{1,3}[0-9]{5,}[a-z]{1,3}', re.IGNORECASE),
]

DEOBFUSCATION_KEYWORDS = [
    "ByteArrayOutputStream",
    "getNextJarEntry",
    "replace(",
    "rollMetric",
    "getName().replace",
    "toByteArray()",
    "getClass().getResourceAsStream"
]

class Scanner:
    def __init__(self, signatures_path="signatures.json"):
        self.signatures_path = signatures_path
        self.signatures = self.load_signatures()
        self.stop_requested = False

    def request_stop(self):
        self.stop_requested = True

    def reset_stop(self):
        self.stop_requested = False

    def load_signatures(self):
        try:
            with open(self.signatures_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("signatures", [])
        except Exception:
            return []

    def compute_hash(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    if self.stop_requested:
                        return None
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def calculate_entropy(self, filepath):
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            if not data:
                return 0.0
            freq = {}
            for byte in data:
                freq[byte] = freq.get(byte, 0) + 1
            entropy = 0.0
            length = len(data)
            for count in freq.values():
                p = count / length
                entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0

    def heuristic_check(self, filepath):
        reasons = []
        ext = os.path.splitext(filepath)[1].lower()
        path_lower = filepath.lower()

        if ext in SKIP_EXTENSIONS:
            return reasons

        if ext in SUSPICIOUS_EXTENSIONS:
            reasons.append(f"Executable extension: {ext}")

        try:
            with open(filepath, "rb") as f:
                data = f.read(8192)
            text = data.decode("utf-8", errors="ignore").lower()

            for kw in SUSPICIOUS_KEYWORDS:
                if kw in text:
                    reasons.append(f"Suspicious keyword: {kw}")

            hidden_count = 0
            for kw in POWERSHELL_HIDDEN_KEYWORDS:
                if kw in text:
                    hidden_count += 1
                    reasons.append(f"Hidden execution marker: {kw}")

            for pattern in OBFUSCATION_PATTERNS:
                matches = pattern.findall(text)
                if len(matches) >= 3:
                    reasons.append(f"Obfuscation detected: {len(matches)} matches")
                    break

            deob_count = 0
            for kw in DEOBFUSCATION_KEYWORDS:
                if kw.lower() in text:
                    deob_count += 1
            if deob_count >= 2:
                reasons.append(f"Deobfuscation flow: {deob_count} indicators")

            if ext == ".bat" and "downloads" in path_lower:
                reasons.append("Downloaded .bat file (Downloads folder)")

        except Exception:
            pass

        entropy = self.calculate_entropy(filepath)
        if entropy > 7.5:
            reasons.append(
                f"High entropy (encryption/obfuscation possible): {entropy:.2f}"
            )

        return reasons

    def scan_file(self, filepath):
        result = {
            "path": filepath,
            "hash": None,
            "threat": False,
            "threat_name": None,
            "threat_type": None,
            "severity": None,
            "heuristic": [],
            "timestamp": datetime.now().isoformat()
        }

        if self.stop_requested:
            result["threat"] = False
            result["threat_type"] = "cancelled"
            return result

        file_hash = self.compute_hash(filepath)
        result["hash"] = file_hash

        if file_hash is None:
            return result

        for sig in self.signatures:
            if file_hash and sig.get("hash") == file_hash:
                result["threat"] = True
                result["threat_name"] = sig.get("name", "Unknown")
                result["threat_type"] = sig.get("type", "malware")
                result["severity"] = sig.get("severity", "high")
                return result

        heur = self.heuristic_check(filepath)
        if heur:
            result["heuristic"] = heur
            result["threat"] = True
            result["threat_name"] = "Heuristic.Suspicious"
            result["threat_type"] = "heuristic"
            result["severity"] = "medium"

        return result

    def scan_directory(self, directory, callback=None):
        results = []
        self.reset_stop()
        for root, dirs, files in os.walk(directory):
            if self.stop_requested:
                break
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for file in files:
                if self.stop_requested:
                    break
                filepath = os.path.join(root, file)
                res = self.scan_file(filepath)
                results.append(res)
                if callback:
                    callback(res)
        return results