import os
import sys
import hashlib
import json
import math
import re
from datetime import datetime
from pathlib import Path


# ---- Uzantı listeleri -------------------------------------------------------

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".scr", ".pif", ".com", ".hta", ".class", ".jar",
    ".msi", ".psm1", ".psd1", ".lnk"
]

# Bu uzantılara karşı heuristik çalıştırılmaz (zaten güvenli kabul edilir)
SKIP_EXTENSIONS = {
    ".py", ".pyc", ".json", ".txt", ".md", ".log",
    ".ico", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".svg", ".css", ".html",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wmv",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".pdf", ".docx", ".xlsx"
}

# Entropi kontrolünde atlanacak dosya türleri (zaten sıkıştırılmış/şifreli olabilir)
ENTROPY_SKIP_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".pdf",
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".png", ".jpg",
    ".jpeg", ".gif", ".bmp", ".ico", ".mp3", ".mp4", ".avi",
    ".mkv", ".mov", ".wmv", ".woff", ".woff2", ".ttf", ".eot", ".svg"
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv",
    ".env", "build", "dist", ".vscode", ".idea"
}

# ---- Anahtar kelimeler ------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "keylog", "ransomware", "trojan", "backdoor",
    "stealer", "botnet", "reverse_shell", "cmd.exe",
    "powershell -enc", "eval(", "base64_decode", "shell_exec",
    "cryptolocker", "wannacry", "mimikatz", "credential",
    "password steal", "cookie steal", "webhook", "discord token"
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
    "kittycraft-installer.bat"
]

DEOBFUSCATION_KEYWORDS = [
    "ByteArrayOutputStream",
    "getNextJarEntry",
    "rollMetric",
    "getName().replace",
    "toByteArray()",
    "getClass().getResourceAsStream"
]

OBFUSCATION_PATTERNS = [
    re.compile(r'[a-z0-9]{24,}', re.IGNORECASE),      # uzun karışık dize
    re.compile(r'\$[a-f0-9]{12,}', re.IGNORECASE),    # uzun hex değişken
    re.compile(r'[a-z]{1,3}[0-9]{6,}[a-z]{1,3}', re.IGNORECASE),
]

REMOVABLE_DRIVE_HINTS = ["removable", "usb", "flash", "sdcard"]

# Sistem / program dosyaları (varsayılan olarak daha gevşek taranır)
SYSTEM_PATH_HINTS = [
    r"windows\\", r"program files", r"program files (x86)",
    r"system32", r"syswow64", r"appdata\\local\\temp"
]

# Varsayılan beyaz liste (hash, yol öneki, uzantı)
DEFAULT_WHITELIST_HASHES = set()
DEFAULT_WHITELIST_PATH_PREFIXES = [
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), ""),
    os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), ""),
    os.path.join(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"), ""),
]


class Scanner:
    def __init__(self, signatures_path="signatures.json", config=None):
        self.signatures_path = signatures_path
        self.config = config or {}
        self.signatures = self.load_signatures()
        self.stop_requested = False

        scan_cfg = self.config.get("scan_settings", {})
        self.heuristic_threshold = scan_cfg.get("heuristic_threshold", 3)
        self.min_file_size_for_entropy = scan_cfg.get("min_file_size_for_entropy", 65536)  # 64 KB
        self.entropy_threshold = scan_cfg.get("entropy_threshold", 7.8)
        self.skip_dirs = set(scan_cfg.get("skip_dirs", list(SKIP_DIRS)))
        self.skip_extensions = set(scan_cfg.get("skip_extensions", list(SKIP_EXTENSIONS)))
        self.suspicious_extensions = set(scan_cfg.get("suspicious_extensions", list(SUSPICIOUS_EXTENSIONS)))

        whitelist_cfg = self.config.get("whitelist", {})
        self.whitelist_hashes = set(whitelist_cfg.get("hashes", list(DEFAULT_WHITELIST_HASHES)))
        self.whitelist_path_prefixes = whitelist_cfg.get("path_prefixes", list(DEFAULT_WHITELIST_PATH_PREFIXES))
        self.whitelist_extensions = set(whitelist_cfg.get("extensions", []))

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
            max_size_mb = self.config.get("scan_settings", {}).get("max_file_size_mb", 100)
            max_size = max_size_mb * 1024 * 1024
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

    def _is_whitelisted(self, filepath, file_hash):
        """Beyaz liste kontrolü: hash, yol öneki veya uzantı."""
        if file_hash and file_hash in self.whitelist_hashes:
            return True
        path_lower = filepath.lower()
        for prefix in self.whitelist_path_prefixes:
            if path_lower.startswith(prefix.lower()):
                return True
        ext = os.path.splitext(filepath)[1].lower()
        if ext in self.whitelist_extensions:
            return True
        return False

    def _is_system_path(self, filepath):
        path_lower = filepath.lower()
        for hint in SYSTEM_PATH_HINTS:
            if hint in path_lower:
                return True
        return False

    def heuristic_check(self, filepath):
        """
        Dönüş: (reasons: list[str], score: int)
        score: 0-10 arası şüphe skoru. Yüksek = daha şüpheli.
        """
        reasons = []
        score = 0
        ext = os.path.splitext(filepath)[1].lower()
        path_lower = filepath.lower()

        # Atlanacak uzantılar → hiçbir şey yapma
        if ext in self.skip_extensions:
            return reasons, score

        # Beyaz liste
        # (hash burada zaten scan_file'da kontrol ediliyor, ama yine de ekleyelim)

        # 1. Çalıştırılabilir uzantı → +1 (ama tek başına yeterli değil)
        if ext in self.suspicious_extensions:
            reasons.append(f"Executable extension: {ext}")
            score += 1

        # 2. Sistem yolu ise eşikleri gevşet (+0, sistem dosyası olarak işaretle)
        is_system = self._is_system_path(filepath)

        # 3. İçerik analizi (ilk 8 KB)
        try:
            with open(filepath, "rb") as f:
                data = f.read(8192)

            # Binary dosya tespiti: null byte içeriyorsa metin taraması yapılmaz
            # (ses, resim, video, arşif gibi dosyalar obfüskasyon yanlış pozitifine uğramaz)
            is_binary = b"\x00" in data
            text = data.decode("utf-8", errors="ignore").lower() if not is_binary else ""

            if text:
                # Şüpheli kelimeler → her biri +2
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in text:
                        reasons.append(f"Suspicious keyword: {kw}")
                        score += 2

                # PowerShell gizli çalıştırma işaretçileri → her biri +3
                for kw in POWERSHELL_HIDDEN_KEYWORDS:
                    if kw in text:
                        reasons.append(f"Hidden execution marker: {kw}")
                        score += 3

                # Obfüskasyon desenleri → her biri +2
                for pattern in OBFUSCATION_PATTERNS:
                    matches = pattern.findall(text)
                    if len(matches) >= 3:
                        reasons.append(f"Obfuscation detected: {len(matches)} matches")
                        score += 2
                        break

                # Deobfüscasyon akışı → +2
                deob_count = 0
                for kw in DEOBFUSCATION_KEYWORDS:
                    if kw.lower() in text:
                        deob_count += 1
                if deob_count >= 2:
                    reasons.append(f"Deobfuscation flow: {deob_count} indicators")
                    score += 2

                # İndirilen .bat (Downloads klasöründe) → +2
                if ext == ".bat" and "downloads" in path_lower:
                    reasons.append("Downloaded .bat file (Downloads folder)")
                    score += 2

        except Exception:
            pass

        # 4. Entropi → sadece yeterince büyük dosyalarda ve sıkıştırılmamış türlerde
        if (
            ext not in ENTROPY_SKIP_EXTENSIONS
            and os.path.getsize(filepath) >= self.min_file_size_for_entropy
        ):
            entropy = self.calculate_entropy(filepath)
            if entropy > self.entropy_threshold:
                reasons.append(
                    f"High entropy (encryption/obfuscation possible): {entropy:.2f}"
                )
                score += 3

        # Sistem dosyaları için skoru biraz azalt (false positive önleme)
        if is_system and score > 0:
            score = max(0, score - 1)

        return reasons, score

    def scan_file(self, filepath):
        result = {
            "path": filepath,
            "hash": None,
            "threat": False,
            "threat_name": None,
            "threat_type": None,
            "severity": None,
            "heuristic": [],
            "heuristic_score": 0,
            "timestamp": datetime.now().isoformat(),
            "size": 0,
            "extension": os.path.splitext(filepath)[1].lower(),
            "whitelisted": False,
        }

        if self.stop_requested:
            result["threat"] = False
            result["threat_type"] = "cancelled"
            return result

        try:
            result["size"] = os.path.getsize(filepath)
        except Exception:
            result["size"] = 0

        file_hash = self.compute_hash(filepath)
        result["hash"] = file_hash

        if file_hash is None:
            return result

        # 1. Beyaz liste kontrolü (hash / yol / uzantı)
        if self._is_whitelisted(filepath, file_hash):
            result["whitelisted"] = True
            return result

        # 2. İmza tabanlı tespit (en yüksek öncelik)
        for sig in self.signatures:
            if file_hash and sig.get("hash") == file_hash:
                result["threat"] = True
                result["threat_name"] = sig.get("name", "Unknown")
                result["threat_type"] = sig.get("type", "malware")
                result["severity"] = sig.get("severity", "high")
                return result

        # 3. Heuristik analiz
        heur, score = self.heuristic_check(filepath)
        result["heuristic"] = heur
        result["heuristic_score"] = score

        # Eşikten yüksekse veya imza varsa tehdit olarak işaretle
        if score >= self.heuristic_threshold:
            result["threat"] = True
            result["threat_name"] = "Heuristic.Suspicious"
            result["threat_type"] = "heuristic"
            # Skor bazlı ciddiyet
            if score >= 7:
                result["severity"] = "high"
            elif score >= 5:
                result["severity"] = "medium"
            else:
                result["severity"] = "low"

        return result

    def scan_directory(self, directory, callback=None):
        results = []
        self.reset_stop()
        directory = os.path.abspath(directory)

        skip_dirs = set(self.config.get("scan_settings", {}).get("skip_dirs", list(self.skip_dirs)))

        for root, dirs, files in os.walk(directory):
            if self.stop_requested:
                break
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for file in files:
                if self.stop_requested:
                    break
                filepath = os.path.join(root, file)
                res = self.scan_file(filepath)
                results.append(res)
                if callback:
                    callback(res)
        return results

    def scan_removable_drives(self, callback=None):
        """Scan removable drives. Cross-platform: Windows drive letters, Linux/macOS mount points."""
        results = []
        self.reset_stop()

        if sys.platform == "win32":
            results = self._scan_removable_windows(callback)
        else:
            results = self._scan_removable_unix(callback)

        return results

    def _scan_removable_windows(self, callback=None):
        """Windows: iterate drive letters A-Z and check removable media hints."""
        results = []
        import string
        for letter in string.ascii_uppercase:
            if self.stop_requested:
                break
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                try:
                    label = ""
                    try:
                        import ctypes
                        vol_name_buf = ctypes.create_unicode_buffer(1024)
                        ctypes.windll.kernel32.GetVolumeInformationW(
                            ctypes.c_wchar_p(drive),
                            vol_name_buf,
                            1024,
                            None, None, None, None, None
                        )
                        label = vol_name_buf.value or ""
                    except Exception:
                        pass

                    drive_info = (label + " " + drive).lower()
                    is_removable = any(h in drive_info for h in REMOVABLE_DRIVE_HINTS) or letter in ("D", "E", "F", "G")
                    if not is_removable and letter in ("A", "B", "C"):
                        continue

                    for root, dirs, files in os.walk(drive):
                        if self.stop_requested:
                            break
                        dirs[:] = [d for d in dirs if d not in self.skip_dirs]
                        for file in files:
                            if self.stop_requested:
                                break
                            filepath = os.path.join(root, file)
                            res = self.scan_file(filepath)
                            res["drive"] = drive
                            results.append(res)
                            if callback:
                                callback(res)
                except Exception:
                    continue
        return results

    def _scan_removable_unix(self, callback=None):
        """Linux/macOS: scan common mount points (/media, /mnt, /Volumes)."""
        results = []
        mount_points = ["/media", "/mnt", "/Volumes"]
        for base in mount_points:
            if self.stop_requested:
                break
            if not os.path.exists(base):
                continue
            try:
                for entry in os.listdir(base):
                    if self.stop_requested:
                        break
                    mount_path = os.path.join(base, entry)
                    if not os.path.ismount(mount_path) and not os.path.isdir(mount_path):
                        continue
                    for root, dirs, files in os.walk(mount_path):
                        if self.stop_requested:
                            break
                        dirs[:] = [d for d in dirs if d not in self.skip_dirs]
                        for file in files:
                            if self.stop_requested:
                                break
                            filepath = os.path.join(root, file)
                            res = self.scan_file(filepath)
                            res["drive"] = mount_path
                            results.append(res)
                            if callback:
                                callback(res)
            except Exception:
                continue
        return results
