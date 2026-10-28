import os
import shutil
import json
from datetime import datetime, timedelta


try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False


class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine", config=None):
        self.quarantine_dir = quarantine_dir
        self.config = config or {}
        self.metadata_file = os.path.join(quarantine_dir, "metadata.json")
        self.key_file = os.path.join(quarantine_dir, "key.bin")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.metadata = self.load_metadata()
        self._key = self._load_or_create_key()

    def _load_or_create_key(self):
        """Şifreleme anahtarını yükler veya yeni bir tane oluşturur."""
        qcfg = self.config.get("quarantine", {})

        # 1. config.json'dan anahtar dene
        key_b64 = qcfg.get("key", "")
        if key_b64 and CRYPTO_AVAILABLE:
            try:
                return Fernet(key_b64.encode())
            except Exception:
                pass

        # 2. quarantine/key.bin dosyasından dene
        if CRYPTO_AVAILABLE and os.path.exists(self.key_file):
            try:
                with open(self.key_file, "rb") as f:
                    key = f.read()
                return Fernet(key)
            except Exception:
                pass

        # 3. Yeni anahtar oluştur ve dosyaya kaydet
        if CRYPTO_AVAILABLE:
            key = Fernet.generate_key()
            try:
                with open(self.key_file, "wb") as f:
                    f.write(key)
            except Exception:
                pass
            return Fernet(key)

        return None

    def _encrypt_data(self, data):
        if self._key and CRYPTO_AVAILABLE:
            return self._key.encrypt(data)
        return data

    def _decrypt_data(self, data):
        if self._key and CRYPTO_AVAILABLE:
            try:
                return self._key.decrypt(data)
            except Exception:
                return data
        return data

    def load_metadata(self):
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_metadata(self):
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2, ensure_ascii=False)

    def quarantine_file(self, filepath):
        if not os.path.exists(filepath):
            return False
        qcfg = self.config.get("quarantine", {})
        encrypt = qcfg.get("encrypt", False)

        filename = os.path.basename(filepath)
        dest = os.path.join(self.quarantine_dir, filename)
        counter = 1
        while os.path.exists(dest):
            name, ext = os.path.splitext(filename)
            dest = os.path.join(self.quarantine_dir, f"{name}_{counter}{ext}")
            counter += 1

        if encrypt and self._key:
            dest = dest + ".enc"
            with open(filepath, "rb") as f:
                data = f.read()
            encrypted = self._encrypt_data(data)
            with open(dest, "wb") as f:
                f.write(encrypted)
            os.remove(filepath)
        else:
            shutil.move(filepath, dest)

        try:
            size = os.path.getsize(dest)
        except Exception:
            size = 0
        self.metadata[os.path.basename(dest)] = {
            "original_path": filepath,
            "quarantined_at": datetime.now().isoformat(),
            "size": size,
            "restored": False,
            "encrypted": bool(encrypt and self._key)
        }
        self.save_metadata()
        return dest

    def restore_file(self, quarantined_name):
        src = os.path.join(self.quarantine_dir, quarantined_name)
        if not os.path.exists(src):
            return False
        info = self.metadata.get(quarantined_name, {})
        dest = info.get("original_path", src)
        dest_dir = os.path.dirname(dest)
        if dest_dir and not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)

        if info.get("encrypted", False) and self._key:
            with open(src, "rb") as f:
                encrypted = f.read()
            decrypted = self._decrypt_data(encrypted)
            with open(dest, "wb") as f:
                f.write(decrypted)
            os.remove(src)
        else:
            shutil.move(src, dest)

        if quarantined_name in self.metadata:
            self.metadata[quarantined_name]["restored"] = True
            self.metadata[quarantined_name]["restored_at"] = datetime.now().isoformat()
            self.save_metadata()
        return dest

    def delete_quarantined(self, quarantined_name):
        src = os.path.join(self.quarantine_dir, quarantined_name)
        if os.path.exists(src):
            os.remove(src)
        if quarantined_name in self.metadata:
            del self.metadata[quarantined_name]
            self.save_metadata()
        return True

    def list_quarantined(self):
        return list(self.metadata.keys())

    def get_quarantine_info(self, quarantined_name):
        return self.metadata.get(quarantined_name, {})

    def cleanup_old(self):
        """Remove quarantine entries older than max_age_days."""
        max_age = self.config.get("quarantine", {}).get("max_age_days", 30)
        cutoff = datetime.now() - timedelta(days=max_age)
        to_remove = []
        for name, info in self.metadata.items():
            try:
                q_at = datetime.fromisoformat(info.get("quarantined_at", ""))
                if q_at < cutoff:
                    to_remove.append(name)
            except Exception:
                continue
        for name in to_remove:
            self.delete_quarantined(name)
        return to_remove
