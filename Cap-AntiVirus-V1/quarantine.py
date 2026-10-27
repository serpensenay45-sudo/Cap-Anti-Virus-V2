import os
import shutil
import json
from datetime import datetime

class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = quarantine_dir
        self.metadata_file = os.path.join(quarantine_dir, "metadata.json")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.metadata = self.load_metadata()

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
        filename = os.path.basename(filepath)
        dest = os.path.join(self.quarantine_dir, filename)
        counter = 1
        while os.path.exists(dest):
            name, ext = os.path.splitext(filename)
            dest = os.path.join(self.quarantine_dir, f"{name}_{counter}{ext}")
            counter += 1
        shutil.move(filepath, dest)
        self.metadata[os.path.basename(dest)] = {
            "original_path": filepath,
            "quarantined_at": datetime.now().isoformat()
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
        shutil.move(src, dest)
        if quarantined_name in self.metadata:
            del self.metadata[quarantined_name]
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