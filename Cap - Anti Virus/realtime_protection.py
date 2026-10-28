import os
import threading
import time
from datetime import datetime
from scanner import Scanner


try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True


    class _ThreatHandler(FileSystemEventHandler):
        """watchdog olaylarını dinleyen handler."""

        def __init__(self, rtp):
            self.rtp = rtp

        def on_created(self, event):
            if not event.is_directory:
                self.rtp._on_file_event(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self.rtp._on_file_event(event.src_path)


except Exception:
    WATCHDOG_AVAILABLE = False

    class _ThreatHandler:  # type: ignore
        """Yedek (watchdog yoksa kullanilmayan) stub sınıf."""
        def __init__(self, rtp):
            self.rtp = rtp


class RealTimeProtection:
    def __init__(self, config=None, quarantine=None, scanner=None, callback=None):
        self.config = config or {}
        self.quarantine = quarantine
        self.scanner = scanner or Scanner(config=config)
        self.callback = callback  # function(result) called when threat found
        self.enabled = False
        self._thread = None
        self._stop = threading.Event()
        self.monitor_paths = []
        self.poll_interval = 5
        self._seen = {}  # path -> mtime
        self._observer = None
        self._use_watchdog = False

    def start(self):
        if self.enabled:
            return
        rt = self.config.get("realtime_protection", {})
        self.enabled = rt.get("enabled", False)
        self.monitor_paths = rt.get("monitor_paths", [])
        self.poll_interval = rt.get("poll_interval_seconds", 5)
        self._use_watchdog = rt.get("use_watchdog", False) and WATCHDOG_AVAILABLE

        if not self.enabled:
            return
        self._stop.clear()

        if self._use_watchdog:
            self._start_watchdog()
        else:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def _start_watchdog(self):
        self._observer = Observer()
        handler = _ThreatHandler(self)
        for path in self.monitor_paths:
            if os.path.exists(path):
                self._observer.schedule(handler, path, recursive=True)
        self._observer.start()

    def stop(self):
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)
            self._observer = None
        if self._thread:
            self._thread.join(timeout=2)
        self.enabled = False

    def _on_file_event(self, filepath):
        """Dosya oluşturma/değişiklik olayı geldiğinde tek dosyayı tarar."""
        try:
            result = self.scanner.scan_file(filepath)
            if result.get("threat"):
                if self.callback:
                    self.callback(result)
                if self.quarantine:
                    self.quarantine.quarantine_file(filepath)
        except Exception:
            pass

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._scan_changed()
            except Exception:
                pass
            self._stop.wait(self.poll_interval)

    def _scan_changed(self):
        rt = self.config.get("realtime_protection", {})
        paths = rt.get("monitor_paths", [])
        interval = rt.get("poll_interval_seconds", 5)

        for path in paths:
            if not os.path.exists(path):
                continue
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in {
                    "node_modules", ".git", "__pycache__", "venv",
                    ".env", "build", "dist", ".vscode", ".idea"
                }]
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(filepath)
                    except Exception:
                        continue
                    prev = self._seen.get(filepath)
                    if prev is None:
                        self._seen[filepath] = mtime
                        continue
                    if mtime != prev:
                        self._seen[filepath] = mtime
                        result = self.scanner.scan_file(filepath)
                        if result.get("threat"):
                            if self.callback:
                                self.callback(result)
                            if self.quarantine:
                                self.quarantine.quarantine_file(filepath)

    def add_monitor_path(self, path):
        if path not in self.monitor_paths:
            self.monitor_paths.append(path)
            rt = self.config.setdefault("realtime_protection", {})
            rt["monitor_paths"] = self.monitor_paths
            if self._observer and os.path.exists(path):
                self._observer.schedule(_ThreatHandler(self), path, recursive=True)

    def remove_monitor_path(self, path):
        if path in self.monitor_paths:
            self.monitor_paths.remove(path)
            rt = self.config.setdefault("realtime_protection", {})
            rt["monitor_paths"] = self.monitor_paths
