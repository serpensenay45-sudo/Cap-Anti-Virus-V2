import threading
import time
from datetime import datetime


class Scheduler:
    def __init__(self, config=None, scan_callback=None):
        self.config = config or {}
        self.scan_callback = scan_callback  # function(scan_type) to run a scan
        self.enabled = False
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        if self.enabled:
            return
        sched = self.config.get("scheduler", {})
        self.enabled = sched.get("enabled", False)
        if not self.enabled:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.enabled = False

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._check_due()
            except Exception:
                pass
            # Check every 60 seconds
            self._stop.wait(60)

    def _check_due(self):
        sched = self.config.get("scheduler", {})
        if not sched.get("enabled", False):
            return
        now = datetime.now()
        hour = sched.get("hour", 2)
        minute = sched.get("minute", 0)
        scan_type = sched.get("scan_type", "quick")

        # Simple check: if current time matches scheduled hour:minute (within the 60s window)
        if now.hour == hour and now.minute == minute:
            if self.scan_callback:
                self.scan_callback(scan_type)
