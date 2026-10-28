import os
import sys
import json
import tkinter as tk
from tkinter import messagebox

# Make sure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logger import setup_logger
from gui import CapAntiVirusGUI
from updater import Updater
from scanner import Scanner
from quarantine import QuarantineManager
from realtime_protection import RealTimeProtection
from scheduler import Scheduler
from system_tray import SystemTray


CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(config):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Config save error: {e}")


if __name__ == "__main__":
    config = load_config()

    vt_api_key = os.environ.get("VT_API_KEY", "") or config.get("vt_api_key", "")
    if not vt_api_key:
        print("Info: VT_API_KEY not set. VirusTotal queries will be disabled.")

    logger = setup_logger()

    # Core components
    scanner = Scanner(config=config)
    quarantine = QuarantineManager(config=config)
    updater = Updater(
        vt_api_key=vt_api_key,
        api_version=config.get("virustotal", {}).get("api_version", "v3")
    )

    # Real-time protection
    realtime = RealTimeProtection(
        config=config,
        quarantine=quarantine,
        scanner=scanner
    )

    # Scheduler
    def run_scheduled_scan(scan_type):
        logger.info(f"Scheduled scan triggered: {scan_type}")
        # The GUI will handle actually starting the scan via its own method
        if hasattr(main_window, "start_scheduled_scan"):
            main_window.start_scheduled_scan(scan_type)

    scheduler = Scheduler(config=config, scan_callback=run_scheduled_scan)

    # Start background services
    realtime.start()
    scheduler.start()

    # Launch GUI
    root = tk.Tk()
    app = CapAntiVirusGUI(
        root,
        config=config,
        scanner=scanner,
        quarantine=quarantine,
        updater=updater,
        realtime=realtime,
        scheduler=scheduler,
        logger=logger
    )
    main_window = app

    # Tray
    tray = SystemTray(root, app)

    def on_closing():
        if config.get("gui", {}).get("minimize_to_tray", True):
            tray.hide_window()
        else:
            app.on_closing()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    root.mainloop()

    # Cleanup on exit
    realtime.stop()
    scheduler.stop()
