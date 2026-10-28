import os
import sys
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

from scanner import Scanner
from quarantine import QuarantineManager
from logger import setup_logger
from info import INFO_TEXT
from updater import Updater
from realtime_protection import RealTimeProtection
from scheduler import Scheduler


STRINGS = {
    "title": "Cap - Anti Virus V2",
    "tab_dashboard": "Dashboard",
    "tab_scan": "Scan",
    "tab_quarantine": "Quarantine",
    "tab_history": "History",
    "tab_settings": "Settings",
    "tab_info": "Info",
    "btn_quick": "Quick Scan",
    "btn_full": "Full System Scan",
    "btn_folder": "Select Folder and Scan",
    "btn_usb": "Scan USB / Removable",
    "btn_clear": "Clear Results",
    "btn_quarantine": "Quarantine Selected",
    "btn_report": "Save Report",
    "btn_refresh": "Refresh",
    "btn_restore": "Restore",
    "btn_delete": "Delete Permanently",
    "btn_virustotal": "VirusTotal Lookup",
    "btn_stop": "Stop",
    "status_ready": "Ready",
    "status_scanning": "Scanning: {}",
    "status_done": "Completed: {} files scanned, {} threats found",
    "status_stopped": "Scan stopped: {} files scanned, {} threats found",
    "col_status": "Status",
    "col_path": "File Path",
    "col_hash": "Hash",
    "col_type": "Type",
    "col_reason": "Suspicious Reasons",
    "status_threat": "THREAT",
    "status_clean": "Clean",
    "warn_select": "Please select a file.",
    "confirm_quarantine": "Quarantine this file?\n{}",
    "quarantined": "Quarantined:\n{}",
    "confirm_restore": "Restore this file?\n{}",
    "restored": "Restored:\n{}",
    "confirm_delete": "Permanently delete this file?\n{}",
    "vt_title": "VirusTotal Result",
    "vt_not_found": "This file was not found in VirusTotal database.",
    "vt_detected": "{}/{} security vendors flagged this file as malicious.",
    "vt_clean": "This file is considered clean by VirusTotal (0/{}).",
    "vt_error": "Error: {}",
    "vt_no_hash": "File hash could not be calculated.",
    "vt_no_api": "VirusTotal API key not defined. Set VT_API_KEY environment variable.",
    "vt_scanning": "Querying VirusTotal...",
    "stat_scans": "Total Scans",
    "stat_threats": "Threats Found",
    "stat_quarantined": "Quarantined Files",
    "stat_realtime": "Real-Time Protection",
    "btn_enable_realtime": "Enable Real-Time Protection",
    "btn_disable_realtime": "Disable Real-Time Protection",
    "lbl_realtime_status_off": "Real-Time Protection: OFF",
    "lbl_realtime_status_on": "Real-Time Protection: ON",
    "setting_theme": "Theme",
    "setting_dark": "Dark",
    "setting_light": "Light",
    "setting_vt_key": "VirusTotal API Key",
    "btn_save_settings": "Save Settings",
    "history_empty": "No scan history yet.",
    "col_history_date": "Date",
    "col_history_path": "Path",
    "col_history_files": "Files",
    "col_history_threats": "Threats",
    "col_history_type": "Scan Type",
    "btn_export_history": "Export History",
    "report_txt": "Text Report (.txt)",
    "report_html": "HTML Report (.html)",
}


# ---------- Dark Theme ----------
DARK_BG = "#1e1e1e"
DARK_PANEL = "#252526"
DARK_ENTRY = "#333333"
DARK_FG = "#cccccc"
DARK_ACCENT = "#007acc"
DARK_SUCCESS = "#4caf50"
DARK_WARNING = "#ff9800"
DARK_DANGER = "#f44336"
LIGHT_BG = "#f0f0f0"
LIGHT_PANEL = "#ffffff"
LIGHT_FG = "#333333"


class CapAntiVirusGUI:
    def __init__(self, root, config=None, scanner=None, quarantine=None,
                 updater=None, realtime=None, scheduler=None, logger=None):
        self.root = root
        self.config = config or {}
        self.t = STRINGS
        self.logger = logger or setup_logger()

        self.root.title(self.t["title"])
        width = self.config.get("gui", {}).get("window_width", 1100)
        height = self.config.get("gui", {}).get("window_height", 800)
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(900, 600)

        # Components
        self.scanner = scanner or Scanner(config=self.config)
        self.quarantine = quarantine or QuarantineManager(config=self.config)
        self.updater = updater if updater else Updater()
        self.realtime = realtime
        self.scheduler = scheduler

        # State
        self.scanning = False
        self.scan_results = []
        self.scan_history = self.load_history()
        self.dark_mode = self.config.get("gui", {}).get("dark_mode", True)

        # UI refs
        self.tree = None
        self.history_tree = None
        self.quar_list = None
        self.status_var = None
        self.progress = None
        self.realtime_status_var = None
        self.stats_labels = {}

        self._setup_styles()
        self.create_widgets()
        self.apply_ui_text()
        self.refresh_stats()
        self.refresh_quarantine()
        self.refresh_history()

        # Start real-time if enabled
        if self.realtime:
            self.realtime.start()
            self._update_realtime_status()

    # ---------- Styling ----------
    def _setup_styles(self):
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        self._apply_theme()

    def _apply_theme(self):
        if self.dark_mode:
            bg = DARK_BG
            panel = DARK_PANEL
            entry = DARK_ENTRY
            fg = DARK_FG
            accent = DARK_ACCENT
        else:
            bg = LIGHT_BG
            panel = LIGHT_PANEL
            entry = "#ffffff"
            fg = LIGHT_FG
            accent = DARK_ACCENT

        self.root.configure(bg=bg)

        self.style.configure(".", background=bg, foreground=fg, fieldbackground=entry)
        self.style.configure("TFrame", background=bg)
        self.style.configure("TLabel", background=bg, foreground=fg)
        self.style.configure("TNotebook", background=bg, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=panel, foreground=fg,
                             padding=[12, 6], borderwidth=1)
        self.style.map("TNotebook.Tab",
                       background=[("selected", accent), ("!selected", panel)],
                       foreground=[("selected", "#ffffff"), ("!selected", fg)])
        self.style.configure("TButton", background=panel, foreground=fg,
                             borderwidth=1, focusthickness=0, padding=[8, 4])
        self.style.map("TButton", background=[("active", accent), ("!disabled", panel)])
        self.style.configure("TEntry", fieldbackground=entry, foreground=fg, borderwidth=1)
        self.style.configure("Horizontal.TProgressbar", background=accent, troughcolor=panel)
        self.style.configure("Treeview", background=entry, foreground=fg,
                             fieldbackground=entry, borderwidth=0)
        self.style.configure("Treeview.Heading", background=panel, foreground=fg)
        self.style.map("Treeview", background=[("selected", accent)])

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.config.setdefault("gui", {})["dark_mode"] = self.dark_mode
        self._apply_theme()
        self.apply_ui_text()

    # ---------- Widgets ----------
    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Dashboard
        self.tab_dash = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dash, text=self.t_("tab_dashboard"))
        self.build_dashboard_tab()

        # Scan
        self.tab_scan = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_scan, text=self.t_("tab_scan"))
        self.build_scan_tab()

        # Quarantine
        self.tab_quar = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_quar, text=self.t_("tab_quarantine"))
        self.build_quarantine_tab()

        # History
        self.tab_hist = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_hist, text=self.t_("tab_history"))
        self.build_history_tab()

        # Settings
        self.tab_sett = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sett, text=self.t_("tab_settings"))
        self.build_settings_tab()

        # Info
        self.tab_info = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_info, text=self.t_("tab_info"))
        self.build_info_tab()

        # Bottom status bar
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.realtime_status_var = tk.StringVar(value=self.t_("lbl_realtime_status_off"))
        self.realtime_status_lbl = ttk.Label(
            bottom_frame, textvariable=self.realtime_status_var,
            foreground=DARK_DANGER if self.dark_mode else DARK_DANGER
        )
        self.realtime_status_lbl.pack(side=tk.LEFT, padx=10, pady=2)

        self.status_var = tk.StringVar(value=self.t_("status_ready"))
        self.status_bar = ttk.Label(
            bottom_frame, textvariable=self.status_var,
            relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=2)

    def t_(self, key):
        return self.t.get(key, key)

    def apply_ui_text(self):
        self.root.title(self.t_("title"))
        tabs = [
            (self.tab_dash, self.t_("tab_dashboard")),
            (self.tab_scan, self.t_("tab_scan")),
            (self.tab_quar, self.t_("tab_quarantine")),
            (self.tab_hist, self.t_("tab_history")),
            (self.tab_sett, self.t_("tab_settings")),
            (self.tab_info, self.t_("tab_info")),
        ]
        for i, (frame, text) in enumerate(tabs):
            self.notebook.tab(i, text=text)

        # Dashboard
        self.dash_title.config(text=self.t_("title"))
        self.btn_dash_quick.config(text=self.t_("btn_quick"))
        self.btn_dash_full.config(text=self.t_("btn_full"))
        self.btn_dash_folder.config(text=self.t_("btn_folder"))
        self.btn_dash_usb.config(text=self.t_("btn_usb"))
        self.btn_dash_quarantine.config(text=self.t_("btn_quarantine"))

        # Scan tab buttons
        self.btn_quick.config(text=self.t_("btn_quick"))
        self.btn_full.config(text=self.t_("btn_full"))
        self.btn_folder.config(text=self.t_("btn_folder"))
        self.btn_usb.config(text=self.t_("btn_usb"))
        self.btn_clear.config(text=self.t_("btn_clear"))
        self.btn_stop.config(text=self.t_("btn_stop"))
        self.btn_virustotal.config(text=self.t_("btn_virustotal"))
        self.btn_quarantine.config(text=self.t_("btn_quarantine"))
        self.btn_report.config(text=self.t_("btn_report"))

        cols = (self.t_("col_status"), self.t_("col_path"), self.t_("col_hash"),
                self.t_("col_type"), self.t_("col_reason"))
        for c, col in zip(self.tree["columns"], cols):
            self.tree.heading(c, text=col)

        # Quarantine tab
        self.btn_refresh.config(text=self.t_("btn_refresh"))
        self.btn_restore.config(text=self.t_("btn_restore"))
        self.btn_delete.config(text=self.t_("btn_delete"))

        # History tab
        hcols = (self.t_("col_history_date"), self.t_("col_history_path"),
                 self.t_("col_history_files"), self.t_("col_history_threats"),
                 self.t_("col_history_type"))
        for c, col in zip(self.history_tree["columns"], hcols):
            self.history_tree.heading(c, text=col)
        self.btn_export_history.config(text=self.t_("btn_export_history"))

        # Settings tab
        self.lbl_theme.config(text=self.t_("setting_theme"))
        self.btn_theme.config(text=self.t_("setting_dark") if self.dark_mode else self.t_("setting_light"))
        self.lbl_vt.config(text=self.t_("setting_vt_key"))
        self.btn_save_settings.config(text=self.t_("btn_save_settings"))

        # Info tab
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete("1.0", tk.END)
        self.info_text.insert(tk.END, INFO_TEXT)
        self.info_text.config(state=tk.DISABLED)

        self.status_var.set(self.t_("status_ready"))

    # ---------- Dashboard ----------
    def build_dashboard_tab(self):
        pad = 10
        # Title
        self.dash_title = ttk.Label(self.tab_dash, text=self.t_("title"),
                                    font=("Segoe UI", 16, "bold"))
        self.dash_title.pack(anchor=tk.W, padx=pad, pady=(pad, 5))

        # Stats cards frame
        stats_frame = ttk.Frame(self.tab_dash)
        stats_frame.pack(fill=tk.X, padx=pad, pady=5)

        self.stats_labels = {}
        stats_def = [
            ("total_scans", self.t_("stat_scans"), "0"),
            ("total_threats", self.t_("stat_threats"), "0"),
            ("quarantined", self.t_("stat_quarantined"), "0"),
        ]
        for key, label, default in stats_def:
            card = ttk.Frame(stats_frame)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
            ttk.Label(card, text=label, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
            val = ttk.Label(card, text=default, font=("Segoe UI", 16, "bold"),
                            foreground=DARK_ACCENT if self.dark_mode else DARK_ACCENT)
            val.pack(anchor=tk.W, pady=(2, 0))
            self.stats_labels[key] = val

        # Real-time status card
        rt_card = ttk.Frame(stats_frame)
        rt_card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Label(rt_card, text=self.t_("stat_realtime"), font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self.realtime_status_var = tk.StringVar(value=self.t_("lbl_realtime_status_off"))
        self.rt_status_lbl = ttk.Label(rt_card, textvariable=self.realtime_status_var,
                                       font=("Segoe UI", 12, "bold"), foreground=DARK_DANGER)
        self.rt_status_lbl.pack(anchor=tk.W, pady=(2, 0))

        self.btn_realtime_toggle = ttk.Button(
            rt_card, text=self.t_("btn_enable_realtime"), command=self.toggle_realtime
        )
        self.btn_realtime_toggle.pack(anchor=tk.W, pady=(5, 0))

        # Quick actions
        actions_frame = ttk.Frame(self.tab_dash)
        actions_frame.pack(fill=tk.X, padx=pad, pady=15)

        self.btn_dash_quick = ttk.Button(actions_frame, text=self.t_("btn_quick"),
                                         command=lambda: self.quick_scan_from_dashboard())
        self.btn_dash_quick.pack(side=tk.LEFT, padx=5)

        self.btn_dash_full = ttk.Button(actions_frame, text=self.t_("btn_full"),
                                        command=lambda: self.full_scan_from_dashboard())
        self.btn_dash_full.pack(side=tk.LEFT, padx=5)

        self.btn_dash_folder = ttk.Button(actions_frame, text=self.t_("btn_folder"),
                                          command=self.scan_folder_from_dashboard)
        self.btn_dash_folder.pack(side=tk.LEFT, padx=5)

        self.btn_dash_usb = ttk.Button(actions_frame, text=self.t_("btn_usb"),
                                       command=self.usb_scan_from_dashboard)
        self.btn_dash_usb.pack(side=tk.LEFT, padx=5)

        self.btn_dash_quarantine = ttk.Button(actions_frame, text=self.t_("btn_quarantine"),
                                              command=lambda: self.notebook.select(self.tab_quar))
        self.btn_dash_quarantine.pack(side=tk.LEFT, padx=5)

        # Recent activity note
        ttk.Label(self.tab_dash, text="Recent activity will appear in the History tab.",
                  font=("Segoe UI", 9), foreground="#888888").pack(anchor=tk.W, padx=pad, pady=(20, 0))

    # ---------- Scan Tab ----------
    def build_scan_tab(self):
        btn_frame = ttk.Frame(self.tab_scan)
        btn_frame.pack(fill=tk.X, pady=5)

        self.btn_quick = ttk.Button(btn_frame, text=self.t_("btn_quick"), command=self.quick_scan)
        self.btn_quick.pack(side=tk.LEFT, padx=5)

        self.btn_full = ttk.Button(btn_frame, text=self.t_("btn_full"), command=self.full_scan)
        self.btn_full.pack(side=tk.LEFT, padx=5)

        self.btn_folder = ttk.Button(btn_frame, text=self.t_("btn_folder"), command=self.scan_folder)
        self.btn_folder.pack(side=tk.LEFT, padx=5)

        self.btn_usb = ttk.Button(btn_frame, text=self.t_("btn_usb"), command=self.usb_scan)
        self.btn_usb.pack(side=tk.LEFT, padx=5)

        self.btn_clear = ttk.Button(btn_frame, text=self.t_("btn_clear"), command=self.clear_results)
        self.btn_clear.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(btn_frame, text=self.t_("btn_stop"), command=self.stop_scan,
                                   state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_virustotal = ttk.Button(btn_frame, text=self.t_("btn_virustotal"),
                                         command=self.virustotal_selected)
        self.btn_virustotal.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(self.tab_scan, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        cols = ("status", "path", "hash", "type", "reason")
        self.tree = ttk.Treeview(self.tab_scan, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=180)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.tree.tag_configure("threat", foreground=DARK_DANGER)
        self.tree.tag_configure("clean", foreground=DARK_SUCCESS if self.dark_mode else "#2e7d32")

        act_frame = ttk.Frame(self.tab_scan)
        act_frame.pack(fill=tk.X, pady=5)

        self.btn_quarantine = ttk.Button(act_frame, text=self.t_("btn_quarantine"),
                                         command=self.quarantine_selected)
        self.btn_quarantine.pack(side=tk.LEFT, padx=5)

        self.btn_report = ttk.Button(act_frame, text=self.t_("btn_report"), command=self.save_report)
        self.btn_report.pack(side=tk.LEFT, padx=5)

    # ---------- Quarantine Tab ----------
    def build_quarantine_tab(self):
        self.quar_list = tk.Listbox(self.tab_quar, bg=DARK_ENTRY if self.dark_mode else "#ffffff",
                                    fg=DARK_FG if self.dark_mode else "#000000",
                                    selectbackground=DARK_ACCENT, selectforeground="#ffffff")
        self.quar_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_frame = ttk.Frame(self.tab_quar)
        btn_frame.pack(fill=tk.X, pady=5)

        self.btn_refresh = ttk.Button(btn_frame, text=self.t_("btn_refresh"), command=self.refresh_quarantine)
        self.btn_refresh.pack(side=tk.LEFT, padx=5)

        self.btn_restore = ttk.Button(btn_frame, text=self.t_("btn_restore"), command=self.restore_selected)
        self.btn_restore.pack(side=tk.LEFT, padx=5)

        self.btn_delete = ttk.Button(btn_frame, text=self.t_("btn_delete"), command=self.delete_selected)
        self.btn_delete.pack(side=tk.LEFT, padx=5)

    # ---------- History Tab ----------
    def build_history_tab(self):
        toolbar = ttk.Frame(self.tab_hist)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        self.btn_export_history = ttk.Button(toolbar, text=self.t_("btn_export_history"),
                                             command=self.export_history)
        self.btn_export_history.pack(side=tk.LEFT)

        hcols = ("date", "path", "files", "threats", "type")
        self.history_tree = ttk.Treeview(self.tab_hist, columns=hcols, show="headings")
        for c in hcols:
            self.history_tree.heading(c, text=c)
            self.history_tree.column(c, width=200)
        self.history_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        if not self.scan_history:
            self.history_tree.insert("", tk.END, values=(
                self.t_("history_empty"), "", "", "", ""
            ))

    # ---------- Settings Tab ----------
    def build_settings_tab(self):
        pad = 10
        container = ttk.Frame(self.tab_sett)
        container.pack(fill=tk.BOTH, expand=True, padx=pad, pady=pad)

        # Theme
        theme_frame = ttk.Frame(container)
        theme_frame.pack(fill=tk.X, pady=5)
        self.lbl_theme = ttk.Label(theme_frame, text=self.t_("setting_theme"), font=("Segoe UI", 10, "bold"))
        self.lbl_theme.pack(side=tk.LEFT, padx=(0, 10))
        self.btn_theme = ttk.Button(theme_frame, text="", command=self.toggle_theme)
        self.btn_theme.pack(side=tk.LEFT)

        # VirusTotal API key
        vt_frame = ttk.Frame(container)
        vt_frame.pack(fill=tk.X, pady=10)
        self.lbl_vt = ttk.Label(vt_frame, text=self.t_("setting_vt_key"), font=("Segoe UI", 10, "bold"))
        self.lbl_vt.pack(side=tk.LEFT, padx=(0, 10))
        self.vt_key_entry = ttk.Entry(vt_frame, width=50)
        self.vt_key_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        current_key = self.config.get("vt_api_key", "")
        if current_key:
            self.vt_key_entry.insert(0, current_key)

        # Real-time protection
        rt_frame = ttk.Frame(container)
        rt_frame.pack(fill=tk.X, pady=10)
        ttk.Label(rt_frame, text="Real-Time Protection", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        self.realtime_var = tk.BooleanVar(value=self.config.get("realtime_protection", {}).get("enabled", False))
        ttk.Checkbutton(rt_frame, text="Enabled", variable=self.realtime_var).pack(side=tk.LEFT)

        # Scheduler
        sched_frame = ttk.Frame(container)
        sched_frame.pack(fill=tk.X, pady=10)
        ttk.Label(sched_frame, text="Scheduled Scan", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        self.sched_var = tk.BooleanVar(value=self.config.get("scheduler", {}).get("enabled", False))
        ttk.Checkbutton(sched_frame, text="Enabled", variable=self.sched_var).pack(side=tk.LEFT)
        ttk.Label(sched_frame, text="  Hour:").pack(side=tk.LEFT, padx=(10, 0))
        self.sched_hour = ttk.Entry(sched_frame, width=5)
        self.sched_hour.insert(0, str(self.config.get("scheduler", {}).get("hour", 2)))
        self.sched_hour.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(sched_frame, text="  Minute:").pack(side=tk.LEFT)
        self.sched_min = ttk.Entry(sched_frame, width=5)
        self.sched_min.insert(0, str(self.config.get("scheduler", {}).get("minute", 0)))
        self.sched_min.pack(side=tk.LEFT, padx=(0, 5))

        self.btn_save_settings = ttk.Button(container, text=self.t_("btn_save_settings"),
                                            command=self.save_settings)
        self.btn_save_settings.pack(anchor=tk.E, pady=10)

        ttk.Label(container, text="Note: Restart the app to apply some settings changes.",
                  font=("Segoe UI", 9), foreground="#888888").pack(anchor=tk.W, pady=(10, 0))

    # ---------- Info Tab ----------
    def build_info_tab(self):
        self.info_text = tk.Text(self.tab_info, wrap=tk.WORD, padx=10, pady=10,
                                 bg=DARK_ENTRY if self.dark_mode else "#ffffff",
                                 fg=DARK_FG if self.dark_mode else "#000000")
        self.info_text.pack(fill=tk.BOTH, expand=True)
        self.info_text.insert(tk.END, INFO_TEXT)
        self.info_text.config(state=tk.DISABLED)

    # ---------- Helpers ----------
    def _set_buttons_state(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        for btn in [self.btn_quick, self.btn_full, self.btn_folder, self.btn_usb,
                    self.btn_clear, self.btn_quarantine, self.btn_report,
                    self.btn_virustotal]:
            btn.config(state=state)

    def _insert_result(self, result):
        if result.get("threat_type") == "cancelled":
            return
        if result["threat"]:
            status = self.t_("status_threat")
            tag = "threat"
        else:
            status = self.t_("status_clean")
            tag = "clean"
        heur = "; ".join(result.get("heuristic", []))
        self.tree.insert(
            "", tk.END,
            values=(status, result["path"], result["hash"] or "-",
                    result.get("threat_type", "-"), heur),
            tags=(tag,)
        )

    def refresh_stats(self):
        total_scans = len(self.scan_history)
        total_threats = sum(h.get("threats", 0) for h in self.scan_history)
        quarantined = len(self.quarantine.list_quarantined())

        self.stats_labels["total_scans"].config(text=str(total_scans))
        self.stats_labels["total_threats"].config(text=str(total_threats))
        self.stats_labels["quarantined"].config(text=str(quarantined))

    def _update_realtime_status(self):
        if not self.realtime:
            self.realtime_status_var.set("Real-Time Protection: N/A")
            self.btn_realtime_toggle.config(text="N/A", state=tk.DISABLED)
            return
        enabled = self.config.get("realtime_protection", {}).get("enabled", False)
        if enabled:
            self.realtime_status_var.set(self.t_("lbl_realtime_status_on"))
            self.realtime_status_lbl.config(foreground=DARK_SUCCESS if self.dark_mode else DARK_SUCCESS)
            self.btn_realtime_toggle.config(text=self.t_("btn_disable_realtime"))
        else:
            self.realtime_status_var.set(self.t_("lbl_realtime_status_off"))
            self.realtime_status_lbl.config(foreground=DARK_DANGER)
            self.btn_realtime_toggle.config(text=self.t_("btn_enable_realtime"))

    def toggle_realtime(self):
        rt = self.config.setdefault("realtime_protection", {})
        current = rt.get("enabled", False)
        rt["enabled"] = not current
        if self.realtime:
            if rt["enabled"]:
                self.realtime.start()
            else:
                self.realtime.stop()
        self._update_realtime_status()
        self.refresh_stats()

    def load_history(self):
        hist_file = os.path.join("history", "history.json")
        if os.path.exists(hist_file):
            try:
                with open(hist_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def save_history(self):
        os.makedirs("history", exist_ok=True)
        hist_file = os.path.join("history", "history.json")
        try:
            max_entries = self.config.get("history", {}).get("max_entries", 100)
            data = self.scan_history[-max_entries:]
            with open(hist_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"History save error: {e}")

    def refresh_history(self):
        if not hasattr(self, "history_tree"):
            return
        self.history_tree.delete(*self.history_tree.get_children())
        if not self.scan_history:
            self.history_tree.insert("", tk.END, values=(
                self.t_("history_empty"), "", "", "", ""
            ))
            return
        for h in reversed(self.scan_history):
            self.history_tree.insert("", tk.END, values=(
                h.get("date", ""), h.get("path", ""), h.get("files", 0),
                h.get("threats", 0), h.get("type", "")
            ))

    def add_history_entry(self, path, files_count, threats_count, scan_type):
        entry = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "path": path,
            "files": files_count,
            "threats": threats_count,
            "type": scan_type
        }
        self.scan_history.append(entry)
        self.save_history()
        self.refresh_history()
        self.refresh_stats()

    # ---------- Scan actions ----------
    def quick_scan(self):
        self._start_scan(os.path.join(os.path.expanduser("~"), "Documents"), "quick")

    def full_scan(self):
        self._start_scan(os.path.expanduser("~"), "full")

    def scan_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self._start_scan(folder, "custom")

    def usb_scan(self):
        self._start_scan("USB/Removable", "usb")

    def quick_scan_from_dashboard(self):
        self.quick_scan()

    def full_scan_from_dashboard(self):
        self.full_scan()

    def scan_folder_from_dashboard(self):
        self.scan_folder()

    def usb_scan_from_dashboard(self):
        self.usb_scan()

    def start_scheduled_scan(self, scan_type):
        if self.scanning:
            return
        path = os.path.expanduser("~\\Documents") if scan_type == "quick" else os.path.expanduser("~")
        self._start_scan(path, scan_type)

    def _start_scan(self, path, scan_type):
        if self.scanning:
            return
        if path == "USB/Removable":
            self.start_scan_usb(scan_type)
            return
        self.start_scan(path, scan_type)

    def start_scan(self, path, scan_type="custom"):
        if self.scanning:
            return
        self.scanning = True
        self.scan_results = []
        self.tree.delete(*self.tree.get_children())
        self.status_var.set(self.t_("status_scanning").format(path))
        self.progress.start()
        self._set_buttons_state(False)
        self.btn_stop.config(state=tk.NORMAL)

        thread = threading.Thread(target=self._run_scan, args=(path, scan_type), daemon=True)
        thread.start()

    def start_scan_usb(self, scan_type="usb"):
        if self.scanning:
            return
        self.scanning = True
        self.scan_results = []
        self.tree.delete(*self.tree.get_children())
        self.status_var.set("Scanning removable drives...")
        self.progress.start()
        self._set_buttons_state(False)
        self.btn_stop.config(state=tk.NORMAL)

        thread = threading.Thread(target=self._run_usb_scan, args=(scan_type,), daemon=True)
        thread.start()

    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.scanner.request_stop()
            self.btn_stop.config(state=tk.DISABLED)
            self.status_var.set(self.t_("status_ready"))

    def _run_scan(self, path, scan_type):
        results = self.scanner.scan_directory(path, callback=self._on_file_scanned)
        self.root.after(0, lambda: self._scan_finished(results, path, scan_type,
                                                       self.scanner.stop_requested))

    def _run_usb_scan(self, scan_type):
        results = self.scanner.scan_removable_drives(callback=self._on_file_scanned)
        self.root.after(0, lambda: self._scan_finished(results, "Removable Drives", scan_type,
                                                       self.scanner.stop_requested))

    def _on_file_scanned(self, result):
        self.root.after(0, lambda: self._insert_result(result))

    def _scan_finished(self, results, path, scan_type, was_stopped):
        self.progress.stop()
        self.scanning = False
        self._set_buttons_state(True)
        self.btn_stop.config(state=tk.DISABLED)
        threat_count = sum(1 for r in results if r["threat"])
        if was_stopped:
            self.status_var.set(self.t_("status_stopped").format(len(results), threat_count))
        else:
            self.status_var.set(self.t_("status_done").format(len(results), threat_count))
        self.logger.info(f"Scan completed: {path}, {len(results)} files, {threat_count} threats")
        self.add_history_entry(path, len(results), threat_count, scan_type)

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())

    def quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Warning", self.t_("warn_select"))
            return
        item = self.tree.item(sel[0])
        path = item["values"][1]
        if messagebox.askyesno("Confirm", self.t_("confirm_quarantine").format(path)):
            dest = self.quarantine.quarantine_file(path)
            if dest:
                messagebox.showinfo("Success", self.t_("quarantined").format(dest))
                self.tree.delete(sel[0])
                self.refresh_quarantine()
                self.refresh_stats()

    def save_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text File", "*.txt"), ("HTML File", "*.html")]
        )
        if not path:
            return
        try:
            if path.endswith(".html"):
                self._save_html_report(path)
            else:
                self._save_txt_report(path)
            messagebox.showinfo("Success", "Report saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {e}")

    def _save_txt_report(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("Cap - Anti Virus V2 - Scan Report\n")
            f.write("=" * 40 + "\n\n")
            for child in self.tree.get_children():
                vals = self.tree.item(child)["values"]
                f.write(" | ".join(str(v) for v in vals) + "\n")

    def _save_html_report(self, path):
        rows = ""
        for child in self.tree.get_children():
            vals = self.tree.item(child)["values"]
            rows += "<tr>" + "".join(f"<td>{v}</td>" for v in vals) + "</tr>"
        html = f"""<html><head><meta charset="utf-8"><title>Cap - Anti Virus V2 Report</title>
<style>body{{font-family:segoe ui;background:#1e1e1e;color:#ccc;}}table{{border-collapse:collapse;width:100%;}}
th,td{{border:1px solid #444;padding:6px;text-align:left;}}th{{background:#007acc;color:#fff;}}
tr:nth-child(even){{background:#252526;}}</style></head><body>
<h1>Cap - Anti Virus V2 - Scan Report</h1>
<table><tr><th>Status</th><th>Path</th><th>Hash</th><th>Type</th><th>Reason</th></tr>{rows}</table></body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def virustotal_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Warning", self.t_("warn_select"))
            return
        if not self.updater.vt_api_key:
            messagebox.showerror("Error", self.t_("vt_no_api"))
            return

        item = self.tree.item(sel[0])
        path = item["values"][1]
        file_hash = item["values"][2]

        if file_hash == "-" or not file_hash:
            messagebox.showerror("Error", self.t_("vt_no_hash"))
            return

        self.status_var.set(self.t_("vt_scanning"))
        self.progress.start()
        self._set_buttons_state(False)

        thread = threading.Thread(target=self._run_vt_check, args=(path, file_hash), daemon=True)
        thread.start()

    def _run_vt_check(self, path, file_hash):
        result = self.updater.virustotal_check_by_hash(file_hash)
        self.root.after(0, lambda: self._vt_finished(path, file_hash, result))

    def _vt_finished(self, path, file_hash, result):
        self.progress.stop()
        self._set_buttons_state(True)
        self.status_var.set(self.t_("status_ready"))

        if "error" in result:
            messagebox.showerror("Error", self.t_("vt_error").format(result["error"]))
            return

        response_code = result.get("response_code", 0)
        if response_code == 0:
            messagebox.showinfo(self.t_("vt_title"), self.t_("vt_not_found"))
            return

        positives = result.get("positives", 0)
        total = result.get("total", 0)
        scan_date = result.get("scan_date", "Unknown")

        win = tk.Toplevel(self.root)
        win.title(self.t_("vt_title"))
        win.geometry("700x500")
        win.transient(self.root)
        win.grab_set()

        ttk.Label(win, text=f"File: {os.path.basename(path)}", font=("Segoe UI", 10, "bold")).pack(pady=5)
        ttk.Label(win, text=f"Hash: {file_hash}").pack(pady=2)
        ttk.Label(win, text=f"Date: {scan_date}").pack(pady=2)

        if positives == 0:
            msg = self.t_("vt_clean").format(total)
            lbl = ttk.Label(win, text=msg, foreground=DARK_SUCCESS if self.dark_mode else DARK_SUCCESS,
                            font=("Segoe UI", 10, "bold"))
        else:
            msg = self.t_("vt_detected").format(positives, total)
            lbl = ttk.Label(win, text=msg, foreground=DARK_DANGER, font=("Segoe UI", 10, "bold"))
        lbl.pack(pady=10)

        frame = ttk.Frame(win)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        cols = ("Antivirus", "Result")
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=15)
        tree.heading("Antivirus", text="Antivirus")
        tree.heading("Result", text="Result")
        tree.column("Antivirus", width=200)
        tree.column("Result", width=300)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        scans = result.get("scans", {})
        for av_name, av_data in scans.items():
            detected = av_data.get("detected", False)
            result_text = av_data.get("result", "Clean")
            display = f"MALICIOUS: {result_text}" if detected else "Clean"
            tree.insert("", tk.END, values=(av_name, display),
                        tags=("detected" if detected else "clean",))

        tree.tag_configure("detected", foreground=DARK_DANGER)
        tree.tag_configure("clean", foreground=DARK_SUCCESS if self.dark_mode else "#2e7d32")

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

    def refresh_quarantine(self):
        if not hasattr(self, "quar_list"):
            return
        self.quar_list.delete(0, tk.END)
        for name in self.quarantine.list_quarantined():
            self.quar_list.insert(tk.END, name)

    def restore_selected(self):
        sel = self.quar_list.curselection()
        if not sel:
            return
        name = self.quar_list.get(sel[0])
        if messagebox.askyesno("Confirm", self.t_("confirm_restore").format(name)):
            dest = self.quarantine.restore_file(name)
            if dest:
                messagebox.showinfo("Success", self.t_("restored").format(dest))
                self.refresh_quarantine()
                self.refresh_stats()

    def delete_selected(self):
        sel = self.quar_list.curselection()
        if not sel:
            return
        name = self.quar_list.get(sel[0])
        if messagebox.askyesno("Confirm", self.t_("confirm_delete").format(name)):
            self.quarantine.delete_quarantined(name)
            self.refresh_quarantine()
            self.refresh_stats()

    def export_history(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON File", "*.json")])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.scan_history, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Success", "History exported.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")

    def save_settings(self):
        self.config["vt_api_key"] = self.vt_key_entry.get().strip()
        self.config["realtime_protection"]["enabled"] = self.realtime_var.get()
        try:
            self.config["scheduler"]["enabled"] = self.sched_var.get()
            self.config["scheduler"]["hour"] = int(self.sched_hour.get())
            self.config["scheduler"]["minute"] = int(self.sched_min.get())
        except Exception:
            pass
        # Save config to disk
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            # Update components
            self.updater.vt_api_key = self.config["vt_api_key"]
            if self.realtime:
                if self.config["realtime_protection"]["enabled"]:
                    self.realtime.start()
                else:
                    self.realtime.stop()
            self._update_realtime_status()
            messagebox.showinfo("Success", "Settings saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def on_closing(self):
        self.save_settings()
        self.root.destroy()
