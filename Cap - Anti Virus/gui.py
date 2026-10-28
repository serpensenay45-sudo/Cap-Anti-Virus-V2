"""
Cap - Anti Virus V2 - Modern GUI
Tüm işlevsellik V1'den korunuyor, sadece arayüz modernleştirildi.
"""
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


# ---------------- Renk Paleti (Modern Dark) ----------------
BG_COLOR = "#0f0f0f"          # Ana arkaplan
SIDEBAR_COLOR = "#161616"     # Kenar çubuğu
SIDEBAR_HOVER = "#1e1e1e"     # Kenar çubuğu hover
SIDEBAR_ACTIVE = "#007acc"    # Aktif sekme (mavi)
CONTENT_COLOR = "#0f0f0f"     # İçerik alanı
CARD_COLOR = "#161616"        # Kart arkaplanı
CARD_HOVER = "#1e1e1e"        # Kart hover
TEXT_PRIMARY = "#e0e0e0"      # Ana yazı
TEXT_SECONDARY = "#a0a0a0"    # İkincil yazı
TEXT_MUTED = "#666666"        # Soluk yazı
ACCENT = "#007acc"            # Ana akcent (mavi)
ACCENT_HOVER = "#0066b3"      # Akcent hover
SUCCESS = "#00d26a"           # Başarılı (yeşil)
SUCCESS_DARK = "#00b854"
DANGER = "#ff4d4d"            # Tehlike (kırmızı)
DANGER_DARK = "#e03e3e"
WARNING = "#ff9f0a"           # Uyarı (turuncu)
BORDER = "#2a2a2a"            # Kenar çizgisi
ENTRY_BG = "#1a1a1a"          # Giriş alanı


STRINGS = {
    "title": "Cap - Anti Virus V2",
    "nav_dashboard": "Dashboard",
    "nav_scan": "Scan",
    "nav_quarantine": "Quarantine",
    "nav_history": "History",
    "nav_settings": "Settings",
    "nav_info": "Info",
    "btn_quick": "Quick Scan",
    "btn_full": "Full System Scan",
    "btn_folder": "Select Folder",
    "btn_usb": "USB / Removable",
    "btn_clear": "Clear",
    "btn_quarantine": "Quarantine",
    "btn_report": "Save Report",
    "btn_refresh": "Refresh",
    "btn_restore": "Restore",
    "btn_delete": "Delete",
    "btn_virustotal": "VirusTotal",
    "btn_stop": "Stop",
    "btn_enable_realtime": "Enable Real-Time",
    "btn_disable_realtime": "Disable Real-Time",
    "lbl_realtime_status_off": "Real-Time: OFF",
    "lbl_realtime_status_on": "Real-Time: ON",
    "stat_scans": "Scans",
    "stat_threats": "Threats",
    "stat_quarantined": "Quarantined",
    "status_ready": "Ready",
    "status_scanning": "Scanning: {}",
    "status_done": "Completed: {} files, {} threats",
    "status_stopped": "Stopped: {} files, {} threats",
    "col_status": "Status",
    "col_path": "File Path",
    "col_hash": "Hash",
    "col_type": "Type",
    "col_reason": "Reason",
    "status_threat": "THREAT",
    "status_clean": "Clean",
    "warn_select": "Please select a file.",
    "confirm_quarantine": "Quarantine this file?\n{}",
    "quarantined": "Quarantined:\n{}",
    "confirm_restore": "Restore this file?\n{}",
    "restored": "Restored:\n{}",
    "confirm_delete": "Permanently delete?\n{}",
    "vt_title": "VirusTotal Result",
    "vt_not_found": "Not found in VirusTotal database.",
    "vt_detected": "{}/{} vendors flagged this file.",
    "vt_clean": "Clean by VirusTotal (0/{}).",
    "vt_error": "Error: {}",
    "vt_no_hash": "Hash could not be calculated.",
    "vt_no_api": "VirusTotal API key not defined.",
    "vt_scanning": "Querying VirusTotal...",
    "setting_theme": "Theme",
    "setting_dark": "Dark",
    "setting_light": "Light",
    "setting_vt_key": "VirusTotal API Key",
    "btn_save_settings": "Save Settings",
    "history_empty": "No scan history.",
    "col_history_date": "Date",
    "col_history_path": "Path",
    "col_history_files": "Files",
    "col_history_threats": "Threats",
    "col_history_type": "Type",
    "btn_export_history": "Export History",
    "report_txt": "Text Report",
    "report_html": "HTML Report",
}


class HoverButton(tk.Button):
    """Hover efekti olan buton."""
    def __init__(self, parent, **kwargs):
        self.default_bg = kwargs.pop("bg", SIDEBAR_COLOR)
        self.hover_bg = kwargs.pop("hover_bg", SIDEBAR_HOVER)
        self.default_fg = kwargs.pop("fg", TEXT_PRIMARY)
        self.hover_fg = kwargs.pop("hover_fg", TEXT_PRIMARY)
        self.active_bg = kwargs.pop("active_bg", SIDEBAR_ACTIVE)
        self.active_fg = kwargs.pop("active_fg", "#ffffff")
        super().__init__(parent, **kwargs)
        self.configure(
            bg=self.default_bg,
            fg=self.default_fg,
            activebackground=self.active_bg,
            activeforeground=self.active_fg,
            relief=tk.FLAT,
            bd=0,
            highlightthickness=0,
            font=("Segoe UI", 10),
            padx=12,
            pady=10,
            cursor="hand2",
        )
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)

    def _on_enter(self, _):
        if self.cget("bg") != self.active_bg:
            self.configure(bg=self.hover_bg)

    def _on_leave(self, _):
        if self.cget("bg") != self.active_bg:
            self.configure(bg=self.default_bg)

    def _on_click(self, _):
        pass

    def set_active(self, active: bool):
        if active:
            self.configure(bg=self.active_bg, fg=self.active_fg)
        else:
            self.configure(bg=self.default_bg, fg=self.default_fg)


class IconLabel(tk.Label):
    """Emoji / simge etiketi."""
    def __init__(self, parent, text="", **kwargs):
        super().__init__(parent, text=text, **kwargs)
        self.configure(bg=kwargs.get("bg", CARD_COLOR), fg=kwargs.get("fg", ACCENT),
                       font=("Segoe UI Emoji", 14))


class CapAntiVirusGUI:
    def __init__(self, root, config=None, scanner=None, quarantine=None,
                 updater=None, realtime=None, scheduler=None, logger=None):
        self.root = root
        self.config = config or {}
        self.t = STRINGS
        self.logger = logger or setup_logger()

        self.root.title(self.t["title"])
        width = self.config.get("gui", {}).get("window_width", 1200)
        height = self.config.get("gui", {}).get("window_height", 760)
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(1000, 650)
        self.root.configure(bg=BG_COLOR)

        # Stil
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        self._configure_ttk_styles()

        # Bileşenler
        self.scanner = scanner or Scanner(config=self.config)
        self.quarantine = quarantine or QuarantineManager(config=self.config)
        self.updater = updater if updater else Updater()
        self.realtime = realtime
        self.scheduler = scheduler

        # Durum
        self.scanning = False
        self.scan_results = []
        self.scan_history = self.load_history()
        self.dark_mode = self.config.get("gui", {}).get("dark_mode", True)
        self.current_view = None

        # UI referansları
        self.nav_buttons = {}
        self.content_frames = {}
        self.tree = None
        self.history_tree = None
        self.quar_list = None
        self.status_var = None
        self.progress = None
        self.progress_var = None
        self.current_file_var = None
        self.stats_labels = {}
        self.realtime_status_var = None
        self.realtime_btn = None
        self.scan_animation_label = None
        self._anim_running = False

        self._build_layout()
        self._switch_content("dashboard", self._dashboard_frame)
        self.refresh_stats()
        self.refresh_quarantine()
        self.refresh_history()

        # Gerçek zamanlı koruma
        if self.realtime:
            self.realtime.start()
            self._update_realtime_status()

    # ---------------- Stil Yapılandırması ----------------
    def _configure_ttk_styles(self):
        self.style.configure("TFrame", background=CONTENT_COLOR)
        self.style.configure("TLabel", background=CONTENT_COLOR, foreground=TEXT_PRIMARY)
        self.style.configure("TEntry", fieldbackground=ENTRY_BG, foreground=TEXT_PRIMARY,
                             bordercolor=BORDER)
        self.style.configure("TProgressbar", troughcolor=ENTRY_BG, background=ACCENT,
                             bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
        self.style.configure("Treeview", background=CARD_COLOR, foreground=TEXT_PRIMARY,
                             fieldbackground=CARD_COLOR, bordercolor=BORDER, borderwidth=0)
        self.style.configure("Treeview.Heading", background=SIDEBAR_COLOR,
                             foreground=TEXT_SECONDARY, bordercolor=BORDER, borderwidth=0,
                             font=("Segoe UI", 9, "bold"))
        self.style.map("Treeview", background=[("selected", ACCENT)],
                       foreground=[("selected", "#ffffff")])

    # ---------------- Ana Düzen ----------------
    def _build_layout(self):
        # Ana container
        self.main_container = tk.Frame(self.root, bg=BG_COLOR)
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        self.sidebar = tk.Frame(self.main_container, bg=SIDEBAR_COLOR, width=220)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=0, pady=0)
        self.sidebar.pack_propagate(False)

        # Uygulama başlığı (sidebar üstü)
        header_frame = tk.Frame(self.sidebar, bg=SIDEBAR_COLOR)
        header_frame.pack(fill=tk.X, padx=16, pady=(20, 10))
        tk.Label(header_frame, text="🛡️", bg=SIDEBAR_COLOR, fg=ACCENT,
                 font=("Segoe UI Emoji", 20)).pack(anchor=tk.W)
        tk.Label(header_frame, text="Cap - Anti Virus", bg=SIDEBAR_COLOR, fg=TEXT_PRIMARY,
                 font=("Segoe UI", 13, "bold")).pack(anchor=tk.W, pady=(4, 0))
        tk.Label(header_frame, text="V2", bg=SIDEBAR_COLOR, fg=TEXT_SECONDARY,
                 font=("Segoe UI", 9)).pack(anchor=tk.W)

        # Ayırıcı
        tk.Frame(self.sidebar, bg=BORDER, height=1).pack(fill=tk.X, padx=16, pady=12)

        # Navigasyon butonları
        nav_items = [
            ("dashboard", "📊", self.t["nav_dashboard"], self._show_dashboard_view),
            ("scan", "🔍", self.t["nav_scan"], self._show_scan_view),
            ("quarantine", "🦠", self.t["nav_quarantine"], self._show_quarantine_view),
            ("history", "📜", self.t["nav_history"], self._show_history_view),
            ("settings", "⚙️", self.t["nav_settings"], self._show_settings_view),
            ("info", "ℹ️", self.t["nav_info"], self._show_info_view),
        ]

        self.nav_frame = tk.Frame(self.sidebar, bg=SIDEBAR_COLOR)
        self.nav_frame.pack(fill=tk.X, padx=8, pady=4)

        for key, icon, text, command in nav_items:
            btn = HoverButton(self.nav_frame, text=f"  {icon}  {text}",
                              command=lambda k=key, c=command: self._navigate(k, c),
                              anchor="w", justify=tk.LEFT)
            btn.pack(fill=tk.X, pady=2, padx=4)
            self.nav_buttons[key] = btn

        # Alt kısım: Gerçek zamanlı durum (sidebar altı)
        self._build_sidebar_footer()

        # İçerik alanı
        self.content = tk.Frame(self.main_container, bg=CONTENT_COLOR)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Tüm görünümleri oluştur
        self._build_dashboard_view()
        self._build_scan_view()
        self._build_quarantine_view()
        self._build_history_view()
        self._build_settings_view()
        self._build_info_view()

        # Alt durum çubuğu
        self._build_status_bar()

    def _build_sidebar_footer(self):
        footer = tk.Frame(self.sidebar, bg=SIDEBAR_COLOR)
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=16, pady=16)

        self.realtime_status_var = tk.StringVar(value=self.t["lbl_realtime_status_off"])
        self.realtime_status_lbl = tk.Label(footer, textvariable=self.realtime_status_var,
                                            bg=SIDEBAR_COLOR, fg=DANGER if self.dark_mode else DANGER,
                                            font=("Segoe UI", 9, "bold"))
        self.realtime_status_lbl.pack(anchor=tk.W, pady=(0, 8))

        self.realtime_btn = HoverButton(footer, text=self.t["btn_enable_realtime"],
                                        command=self.toggle_realtime, anchor="w", justify=tk.LEFT,
                                        bg=ENTRY_BG, fg=TEXT_PRIMARY, hover_bg=CARD_HOVER,
                                        active_bg=ACCENT, active_fg="#ffffff",
                                        font=("Segoe UI", 9), padx=8, pady=6)
        self.realtime_btn.pack(fill=tk.X)

        # Versiyon
        tk.Label(footer, text="v2.0.0", bg=SIDEBAR_COLOR, fg=TEXT_MUTED,
                 font=("Segoe UI", 8)).pack(anchor=tk.E, pady=(12, 0))

    def _build_status_bar(self):
        bar = tk.Frame(self.content, bg=SIDEBAR_COLOR, height=34)
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        bar.pack_propagate(False)

        self.status_var = tk.StringVar(value=self.t["status_ready"])
        self.status_lbl = tk.Label(bar, textvariable=self.status_var,
                                   bg=SIDEBAR_COLOR, fg=TEXT_SECONDARY,
                                   font=("Segoe UI", 9), anchor=tk.W)
        self.status_lbl.pack(side=tk.LEFT, padx=12, pady=6)

        # Sağ taraf: tarama ilerleme
        right = tk.Frame(bar, bg=SIDEBAR_COLOR)
        right.pack(side=tk.RIGHT, padx=12, pady=4)

        self.current_file_var = tk.StringVar(value="")
        self.current_file_lbl = tk.Label(right, textvariable=self.current_file_var,
                                         bg=SIDEBAR_COLOR, fg=TEXT_MUTED,
                                         font=("Segoe UI", 8))
        self.current_file_lbl.pack(side=tk.RIGHT, padx=(8, 0))

        self.progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(right, variable=self.progress_var,
                                        maximum=100, length=180, mode="determinate")
        self.progress.pack(side=tk.RIGHT, padx=(0, 8))

    # ---------------- Görünüş Yönetimi ----------------
    def _navigate(self, key, command):
        # Nav butonlarını sıfırla
        for k, btn in self.nav_buttons.items():
            btn.set_active(k == key)
        self.current_view = key
        command()

    def _show_view(self, view_name):
        self._navigate(view_name, lambda: None)


    def _hide_all_views(self):
        for frame in self.content_frames.values():
            frame.pack_forget()
        for child in self.content.winfo_children():
            if isinstance(child, tk.Frame) and child.winfo_height() > 40:
                child.pack_forget()

    def _switch_content(self, frame_key, frame):
        self._hide_all_views()
        self.content_frames[frame_key] = frame
        frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        self.root.update_idletasks()

    # ---------------- Dashboard ----------------
    def _build_dashboard_view(self):
        self._dashboard_frame = tk.Frame(self.content, bg=CONTENT_COLOR)
        frame = self._dashboard_frame

        # Başlık
        title = tk.Label(frame, text=self.t["nav_dashboard"], bg=CONTENT_COLOR,
                         fg=TEXT_PRIMARY, font=("Segoe UI", 18, "bold"))
        title.pack(anchor=tk.W, padx=24, pady=(20, 4))
        subtitle = tk.Label(frame, text="System security overview",
                            bg=CONTENT_COLOR, fg=TEXT_SECONDARY,
                            font=("Segoe UI", 10))
        subtitle.pack(anchor=tk.W, padx=24, pady=(0, 16))

        # Stat kartları
        cards_frame = tk.Frame(frame, bg=CONTENT_COLOR)
        cards_frame.pack(fill=tk.X, padx=24, pady=8)

        stat_defs = [
            ("total_scans", self.t["stat_scans"], "0", "📊", ACCENT),
            ("total_threats", self.t["stat_threats"], "0", "🦠", DANGER),
            ("quarantined", self.t["stat_quarantined"], "0", "🗄️", WARNING),
        ]

        self.stats_cards = {}
        for key, label, default, icon, color in stat_defs:
            card = tk.Frame(cards_frame, bg=CARD_COLOR, highlightbackground=BORDER,
                            highlightthickness=1, bd=0)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

            inner = tk.Frame(card, bg=CARD_COLOR)
            inner.pack(fill=tk.BOTH, padx=14, pady=14)

            top = tk.Frame(inner, bg=CARD_COLOR)
            top.pack(fill=tk.X)
            tk.Label(top, text=icon, bg=CARD_COLOR, fg=color,
                     font=("Segoe UI Emoji", 18)).pack(side=tk.LEFT)
            tk.Label(top, text=label, bg=CARD_COLOR, fg=TEXT_SECONDARY,
                     font=("Segoe UI", 9)).pack(side=tk.RIGHT)

            val = tk.Label(inner, text=default, bg=CARD_COLOR, fg=TEXT_PRIMARY,
                           font=("Segoe UI", 24, "bold"))
            val.pack(anchor=tk.W, pady=(6, 0))
            self.stats_cards[key] = val

        # Hızlı eylemler
        actions_frame = tk.Frame(frame, bg=CONTENT_COLOR)
        actions_frame.pack(fill=tk.X, padx=24, pady=(24, 8))

        tk.Label(actions_frame, text="Quick Actions", bg=CONTENT_COLOR,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 8))

        btns = [
            (self.t["btn_quick"], ACCENT, lambda: self.quick_scan()),
            (self.t["btn_full"], ACCENT, lambda: self.full_scan()),
            (self.t["btn_folder"], ACCENT, self.scan_folder),
            (self.t["btn_usb"], ACCENT, self.usb_scan),
            (self.t["btn_quarantine"], WARNING, lambda: self._show_quarantine_view()),
        ]

        btn_row = tk.Frame(actions_frame, bg=CONTENT_COLOR)
        btn_row.pack(fill=tk.X)
        for text, color, cmd in btns:
            btn = HoverButton(btn_row, text=text, command=cmd, bg=ENTRY_BG,
                              fg=TEXT_PRIMARY, hover_bg=CARD_HOVER, active_bg=color,
                              active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                              padx=14, pady=8)
            btn.pack(side=tk.LEFT, padx=4, pady=4)

        # Gerçek zamanlı durum kartı
        rt_frame = tk.Frame(frame, bg=CARD_COLOR, highlightbackground=BORDER,
                            highlightthickness=1, bd=0)
        rt_frame.pack(fill=tk.X, padx=24, pady=(20, 8))
        rt_inner = tk.Frame(rt_frame, bg=CARD_COLOR)
        rt_inner.pack(fill=tk.X, padx=14, pady=14)

        tk.Label(rt_inner, text="Real-Time Protection", bg=CARD_COLOR,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 11, "bold")).pack(anchor=tk.W)
        self.dash_rt_var = tk.StringVar(value=self.t["lbl_realtime_status_off"])
        self.dash_rt_lbl = tk.Label(rt_inner, textvariable=self.dash_rt_var,
                                    bg=CARD_COLOR, fg=DANGER,
                                    font=("Segoe UI", 10, "bold"))
        self.dash_rt_lbl.pack(anchor=tk.W, pady=(2, 0))

        self.dash_rt_btn = HoverButton(rt_inner, text=self.t["btn_enable_realtime"],
                                       command=self.toggle_realtime,
                                       bg=ENTRY_BG, fg=TEXT_PRIMARY, hover_bg=CARD_HOVER,
                                       active_bg=SUCCESS, active_fg="#ffffff",
                                       font=("Segoe UI", 9), padx=10, pady=4)
        self.dash_rt_btn.pack(anchor=tk.W, pady=(8, 0))

        # Not
        tk.Label(frame, text="Scan history and recent activity appear in the History tab.",
                 bg=CONTENT_COLOR, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(
            anchor=tk.W, padx=24, pady=(24, 0))

    def _show_dashboard_view(self):
        self._switch_content("dashboard", self._dashboard_frame)
        self._update_realtime_status()
        self.refresh_stats()
        self._update_realtime_status()
        self.refresh_stats()

    # ---------------- Scan ----------------
    def _build_scan_view(self):
        self._scan_frame = tk.Frame(self.content, bg=CONTENT_COLOR)
        frame = self._scan_frame

        # Başlık
        title = tk.Label(frame, text=self.t["nav_scan"], bg=CONTENT_COLOR,
                         fg=TEXT_PRIMARY, font=("Segoe UI", 18, "bold"))
        title.pack(anchor=tk.W, padx=24, pady=(20, 4))

        # Tarama butonları
        btn_frame = tk.Frame(frame, bg=CONTENT_COLOR)
        btn_frame.pack(fill=tk.X, padx=24, pady=12)

        scan_btns = [
            (self.t["btn_quick"], lambda: self.quick_scan()),
            (self.t["btn_full"], lambda: self.full_scan()),
            (self.t["btn_folder"], self.scan_folder),
            (self.t["btn_usb"], self.usb_scan),
            (self.t["btn_clear"], self.clear_results),
            (self.t["btn_stop"], self.stop_scan),
        ]

        colors = [ACCENT, ACCENT, ACCENT, ACCENT, WARNING, DANGER]
        for (text, cmd), color in zip(scan_btns, colors):
            btn = HoverButton(btn_frame, text=text, command=cmd, bg=ENTRY_BG,
                              fg=TEXT_PRIMARY, hover_bg=CARD_HOVER, active_bg=color,
                              active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                              padx=12, pady=7)
            btn.pack(side=tk.LEFT, padx=4, pady=4)
            if text == self.t["btn_stop"]:
                btn.configure(state=tk.DISABLED, fg=TEXT_MUTED)
                self.btn_stop_widget = btn

        # İlerleme ve mevcut dosya
        prog_frame = tk.Frame(frame, bg=CONTENT_COLOR)
        prog_frame.pack(fill=tk.X, padx=24, pady=(4, 8))

        self.scan_progress_var = tk.DoubleVar(value=0)
        self.scan_progress = ttk.Progressbar(prog_frame, variable=self.scan_progress_var,
                                             maximum=100, length=300, mode="determinate")
        self.scan_progress.pack(fill=tk.X, pady=(0, 4))

        self.current_file_var2 = tk.StringVar(value="Idle")
        self.current_file_lbl2 = tk.Label(prog_frame, textvariable=self.current_file_var2,
                                          bg=CONTENT_COLOR, fg=TEXT_SECONDARY,
                                          font=("Segoe UI", 9))
        self.current_file_lbl2.pack(anchor=tk.W)

        # Sonuç tablosu
        table_frame = tk.Frame(frame, bg=CARD_COLOR, highlightbackground=BORDER,
                               highlightthickness=1, bd=0)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 8))

        cols = ("status", "path", "hash", "type", "reason")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")
        widths = {"status": 90, "path": 320, "hash": 120, "type": 90, "reason": 260}
        for c in cols:
            self.tree.heading(c, text=self.t[f"col_{c}"])
            self.tree.column(c, width=widths[c], anchor=tk.W)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=1, pady=1)

        self.tree.tag_configure("threat", foreground=DANGER)
        self.tree.tag_configure("clean", foreground=SUCCESS)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Alt eylemler
        act_frame = tk.Frame(frame, bg=CONTENT_COLOR)
        act_frame.pack(fill=tk.X, padx=24, pady=(0, 20))

        self.btn_quarantine_scan = HoverButton(act_frame, text=self.t["btn_quarantine"],
                                               command=self.quarantine_selected,
                                               bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                               hover_bg=CARD_HOVER, active_bg=WARNING,
                                               active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                                               padx=12, pady=6)
        self.btn_quarantine_scan.pack(side=tk.LEFT, padx=4)

        self.btn_report_scan = HoverButton(act_frame, text=self.t["btn_report"],
                                           command=self.save_report,
                                           bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                           hover_bg=CARD_HOVER, active_bg=ACCENT,
                                           active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                                           padx=12, pady=6)
        self.btn_report_scan.pack(side=tk.LEFT, padx=4)

        self.btn_vt_scan = HoverButton(act_frame, text=self.t["btn_virustotal"],
                                       command=self.virustotal_selected,
                                       bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                       hover_bg=CARD_HOVER, active_bg=ACCENT,
                                       active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                                       padx=12, pady=6)
        self.btn_vt_scan.pack(side=tk.LEFT, padx=4)

    def _show_scan_view(self):
        self._switch_content("scan", self._scan_frame)

    # ---------------- Quarantine ----------------
    def _build_quarantine_view(self):
        self._quarantine_frame = tk.Frame(self.content, bg=CONTENT_COLOR)
        frame = self._quarantine_frame

        title = tk.Label(frame, text=self.t["nav_quarantine"], bg=CONTENT_COLOR,
                         fg=TEXT_PRIMARY, font=("Segoe UI", 18, "bold"))
        title.pack(anchor=tk.W, padx=24, pady=(20, 4))

        # Liste
        list_frame = tk.Frame(frame, bg=CARD_COLOR, highlightbackground=BORDER,
                              highlightthickness=1, bd=0)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=8)

        self.quar_list = tk.Listbox(list_frame, bg=CARD_COLOR, fg=TEXT_PRIMARY,
                                    selectbackground=ACCENT, selectforeground="#ffffff",
                                    font=("Consolas", 10), borderwidth=0,
                                    highlightthickness=0, activestyle="none")
        self.quar_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=1, pady=1)

        q_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL,
                                 command=self.quar_list.yview)
        self.quar_list.configure(yscrollcommand=q_scroll.set)
        q_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Butonlar
        btn_frame = tk.Frame(frame, bg=CONTENT_COLOR)
        btn_frame.pack(fill=tk.X, padx=24, pady=(8, 20))

        self.btn_q_refresh = HoverButton(btn_frame, text=self.t["btn_refresh"],
                                         command=self.refresh_quarantine,
                                         bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                         hover_bg=CARD_HOVER, active_bg=ACCENT,
                                         active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                                         padx=12, pady=6)
        self.btn_q_refresh.pack(side=tk.LEFT, padx=4)

        self.btn_q_restore = HoverButton(btn_frame, text=self.t["btn_restore"],
                                         command=self.restore_selected,
                                         bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                         hover_bg=CARD_HOVER, active_bg=SUCCESS,
                                         active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                                         padx=12, pady=6)
        self.btn_q_restore.pack(side=tk.LEFT, padx=4)

        self.btn_q_delete = HoverButton(btn_frame, text=self.t["btn_delete"],
                                        command=self.delete_selected,
                                        bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                        hover_bg=CARD_HOVER, active_bg=DANGER,
                                        active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                                        padx=12, pady=6)
        self.btn_q_delete.pack(side=tk.LEFT, padx=4)

    def _show_quarantine_view(self):
        self._switch_content("quarantine", self._quarantine_frame)
        self.refresh_quarantine()

    # ---------------- History ----------------
    def _build_history_view(self):
        self._history_frame = tk.Frame(self.content, bg=CONTENT_COLOR)
        frame = self._history_frame

        title = tk.Label(frame, text=self.t["nav_history"], bg=CONTENT_COLOR,
                         fg=TEXT_PRIMARY, font=("Segoe UI", 18, "bold"))
        title.pack(anchor=tk.W, padx=24, pady=(20, 4))

        # Üst araç çubuğu
        top = tk.Frame(frame, bg=CONTENT_COLOR)
        top.pack(fill=tk.X, padx=24, pady=8)
        self.btn_hist_export = HoverButton(top, text=self.t["btn_export_history"],
                                           command=self.export_history,
                                           bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                           hover_bg=CARD_HOVER, active_bg=ACCENT,
                                           active_fg="#ffffff", font=("Segoe UI", 9, "bold"),
                                           padx=12, pady=6)
        self.btn_hist_export.pack(side=tk.LEFT)

        # Tablo
        table_frame = tk.Frame(frame, bg=CARD_COLOR, highlightbackground=BORDER,
                               highlightthickness=1, bd=0)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=8)

        hcols = ("date", "path", "files", "threats", "type")
        self.history_tree = ttk.Treeview(table_frame, columns=hcols, show="headings")
        widths = {"date": 160, "path": 360, "files": 70, "threats": 80, "type": 120}
        for c in hcols:
            self.history_tree.heading(c, text=self.t[f"col_history_{c}"])
            self.history_tree.column(c, width=widths[c], anchor=tk.W)
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=1, pady=1)

        h_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL,
                                 command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=h_scroll.set)
        h_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        if not self.scan_history:
            self.history_tree.insert("", tk.END, values=(
                self.t["history_empty"], "", "", "", ""
            ))

    def _show_history_view(self):
        self._switch_content("history", self._history_frame)
        self.refresh_history()

    # ---------------- Settings ----------------
    def _build_settings_view(self):
        self._settings_frame = tk.Frame(self.content, bg=CONTENT_COLOR)
        frame = self._settings_frame

        title = tk.Label(frame, text=self.t["nav_settings"], bg=CONTENT_COLOR,
                         fg=TEXT_PRIMARY, font=("Segoe UI", 18, "bold"))
        title.pack(anchor=tk.W, padx=24, pady=(20, 4))

        container = tk.Frame(frame, bg=CARD_COLOR, highlightbackground=BORDER,
                             highlightthickness=1, bd=0)
        container.pack(fill=tk.BOTH, expand=True, padx=24, pady=8)
        inner = tk.Frame(container, bg=CARD_COLOR)
        inner.pack(fill=tk.BOTH, padx=24, pady=20, expand=True)

        # Tema
        theme_row = tk.Frame(inner, bg=CARD_COLOR)
        theme_row.pack(fill=tk.X, pady=10)
        tk.Label(theme_row, text=self.t["setting_theme"], bg=CARD_COLOR,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 12))
        self.btn_theme_sett = HoverButton(theme_row, text="", command=self.toggle_theme,
                                          bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                          hover_bg=CARD_HOVER, active_bg=ACCENT,
                                          active_fg="#ffffff", font=("Segoe UI", 9),
                                          padx=10, pady=5)
        self.btn_theme_sett.pack(side=tk.LEFT)
        self._update_theme_button_text()

        # VirusTotal API anahtarı
        vt_row = tk.Frame(inner, bg=CARD_COLOR)
        vt_row.pack(fill=tk.X, pady=10)
        tk.Label(vt_row, text=self.t["setting_vt_key"], bg=CARD_COLOR,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 12))
        self.vt_key_entry = tk.Entry(vt_row, bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                     insertbackground=TEXT_PRIMARY, relief=tk.FLAT,
                                     bd=0, highlightthickness=1, highlightbackground=BORDER,
                                     font=("Segoe UI", 9), width=45)
        self.vt_key_entry.pack(side=tk.LEFT, padx=(0, 6), fill=tk.X, expand=True,
                               ipady=4)
        current_key = self.config.get("vt_api_key", "")
        if current_key:
            self.vt_key_entry.insert(0, current_key)

        # Gerçek zamanlı koruma
        rt_row = tk.Frame(inner, bg=CARD_COLOR)
        rt_row.pack(fill=tk.X, pady=10)
        tk.Label(rt_row, text="Real-Time Protection", bg=CARD_COLOR,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 12))
        self.realtime_var = tk.BooleanVar(value=self.config.get("realtime_protection", {}).get("enabled", False))
        cb = tk.Checkbutton(rt_row, text="Enabled", variable=self.realtime_var,
                            bg=CARD_COLOR, fg=TEXT_PRIMARY, selectcolor=ENTRY_BG,
                            activebackground=CARD_COLOR, activeforeground=TEXT_PRIMARY,
                            font=("Segoe UI", 9), bd=0, highlightthickness=0)
        cb.pack(side=tk.LEFT)

        self.watchdog_var = tk.BooleanVar(value=self.config.get("realtime_protection", {}).get("use_watchdog", True))
        cb_wd = tk.Checkbutton(rt_row, text="Use Watchdog (real events)", variable=self.watchdog_var,
                               bg=CARD_COLOR, fg=TEXT_PRIMARY, selectcolor=ENTRY_BG,
                               activebackground=CARD_COLOR, activeforeground=TEXT_PRIMARY,
                               font=("Segoe UI", 9), bd=0, highlightthickness=0)
        cb_wd.pack(side=tk.LEFT, padx=(12, 0))

        # Zamanlayıcı
        sched_row = tk.Frame(inner, bg=CARD_COLOR)
        sched_row.pack(fill=tk.X, pady=10)
        tk.Label(sched_row, text="Scheduled Scan", bg=CARD_COLOR,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 12))
        self.sched_var = tk.BooleanVar(value=self.config.get("scheduler", {}).get("enabled", False))
        cb2 = tk.Checkbutton(sched_row, text="Enabled", variable=self.sched_var,
                             bg=CARD_COLOR, fg=TEXT_PRIMARY, selectcolor=ENTRY_BG,
                             activebackground=CARD_COLOR, activeforeground=TEXT_PRIMARY,
                             font=("Segoe UI", 9), bd=0, highlightthickness=0)
        cb2.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(sched_row, text="Hour:", bg=CARD_COLOR, fg=TEXT_SECONDARY,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.sched_hour = tk.Entry(sched_row, bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                   insertbackground=TEXT_PRIMARY, relief=tk.FLAT, bd=0,
                                   highlightthickness=1, highlightbackground=BORDER,
                                   font=("Segoe UI", 9), width=5)
        self.sched_hour.insert(0, str(self.config.get("scheduler", {}).get("hour", 2)))
        self.sched_hour.pack(side=tk.LEFT, padx=(2, 8), ipady=2)

        tk.Label(sched_row, text="Minute:", bg=CARD_COLOR, fg=TEXT_SECONDARY,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.sched_min = tk.Entry(sched_row, bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                  insertbackground=TEXT_PRIMARY, relief=tk.FLAT, bd=0,
                                  highlightthickness=1, highlightbackground=BORDER,
                                  font=("Segoe UI", 9), width=5)
        self.sched_min.insert(0, str(self.config.get("scheduler", {}).get("minute", 0)))
        self.sched_min.pack(side=tk.LEFT, padx=(2, 0), ipady=2)

        # Kaydet butonu
        save_frame = tk.Frame(inner, bg=CARD_COLOR)
        save_frame.pack(fill=tk.X, pady=(20, 0))
        self.btn_save_sett = HoverButton(save_frame, text=self.t["btn_save_settings"],
                                         command=self.save_settings,
                                         bg=ACCENT, fg="#ffffff",
                                         hover_bg=ACCENT_HOVER, active_bg=ACCENT,
                                         active_fg="#ffffff", font=("Segoe UI", 10, "bold"),
                                         padx=20, pady=8)
        self.btn_save_sett.pack(side=tk.RIGHT)

        tk.Label(inner, text="Some changes require a restart to take effect.",
                 bg=CARD_COLOR, fg=TEXT_MUTED, font=("Segoe UI", 8)).pack(
            anchor=tk.W, pady=(10, 0))

    def _show_settings_view(self):
        self._switch_content("settings", self._settings_frame)

    def _update_theme_button_text(self):
        self.btn_theme_sett.configure(
            text=self.t["setting_dark"] if self.dark_mode else self.t["setting_light"])

    # ---------------- Info ----------------
    def _build_info_view(self):
        self._info_frame = tk.Frame(self.content, bg=CONTENT_COLOR)
        frame = self._info_frame

        title = tk.Label(frame, text=self.t["nav_info"], bg=CONTENT_COLOR,
                         fg=TEXT_PRIMARY, font=("Segoe UI", 18, "bold"))
        title.pack(anchor=tk.W, padx=24, pady=(20, 4))

        text_frame = tk.Frame(frame, bg=CARD_COLOR, highlightbackground=BORDER,
                              highlightthickness=1, bd=0)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=8)

        self.info_text = tk.Text(text_frame, wrap=tk.WORD, padx=14, pady=14,
                                 bg=CARD_COLOR, fg=TEXT_PRIMARY,
                                 insertbackground=ACCENT, relief=tk.FLAT, bd=0,
                                 highlightthickness=0, font=("Segoe UI", 10))
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        self.info_text.insert(tk.END, INFO_TEXT)
        self.info_text.config(state=tk.DISABLED)

    def _show_info_view(self):
        self._switch_content("info", self._info_frame)

    # ---------------- Tema ----------------
    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.config.setdefault("gui", {})["dark_mode"] = self.dark_mode
        self._update_theme_button_text()
        # Renk paletini güncelle (kullanıcıya bildirim)
        messagebox.showinfo("Theme", "Theme switched. Restart the app for full effect.")

    # ---------------- İstatistikler ----------------
    def refresh_stats(self):
        total_scans = len(self.scan_history)
        total_threats = sum(h.get("threats", 0) for h in self.scan_history)
        quarantined = len(self.quarantine.list_quarantined())

        self.stats_cards["total_scans"].config(text=str(total_scans))
        self.stats_cards["total_threats"].config(text=str(total_threats))
        self.stats_cards["quarantined"].config(text=str(quarantined))

    def _update_realtime_status(self):
        if not self.realtime:
            if self.realtime_status_var:
                self.realtime_status_var.set("Real-Time: N/A")
            if self.realtime_btn:
                self.realtime_btn.configure(text="N/A", state=tk.DISABLED)
            if hasattr(self, "dash_rt_var"):
                self.dash_rt_var.set("Real-Time: N/A")
                self.dash_rt_lbl.configure(fg=TEXT_MUTED)
            if hasattr(self, "dash_rt_btn"):
                self.dash_rt_btn.configure(text="N/A", state=tk.DISABLED)
            return

        enabled = self.config.get("realtime_protection", {}).get("enabled", False)
        if enabled:
            status = self.t["lbl_realtime_status_on"]
            color = SUCCESS
            btn_text = self.t["btn_disable_realtime"]
        else:
            status = self.t["lbl_realtime_status_off"]
            color = DANGER
            btn_text = self.t["btn_enable_realtime"]

        if self.realtime_status_var:
            self.realtime_status_var.set(status)
            self.realtime_status_lbl.configure(fg=color)
        if self.realtime_btn:
            self.realtime_btn.configure(text=btn_text)
        if hasattr(self, "dash_rt_var"):
            self.dash_rt_var.set(status)
            self.dash_rt_lbl.configure(fg=color)
        if hasattr(self, "dash_rt_btn"):
            self.dash_rt_btn.configure(text=btn_text)

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

    # ---------------- Geçmiş ----------------
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
                self.t["history_empty"], "", "", "", ""
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

    # ---------------- Tarama İşlemleri ----------------
    def _set_scan_buttons(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        fg = TEXT_PRIMARY if enabled else TEXT_MUTED
        for btn in [getattr(self, "btn_quick", None),
                    getattr(self, "btn_full", None),
                    getattr(self, "btn_folder", None),
                    getattr(self, "btn_usb", None),
                    getattr(self, "btn_clear", None),
                    getattr(self, "btn_quarantine_scan", None),
                    getattr(self, "btn_report_scan", None),
                    getattr(self, "btn_vt_scan", None)]:
            if btn:
                btn.configure(state=state)
                if not enabled:
                    btn.configure(fg=TEXT_MUTED)
                else:
                    btn.configure(fg=TEXT_PRIMARY)

        stop_btn = getattr(self, "btn_stop_widget", None)
        if stop_btn:
            stop_btn.configure(state=tk.DISABLED if enabled else tk.NORMAL,
                               fg=TEXT_MUTED if enabled else TEXT_PRIMARY)

    def quick_scan(self):
        self._start_scan(os.path.join(os.path.expanduser("~"), "Documents"), "quick")

    def full_scan(self):
        self._start_scan(os.path.expanduser("~"), "full")

    def scan_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self._start_scan(folder, "custom")

    def usb_scan(self):
        self._start_scan_usb("usb")

    def _start_scan(self, path, scan_type):
        if self.scanning:
            return
        self.scanning = True
        self.scan_results = []
        self.tree.delete(*self.tree.get_children())
        self.status_var.set(self.t["status_scanning"].format(path))
        self.current_file_var.set("Scanning...")
        self.current_file_var2.set("Scanning...")
        self.scan_progress_var.set(0)
        self.progress_var.set(0)
        self._set_scan_buttons(False)

        thread = threading.Thread(target=self._run_scan, args=(path, scan_type), daemon=True)
        thread.start()

    def _start_scan_usb(self, scan_type):
        if self.scanning:
            return
        self.scanning = True
        self.scan_results = []
        self.tree.delete(*self.tree.get_children())
        self.status_var.set("Scanning removable drives...")
        self.current_file_var.set("Scanning USB...")
        self.current_file_var2.set("Scanning USB...")
        self.scan_progress_var.set(0)
        self.progress_var.set(0)
        self._set_scan_buttons(False)

        thread = threading.Thread(target=self._run_usb_scan, args=(scan_type,), daemon=True)
        thread.start()

    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.scanner.request_stop()
            self.status_var.set(self.t["status_ready"])
            self.current_file_var.set("Stopped")
            self.current_file_var2.set("Stopped")

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

    def _insert_result(self, result):
        if result.get("threat_type") == "cancelled":
            return
        if result["threat"]:
            status = self.t["status_threat"]
            tag = "threat"
        else:
            status = self.t["status_clean"]
            tag = "clean"
        heur = "; ".join(result.get("heuristic", []))
        self.tree.insert(
            "", tk.END,
            values=(status, result["path"], result["hash"] or "-",
                    result.get("threat_type", "-"), heur),
            tags=(tag,)
        )

    def _scan_finished(self, results, path, scan_type, was_stopped):
        self.scanning = False
        self.scan_progress_var.set(100)
        self.progress_var.set(100)
        self._set_scan_buttons(True)
        self.current_file_var.set("Idle")
        self.current_file_var2.set("Idle")

        threat_count = sum(1 for r in results if r["threat"])
        if was_stopped:
            self.status_var.set(self.t["status_stopped"].format(len(results), threat_count))
        else:
            self.status_var.set(self.t["status_done"].format(len(results), threat_count))

        self.logger.info(f"Scan completed: {path}, {len(results)} files, {threat_count} threats")
        self.add_history_entry(path, len(results), threat_count, scan_type)

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())

    def quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Warning", self.t["warn_select"])
            return
        item = self.tree.item(sel[0])
        path = item["values"][1]
        if messagebox.askyesno("Confirm", self.t["confirm_quarantine"].format(path)):
            dest = self.quarantine.quarantine_file(path)
            if dest:
                messagebox.showinfo("Success", self.t["quarantined"].format(dest))
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
<style>body{{font-family:'Segoe UI';background:#1e1e1e;color:#e0e0e0;}}table{{border-collapse:collapse;width:100%;}}
th,td{{border:1px solid #444;padding:6px;text-align:left;}}th{{background:#007acc;color:#fff;}}
tr:nth-child(even){{background:#252526;}}</style></head><body>
<h1>Cap - Anti Virus V2 - Scan Report</h1>
<table><tr><th>Status</th><th>Path</th><th>Hash</th><th>Type</th><th>Reason</th></tr>{rows}</table></body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def virustotal_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Warning", self.t["warn_select"])
            return
        if not self.updater.vt_api_key:
            messagebox.showerror("Error", self.t["vt_no_api"])
            return

        item = self.tree.item(sel[0])
        path = item["values"][1]
        file_hash = item["values"][2]

        if file_hash == "-" or not file_hash:
            messagebox.showerror("Error", self.t["vt_no_hash"])
            return

        self.status_var.set(self.t["vt_scanning"])
        self.scan_progress_var.set(50)
        self.progress_var.set(50)

        thread = threading.Thread(target=self._run_vt_check, args=(path, file_hash), daemon=True)
        thread.start()

    def _run_vt_check(self, path, file_hash):
        result = self.updater.virustotal_check_by_hash(file_hash)
        self.root.after(0, lambda: self._vt_finished(path, file_hash, result))

    def _vt_finished(self, path, file_hash, result):
        self.scan_progress_var.set(100)
        self.progress_var.set(100)
        self.status_var.set(self.t["status_ready"])

        if "error" in result:
            messagebox.showerror("Error", self.t["vt_error"].format(result["error"]))
            return

        response_code = result.get("response_code", 0)
        if response_code == 0:
            messagebox.showinfo(self.t["vt_title"], self.t["vt_not_found"])
            return

        positives = result.get("positives", 0)
        total = result.get("total", 0)
        scan_date = result.get("scan_date", "Unknown")

        win = tk.Toplevel(self.root)
        win.title(self.t["vt_title"])
        win.geometry("700x520")
        win.configure(bg=CARD_COLOR)
        win.transient(self.root)
        win.grab_set()

        # Header
        header = tk.Frame(win, bg=CARD_COLOR)
        header.pack(fill=tk.X, padx=16, pady=14)
        tk.Label(header, text=f"File: {os.path.basename(path)}", bg=CARD_COLOR,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 11, "bold")).pack(anchor=tk.W)
        tk.Label(header, text=f"Hash: {file_hash}", bg=CARD_COLOR,
                 fg=TEXT_SECONDARY, font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(2, 0))
        tk.Label(header, text=f"Date: {scan_date}", bg=CARD_COLOR,
                 fg=TEXT_SECONDARY, font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(2, 0))

        # Sonuç etiketi
        if positives == 0:
            msg = self.t["vt_clean"].format(total)
            fg = SUCCESS
        else:
            msg = self.t["vt_detected"].format(positives, total)
            fg = DANGER
        tk.Label(win, text=msg, bg=CARD_COLOR, fg=fg,
                 font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=16, pady=(10, 4))

        # Detay tablo
        frame = tk.Frame(win, bg=CARD_COLOR)
        frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=4)

        cols = ("Antivirus", "Result")
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=14)
        tree.heading("Antivirus", text="Antivirus")
        tree.heading("Result", text="Result")
        tree.column("Antivirus", width=200)
        tree.column("Result", width=300)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree.tag_configure("detected", foreground=DANGER)
        tree.tag_configure("clean", foreground=SUCCESS)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        scans = result.get("scans", {})
        for av_name, av_data in scans.items():
            detected = av_data.get("detected", False)
            result_text = av_data.get("result", "Clean")
            display = f"MALICIOUS: {result_text}" if detected else "Clean"
            tree.insert("", tk.END, values=(av_name, display),
                        tags=("detected" if detected else "clean",))

        # Kapat butonu
        btn_close = HoverButton(win, text="Close", command=win.destroy,
                                bg=ACCENT, fg="#ffffff", hover_bg=ACCENT_HOVER,
                                active_bg=ACCENT, active_fg="#ffffff",
                                font=("Segoe UI", 9, "bold"), padx=16, pady=6)
        btn_close.pack(pady=12)

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
        if messagebox.askyesno("Confirm", self.t["confirm_restore"].format(name)):
            dest = self.quarantine.restore_file(name)
            if dest:
                messagebox.showinfo("Success", self.t["restored"].format(dest))
                self.refresh_quarantine()
                self.refresh_stats()

    def delete_selected(self):
        sel = self.quar_list.curselection()
        if not sel:
            return
        name = self.quar_list.get(sel[0])
        if messagebox.askyesno("Confirm", self.t["confirm_delete"].format(name)):
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
        self.config["realtime_protection"]["use_watchdog"] = self.watchdog_var.get()
        try:
            self.config["scheduler"]["enabled"] = self.sched_var.get()
            self.config["scheduler"]["hour"] = int(self.sched_hour.get())
            self.config["scheduler"]["minute"] = int(self.sched_min.get())
        except Exception:
            pass

        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
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

    def start_scheduled_scan(self, scan_type):
        """Called by scheduler when a scheduled scan is due."""
        if self.scanning:
            return
        path = os.path.join(os.path.expanduser("~"), "Documents") if scan_type == "quick" else os.path.expanduser("~")
        self._navigate("scan", lambda: None)
        self._start_scan(path, scan_type)
