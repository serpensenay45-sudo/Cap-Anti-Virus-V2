import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
from scanner import Scanner
from quarantine import QuarantineManager
from logger import setup_logger
from info import INFO_TEXT
from updater import Updater

STRINGS = {
    "title": "Cap - Anti Virus V1",
    "tab_scan": "Scan",
    "tab_quarantine": "Quarantine",
    "tab_info": "Info",
    "btn_quick": "Quick Scan",
    "btn_full": "Full System Scan",
    "btn_folder": "Select Folder and Scan",
    "btn_clear": "Clear Results",
    "btn_quarantine": "Quarantine",
    "btn_report": "Save Report",
    "btn_refresh": "Refresh",
    "btn_restore": "Restore",
    "btn_delete": "Delete Permanently",
    "btn_virustotal": "Search on VirusTotal",
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
    "vt_no_api": "VirusTotal API key not defined. Please fill vt_api_key in main.py.",
    "vt_scanning": "Querying VirusTotal..."
}

class CapAntiVirusGUI:
    def __init__(self, root, updater=None):
        self.root = root
        self.t = STRINGS
        self.root.title(self.t["title"])
        self.root.geometry("950x750")
        self.logger = setup_logger()
        self.scanner = Scanner()
        self.quarantine = QuarantineManager()
        self.updater = updater if updater else Updater()
        self.scanning = False
        self.create_widgets()
        self.apply_ui_text()

    def t_(self, key):
        return self.t.get(key, key)

    def apply_ui_text(self):
        self.root.title(self.t_("title"))
        self.notebook.tab(0, text=self.t_("tab_scan"))
        self.notebook.tab(1, text=self.t_("tab_quarantine"))
        self.notebook.tab(2, text=self.t_("tab_info"))

        self.btn_quick.config(text=self.t_("btn_quick"))
        self.btn_full.config(text=self.t_("btn_full"))
        self.btn_folder.config(text=self.t_("btn_folder"))
        self.btn_clear.config(text=self.t_("btn_clear"))
        self.btn_quarantine.config(text=self.t_("btn_quarantine"))
        self.btn_report.config(text=self.t_("btn_report"))
        self.btn_virustotal.config(text=self.t_("btn_virustotal"))
        self.btn_stop.config(text=self.t_("btn_stop"))

        self.btn_refresh.config(text=self.t_("btn_refresh"))
        self.btn_restore.config(text=self.t_("btn_restore"))
        self.btn_delete.config(text=self.t_("btn_delete"))

        self.status_var.set(self.t_("status_ready"))

        cols = (self.t_("col_status"), self.t_("col_path"), self.t_("col_hash"),
                self.t_("col_type"), self.t_("col_reason"))
        for c, col in zip(self.tree["columns"], cols):
            self.tree.heading(c, text=col)

        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete("1.0", tk.END)
        self.info_text.insert(tk.END, INFO_TEXT)
        self.info_text.config(state=tk.DISABLED)

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_scan = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_scan, text=self.t_("tab_scan"))
        self.build_scan_tab()

        self.tab_quar = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_quar, text=self.t_("tab_quarantine"))
        self.build_quarantine_tab()

        self.tab_info = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_info, text=self.t_("tab_info"))
        self.build_info_tab()

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value=self.t_("status_ready"))
        self.status_bar = ttk.Label(
            bottom_frame, textvariable=self.status_var,
            relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def build_scan_tab(self):
        btn_frame = ttk.Frame(self.tab_scan)
        btn_frame.pack(fill=tk.X, pady=5)

        self.btn_quick = ttk.Button(btn_frame, text=self.t_("btn_quick"), command=self.quick_scan)
        self.btn_quick.pack(side=tk.LEFT, padx=5)

        self.btn_full = ttk.Button(btn_frame, text=self.t_("btn_full"), command=self.full_scan)
        self.btn_full.pack(side=tk.LEFT, padx=5)

        self.btn_folder = ttk.Button(btn_frame, text=self.t_("btn_folder"), command=self.scan_folder)
        self.btn_folder.pack(side=tk.LEFT, padx=5)

        self.btn_clear = ttk.Button(btn_frame, text=self.t_("btn_clear"), command=self.clear_results)
        self.btn_clear.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(btn_frame, text=self.t_("btn_stop"), command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_virustotal = ttk.Button(btn_frame, text=self.t_("btn_virustotal"), command=self.virustotal_selected)
        self.btn_virustotal.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(self.tab_scan, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        cols = ("status", "path", "hash", "type", "reason")
        self.tree = ttk.Treeview(self.tab_scan, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=160)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        act_frame = ttk.Frame(self.tab_scan)
        act_frame.pack(fill=tk.X, pady=5)

        self.btn_quarantine = ttk.Button(act_frame, text=self.t_("btn_quarantine"), command=self.quarantine_selected)
        self.btn_quarantine.pack(side=tk.LEFT, padx=5)

        self.btn_report = ttk.Button(act_frame, text=self.t_("btn_report"), command=self.save_report)
        self.btn_report.pack(side=tk.LEFT, padx=5)

    def build_quarantine_tab(self):
        self.quar_list = tk.Listbox(self.tab_quar)
        self.quar_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_frame = ttk.Frame(self.tab_quar)
        btn_frame.pack(fill=tk.X, pady=5)

        self.btn_refresh = ttk.Button(btn_frame, text=self.t_("btn_refresh"), command=self.refresh_quarantine)
        self.btn_refresh.pack(side=tk.LEFT, padx=5)

        self.btn_restore = ttk.Button(btn_frame, text=self.t_("btn_restore"), command=self.restore_selected)
        self.btn_restore.pack(side=tk.LEFT, padx=5)

        self.btn_delete = ttk.Button(btn_frame, text=self.t_("btn_delete"), command=self.delete_selected)
        self.btn_delete.pack(side=tk.LEFT, padx=5)

        self.refresh_quarantine()

    def build_info_tab(self):
        self.info_text = tk.Text(self.tab_info, wrap=tk.WORD, padx=10, pady=10)
        self.info_text.pack(fill=tk.BOTH, expand=True)
        self.info_text.insert(tk.END, INFO_TEXT)
        self.info_text.config(state=tk.DISABLED)

    def quick_scan(self):
        if self.scanning:
            return
        path = os.path.expanduser("~\\Documents")
        if not os.path.exists(path):
            path = os.path.expanduser("~")
        self.start_scan(path)

    def full_scan(self):
        if self.scanning:
            return
        path = os.path.expanduser("~")
        self.start_scan(path)

    def scan_folder(self):
        if self.scanning:
            return
        folder = filedialog.askdirectory()
        if folder:
            self.start_scan(folder)

    def start_scan(self, path):
        self.scanning = True
        self.tree.delete(*self.tree.get_children())
        self.status_var.set(self.t_("status_scanning").format(path))
        self.progress.start()
        self._set_buttons_state(False)
        self.btn_stop.config(state=tk.NORMAL)

        thread = threading.Thread(target=self._run_scan, args=(path,), daemon=True)
        thread.start()

    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.scanner.request_stop()
            self.btn_stop.config(state=tk.DISABLED)
            self.status_var.set(self.t_("status_ready"))

    def _run_scan(self, path):
        results = self.scanner.scan_directory(path, callback=self._on_file_scanned)
        self.root.after(0, lambda: self._scan_finished(results, path, self.scanner.stop_requested))

    def _on_file_scanned(self, result):
        self.root.after(0, lambda: self._insert_result(result))

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
        self.tree.tag_configure("threat", foreground="red")
        self.tree.tag_configure("clean", foreground="green")

    def _scan_finished(self, results, path, was_stopped):
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

    def _set_buttons_state(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.btn_quick.config(state=state)
        self.btn_full.config(state=state)
        self.btn_folder.config(state=state)
        self.btn_clear.config(state=state)
        self.btn_quarantine.config(state=state)
        self.btn_report.config(state=state)
        self.btn_virustotal.config(state=state)

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

    def save_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text File", "*.txt")]
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for child in self.tree.get_children():
                    vals = self.tree.item(child)["values"]
                    f.write(" | ".join(str(v) for v in vals) + "\n")
            messagebox.showinfo("Success", "Report saved.")

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
            lbl = ttk.Label(win, text=msg, foreground="green", font=("Segoe UI", 10, "bold"))
        else:
            msg = self.t_("vt_detected").format(positives, total)
            lbl = ttk.Label(win, text=msg, foreground="red", font=("Segoe UI", 10, "bold"))
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
            tree.insert("", tk.END, values=(av_name, display), tags=("detected" if detected else "clean",))

        tree.tag_configure("detected", foreground="red")
        tree.tag_configure("clean", foreground="green")

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

    def refresh_quarantine(self):
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

    def delete_selected(self):
        sel = self.quar_list.curselection()
        if not sel:
            return
        name = self.quar_list.get(sel[0])
        if messagebox.askyesno("Confirm", self.t_("confirm_delete").format(name)):
            self.quarantine.delete_quarantined(name)
            self.refresh_quarantine()
