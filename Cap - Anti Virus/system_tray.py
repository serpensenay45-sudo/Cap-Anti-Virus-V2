"""
System tray integration for Cap - Anti Virus V2.
Uses tkinter-based approach to avoid extra dependencies.
Minimize-to-tray and restore functionality.
"""

import tkinter as tk


class SystemTray:
    """
    Lightweight system tray helper using tkinter.
    Provides minimize/restore and a simple popup menu via the root window.
    """

    def __init__(self, root, app):
        self.root = root
        self.app = app
        self.tray_icon = None
        self.hidden = False

    def hide_window(self):
        self.root.withdraw()
        self.hidden = True

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.hidden = False

    def toggle_window(self):
        if self.hidden:
            self.show_window()
        else:
            self.hide_window()

    def quit_app(self):
        self.app.on_closing()
