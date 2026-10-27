import os
import tkinter as tk
from gui import CapAntiVirusGUI
from updater import Updater

if __name__ == "__main__":
    vt_api_key = os.environ.get("VT_API_KEY", "")
    if not vt_api_key:
        print("Uyarı: VT_API_KEY ortam değişkeni tanımlanmadı. VirusTotal sorguları çalışmayacaktır.")
        print("Örnek: set VT_API_KEY=SENIN_API_ANAHTARIN")
    updater = Updater(vt_api_key=vt_api_key)
    root = tk.Tk()
    app = CapAntiVirusGUI(root, updater=updater)
    root.mainloop()