# Cap - Anti Virus V1

An education-purpose antivirus prototype developed in Python.

## Features
- File and folder scanning (SHA-256 signature-based)
- Heuristic analysis (suspicious extension, keyword, entropy)
- Quarantine management (isolate, restore, delete files)
- Scan stopping (Stop button)
- VirusTotal integration (query by hash)
- English language support
- Scan report saving
- User education screen (why antivirus is needed, what to watch out for)
- PowerShell hidden execution (-WindowStyle Hidden) detection

## Installation and Running
1. Python 3.10+ must be installed.
2. Open a terminal in the project folder:
   ```bash
   python main.py
   ```

## VirusTotal API Key
1. Create a free account at [virustotal.com/gui/join](https://www.virustotal.com/gui/join).
2. Copy your API Key.
3. Open "main.py" and edit this line:
   "python"
   updater = Updater(vt_api_key="YOUR_API_KEY")
   ```

## Packaging as Exe
```bash
pyinstaller --onefile --windowed main.py
```
You can use the resulting `dist/main.exe` file.

## Warning
This software is for learning and prototype purposes only. It does not replace a real antivirus and is not a commercial security product.
