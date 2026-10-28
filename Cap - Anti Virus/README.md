# Cap - Anti Virus V2

An education-purpose antivirus prototype developed in Python.

## New in V2
- Modern dark-themed GUI
- Dashboard with statistics
- Multiple scan modes: Quick, Full System, Custom Folder, USB/Removable
- Real-time file system protection (polling-based)
- Scheduled scanning
- Scan history (JSON-based)
- Enhanced quarantine with metadata
- System tray integration
- VirusTotal v3 API integration
- HTML/Text report export
- English language (single language)

## Features
- File and folder scanning (SHA-256 signature-based)
- Heuristic analysis (suspicious extension, keyword, entropy, obfuscation)
- Quarantine management (isolate, restore, delete files)
- Scan stopping
- VirusTotal integration (query by hash)
- Scan report saving (TXT/HTML)
- User education screen
- Real-time protection
- Scheduled scans
- System tray

## Installation and Running
1. Python 3.10+ must be installed.
2. Open a terminal in the project folder:
   ```bash
   python main.py
   ```

## VirusTotal API Key (Optional)
1. Get a free API key from https://www.virustotal.com/gui/join
2. Copy `.env.example` to `.env` and add your key:
   ```env
   VT_API_KEY=YOUR_API_KEY
   ```
3. Set the environment variable before running:
   ```cmd
   set VT_API_KEY=YOUR_API_KEY
   python main.py
   ```

## Packaging as Exe
```bash
pyinstaller --onefile --windowed main.py
```

## Warning
This software is for learning and prototype purposes only. It does not replace a real antivirus and is not a commercial security product.
