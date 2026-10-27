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

## VirusTotal API Key (GitHub'a yüklemeden önce gerekli)

API keyinizi **kod içinde hardcode yapmayın** ve **GitHub'a paylaşmayın**. Bunun yerine ortam değişkeni olarak kullanın:

1. [virustotal.com/gui/join](https://www.virustotal.com/gui/join) adresinden ücretsiz hesap açın.
2. API Key'inizi kopyalayın.
3. `.env.example` dosyasını kopyalayıp `.env` olarak kaydedin:
   ```bash
   copy .env.example .env
   ```
4. `.env` dosyasını açın ve kendi API keyinizi yazın:
   ```env
   VT_API_KEY=SENIN_API_ANAHTARIN
   ```
5. Programı çalıştırmadan önce ortam değişkenini tanımlayın (Windows CMD):
   ```cmd
   set VT_API_KEY=SENIN_API_ANAHTARIN
   python main.py
   ```
   Veya PowerShell için:
   ```powershell
   $env:VT_API_KEY="SENIN_API_ANAHTARIN"
   python main.py
   ```

### GitHub'a güvenli yükleme
- `.env` dosyası zaten `.gitignore`'da hariç tutulmuştur, GitHub'a gitmeyecektir.
- API keyinizi hiçbir dosyada kod içinde bırakmayın.

## Packaging as Exe
```bash
pyinstaller --onefile --windowed main.py
```
You can use the resulting `dist/main.exe` file.

## Warning
This software is for learning and prototype purposes only. It does not replace a real antivirus and is not a commercial security product.
