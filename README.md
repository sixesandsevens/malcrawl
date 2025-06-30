# MalCrawl

MalCrawl is a lightweight website crawler designed for forensic analysis. It collects links, images and embedded media while flagging suspicious JavaScript behaviour.

## Features
- Optional JavaScript rendering via Selenium with screenshot capture
- SQLite logging of crawl results
- Simple HTML interface and CLI
- **Asynchronous JavaScript deobfuscation pipeline** detecting obfuscated code, attempting to decode it and inferring potential malicious intent
- Interactive code viewer with syntax highlighted deobfuscated scripts and copy-to-clipboard buttons
- Targeted keyword scanning across scripts
- Debug mode to include otherwise filtered scripts
- YARA and ClamAV signature scanning
- Suspicious attribute scanning (inline events, hidden iframes)

## Upcoming
- CLI support for full scans from the terminal
- Targeted crawls
- Full sandbox execution
- Signature database

## Install
Requires Python 3.10+ with the following packages:

```bash
pip install -r requirements.txt
```

Optional: create a virtual environment first:

```bash
python3 -m venv venv
source venv/bin/activate
```

ClamAV and YARA are optional but recommended. Ensure the respective binaries are installed if you want signature scanning.

## Usage
### Web Interface
Run the Flask app:

```bash
python app.py
```

Open `http://localhost:5000` in your browser to start a scan.

### CLI
Example commands:

```bash
python cli.py scan https://example.com --output json
python cli.py scan https://example.com --render-js --sandbox --verbose
```

## Deobfuscation Pipeline
The scanner analyses each `<script>` block concurrently. Heuristics flag obfuscated code (e.g. `eval`, long variable names or encoded strings). The code is decoded (base64 and hex) and scanned for behaviours such as redirection, credential harvesting or beaconing. A preview of the beautified script is printed to the console along with detected threat types.

This process runs asynchronously so it does not block the crawling workflow.

## Database
Results are stored in `malcrawl.db` when SQLite logging is enabled. Screenshots are saved to `screenshots/` when JS rendering is used with screenshot capture.

## Ethical Disclaimer
This tool is provided for research, auditing and educational purposes only. Use it responsibly.
