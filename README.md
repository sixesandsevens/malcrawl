# MalCrawl

MalCrawl is a lightweight website crawler designed for forensic analysis. It collects links, images and embedded video references while flagging suspicious JavaScript behaviour.

## Features
- Optional JavaScript rendering via Selenium with screenshot capture
- SQLite logging of crawl results
- Simple HTML interface and CLI
- **Asynchronous JavaScript deobfuscation pipeline** detecting obfuscated code, attempting to decode it and inferring potential malicious intent
- Interactive code viewer with syntax highlighted deobfuscated scripts and copy-to-clipboard buttons
- Targeted keyword scanning across scripts
- Debug mode to include otherwise filtered scripts

## Usage
### Web Interface
Install dependencies and run the Flask app:
```bash
pip install -r requirements.txt
python app.py
```
Open `http://localhost:5000` in your browser.

### CLI
```bash
python main.py --url https://example.com --sqlite
python main.py --url https://example.com --target initWmLoginPosition --debug
```

## Deobfuscation Pipeline
The scanner now analyses each `<script>` block concurrently. Heuristics flag obfuscated code (e.g. use of `eval`, unusually long variable names or encoded strings). The code is then decoded (base64 and hex) and scanned for behaviours such as redirection, credential harvesting or network beaconing. A short preview of the beautified script is printed to the console along with detected threat types.

This process runs asynchronously so it does not block the crawling workflow.

## Database
Results are stored in `malcrawl.db` when SQLite logging is enabled. Screenshots are saved to `screenshots/` when JS rendering is used with screenshot capture.

MalCrawl is intended for research purposes only.
