# MalCrawl

MalCrawl is a lightweight website crawler designed for forensic analysis. It collects links, images and embedded media while flagging suspicious JavaScript behaviour.

## Features
- Web based UI for launching scans and reviewing results
- Command line interface for automated scans
- Optional JavaScript rendering via Selenium with screenshot capture
- SQLite logging of crawl results
- **Asynchronous JavaScript deobfuscation pipeline** detecting obfuscated code and inferring potential malicious intent
- Interactive code viewer with syntax highlighted deobfuscated scripts and copy-to-clipboard buttons
- Signature based scanning via YARA and ClamAV
- Suspicious attribute scanning (inline events, hidden iframes)
- Optional sandbox execution of scripts

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
The command line exposes most functionality:

```bash
# scan a live URL with a custom User-Agent
python cli.py scan --url https://example.com --user-agent "MyCrawler/1.0" --sandbox --verbose

# scan a local file
python cli.py scan --file sample.html --export text

# run the built in test scan
python cli.py scan --test

# list and view previous scans
python cli.py list
python cli.py view 1

# export a scan result
python cli.py export 1 --format json --output result.json
```

Use `python cli.py --help` for a full list of arguments.

Customising the User-Agent ensures that all HTTP requests, including external
script downloads, present the specified identifier. Some sites block requests
without a User-Agent which can cause script fetching to fail.

## Optional Sandboxing
If Node.js is available you can enable lightweight sandbox execution of detected scripts. Behaviour such as network requests or DOM access will be logged alongside other findings.

## Deobfuscation Pipeline
The scanner analyses each `<script>` block concurrently. Heuristics flag obfuscated code (e.g. `eval`, long variable names or encoded strings). The code is decoded (base64 and hex) and scanned for behaviours such as redirection, credential harvesting or beaconing. A preview of the beautified script is printed to the console along with detected threat types.

This process runs asynchronously so it does not block the crawling workflow.

## Database
Results are stored in `malcrawl.db` when SQLite logging is enabled. Screenshots are saved to `screenshots/` when JS rendering is used with screenshot capture.

## Security Disclaimer
MalCrawl analyses websites for research, auditing and educational purposes only. It does not attempt to exploit or infect targets. Use responsibly.

## Roadmap
- Screenshot diffing
- Behavioural signatures
- API export
