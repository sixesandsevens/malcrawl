import argparse
import contextlib
import datetime
import io
import json
import os
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from crawler import crawl, reset_state
from scanner import scan_page
from config import CONFIG, DEFAULT_DEPTH, DEFAULT_USER_AGENT
from storage import (
    fetch_results,
    fetch_result,
    list_scans,
    log_crawl_result,
)
from sandbox.executor import sandbox_eval


def _write_log(data: str) -> None:
    os.makedirs("cli_logs", exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("cli_logs", f"scan_{ts}.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)
    print(f"Log written to {path}")


def _run_with_capture(func, args) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        func(args)
    output = buf.getvalue()
    print(output, end="")
    if getattr(args, "log", False):
        _write_log(output)
    return output


def scan_url(args: argparse.Namespace) -> None:
    if args.no_yara:
        CONFIG["enable_yara"] = False
    if args.no_clamav:
        CONFIG["enable_clamav"] = False
    if args.yara_rules:
        CONFIG["yara_rules_path"] = args.yara_rules

    ua = args.user_agent or DEFAULT_USER_AGENT

    reset_state()
    crawl(
        args.url,
        depth=DEFAULT_DEPTH,
        use_sqlite=True,
        user_agent=ua,
        render_js=args.render_js,
        target_pattern=None,
        debug=args.verbose,
    )

    domain = urlparse(args.url).netloc
    results = fetch_results(domain)
    if args.sandbox:
        for result in results:
            sb_out = []
            for script in result.get("deobfuscated_scripts", []):
                code = script.get("deobfuscated") or script.get("original", "")
                sb_out.append(sandbox_eval(code))
            result["sandbox_behavior"] = sb_out

    output = {"domain": domain, "results": results}
    data = json.dumps(output, indent=2)

    save_path = args.save_path or f"{domain}.json"
    if args.export == "json":
        with open(save_path, "w", encoding="utf-8") as fh:
            fh.write(data)
    else:
        with open(save_path, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(f"URL: {r['url']}\n")
                fh.write(f"Issues: {len(r['issues'])}\n\n")
    if not args.quiet:
        print(f"Scan complete for {args.url}")
        print(f"Results saved to {save_path}")
        if args.verbose:
            for r in results:
                print(f"- {r['url']}: {len(r['issues'])} issues")


def scan_file(args: argparse.Namespace) -> None:
    if args.no_yara:
        CONFIG["enable_yara"] = False
    if args.no_clamav:
        CONFIG["enable_clamav"] = False
    if args.yara_rules:
        CONFIG["yara_rules_path"] = args.yara_rules

    with open(args.file, "r", encoding="utf-8") as fh:
        html = fh.read()
    soup = BeautifulSoup(html, "html.parser")
    suspicious, scripts, inline_events, matches = scan_page(soup, args.file, debug=args.verbose)
    links = [a.get("href") for a in soup.find_all("a", href=True)]
    images = [i.get("src") for i in soup.find_all("img", src=True)]
    videos = [v.get("src") for v in soup.find_all("video", src=True)] + [s.get("src") for s in soup.find_all("source", src=True)]
    crawl_id = log_crawl_result(
        args.file,
        len(links),
        len(images),
        len(videos),
        suspicious,
        scripts=scripts,
        matches=matches,
    )
    result = fetch_result(crawl_id)
    results = [result] if result else []
    if args.sandbox and result:
        sb_out = []
        for script in result.get("deobfuscated_scripts", []):
            code = script.get("deobfuscated") or script.get("original", "")
            sb_out.append(sandbox_eval(code))
        result["sandbox_behavior"] = sb_out
    data = json.dumps({"file": args.file, "results": results}, indent=2)
    save_path = args.save_path or f"{os.path.basename(args.file)}.json"
    if args.export == "json":
        with open(save_path, "w", encoding="utf-8") as fh:
            fh.write(data)
    else:
        with open(save_path, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(f"Issues: {len(r['issues'])}\n")
    if not args.quiet:
        print(f"Scan complete for {args.file}")
        print(f"Results saved to {save_path}")


def command_list(args: argparse.Namespace) -> None:
    scans = list_scans()
    for s in scans:
        print(f"{s[0]}\t{s[1]}\t{s[2]}\t{s[3]}")


def command_view(args: argparse.Namespace) -> None:
    result = fetch_result(args.scan_id)
    if result:
        print(json.dumps(result, indent=2))
    else:
        print("Scan not found")


def command_export(args: argparse.Namespace) -> None:
    result = fetch_result(args.scan_id)
    if not result:
        print("Scan not found")
        return
    if args.format == "json":
        data = json.dumps(result, indent=2)
    else:
        lines = [
            f"URL: {result['url']}",
            f"Timestamp: {result['timestamp']}",
            f"Issues: {len(result['issues'])}",
        ]
        data = "\n".join(lines)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(data)
    else:
        print(data)


def main() -> None:
    parser = argparse.ArgumentParser(description="MalCrawl Command Line")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a URL or file")
    tgt = scan.add_mutually_exclusive_group(required=False)
    tgt.add_argument("--url", help="URL to scan")
    tgt.add_argument("--file", help="HTML file to scan")
    scan.add_argument("--test", action="store_true", help="Run built-in test scan")
    scan.add_argument(
        "--export",
        choices=["json", "text"],
        default="json",
        help="Export format for results",
    )
    scan.add_argument("--user-agent", help="Custom User-Agent header")
    scan.add_argument("--render-js", action="store_true", help="Use Selenium to render JS")
    scan.add_argument("--sandbox", action="store_true", help="Run sandbox analysis of scripts")
    scan.add_argument("--quiet", action="store_true", help="Suppress status output")
    scan.add_argument("--verbose", action="store_true", help="Verbose output")
    scan.add_argument("--save-path", help="Path to save exported results")
    scan.add_argument("--no-yara", action="store_true", help="Disable YARA scanning")
    scan.add_argument("--no-clamav", action="store_true", help="Disable ClamAV scanning")
    scan.add_argument("--yara-rules", help="Path to YARA rules directory")
    scan.add_argument("--log", action="store_true", help="Save console output to cli_logs")

    list_cmd = sub.add_parser("list", help="List previous scans")
    list_cmd.set_defaults(func=command_list)

    view_cmd = sub.add_parser("view", help="View a scan result")
    view_cmd.add_argument("scan_id", type=int, help="ID of scan to view")
    view_cmd.set_defaults(func=command_view)

    export_cmd = sub.add_parser("export", help="Export a scan result")
    export_cmd.add_argument("scan_id", type=int, help="ID of scan to export")
    export_cmd.add_argument(
        "--format", choices=["json", "text"], default="json", help="Export format"
    )
    export_cmd.add_argument("--output", help="Output file path")
    export_cmd.set_defaults(func=command_export)

    args = parser.parse_args()

    if args.command == "scan":
        if args.test:
            args.file = os.path.join("tests", "mocks", "test.html")
        if args.url:
            _run_with_capture(scan_url, args)
        elif args.file:
            _run_with_capture(scan_file, args)
        else:
            parser.error("--url or --file is required")
    elif hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
