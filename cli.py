import argparse
import json
from urllib.parse import urlparse

from crawler import crawl, reset_state
from config import CONFIG, DEFAULT_DEPTH, DEFAULT_USER_AGENT
from storage import fetch_results
from sandbox.executor import sandbox_eval


def run_scan(args: argparse.Namespace) -> None:
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
    if args.output == "json":
        with open(save_path, "w", encoding="utf-8") as fh:
            fh.write(data)
    else:
        import zipfile
        with zipfile.ZipFile(save_path, "w") as zf:
            zf.writestr(f"{domain}.json", data)

    if not args.quiet:
        print(f"Scan complete for {args.url}")
        print(f"Results saved to {save_path}")
        if args.verbose:
            for r in results:
                print(f"- {r['url']}: {len(r['issues'])} issues")


def main() -> None:
    parser = argparse.ArgumentParser(description="MalCrawl Command Line")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a URL")
    scan.add_argument("url")
    scan.add_argument("--output", choices=["json", "zip"], default="json")
    scan.add_argument("--user-agent")
    scan.add_argument("--render-js", action="store_true")
    scan.add_argument("--sandbox", action="store_true")
    scan.add_argument("--quiet", action="store_true")
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--save-path")
    scan.add_argument("--no-yara", action="store_true")
    scan.add_argument("--no-clamav", action="store_true")
    scan.add_argument("--yara-rules")

    args = parser.parse_args()
    if args.command == "scan":
        run_scan(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
