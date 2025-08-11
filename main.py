# ============================================================
# MalCrawl — Codex Context Header
# Purpose: Keep changes aligned with MalCrawl’s architecture, priorities, and security model.
#
# PROJECT SUMMARY
# - MalCrawl is a forensic web crawler that fetches pages, (optionally) renders JS with Selenium, 
#   extracts inline/external JS, deobfuscates it, and flags suspicious behavior via signatures 
#   (YARA, ClamAV, custom JSON DB). Results are viewable in a web UI and via CLI.
# - Core values: lean core, modular heavy features (sandbox, diffing, plugin scanners), 
#   safe-by-default execution, human-readable output.
#
# CURRENT PRIORITIES (implement in this order)
# 1) CLI Enhancements:
#    - Full flags for scope, depth, detection backends, output format
#    - Progress output
#    - Resume previous scan
# 2) Sandboxing v1:
#    - Isolated JS execution (Node VM / py_mini_racer)
#    - Strict time/memory limits
#    - No network access
#    - Log eval, Function(), DOM writes, and timeouts
# 3) README Improvements:
#    - Add CLI usage examples
#    - Clarify installation process
#    - Include contribution guidelines
#
# CODING STYLE NOTES:
# - Keep modules small and single-purpose.
# - Use dependency injection for scanners to allow easy swapping.
# - Maintain HTML output readability (avoid dumping raw JSON without formatting).
# ============================================================


"""CLI entry point for running MalCrawl from the command line."""

import argparse
from crawler import crawl
from config import DEFAULT_DEPTH

def main():
    parser = argparse.ArgumentParser(description="MalCrawl Web Scanner")
    parser.add_argument("--url", required=True, help="Target URL to crawl")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="Crawl depth")
    parser.add_argument("--sqlite", action="store_true", help="Enable SQLite logging")
    parser.add_argument("--target", help="Keyword or pattern to search in scripts")
    parser.add_argument("--debug", action="store_true", help="Debug mode (include filtered scripts)")

    args = parser.parse_args()
    crawl(
        args.url,
        depth=args.depth,
        use_sqlite=args.sqlite,
        target_pattern=args.target,
        debug=args.debug,
    )

if __name__ == "__main__":
    main()
