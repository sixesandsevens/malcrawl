"""CLI entry point for running MalCrawl from the command line."""

import argparse
from crawler import crawl
from config import DEFAULT_DEPTH

def main():
    parser = argparse.ArgumentParser(description="MalCrawl Web Scanner")
    parser.add_argument("--url", required=True, help="Target URL to crawl")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="Crawl depth")
    parser.add_argument("--sqlite", action="store_true", help="Enable SQLite logging")

    args = parser.parse_args()
    crawl(args.url, depth=args.depth, use_sqlite=args.sqlite)

if __name__ == "__main__":
    main()
