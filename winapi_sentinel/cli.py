"""Command line interface: winapi-sentinel scan <file> [--json]."""
from __future__ import annotations

import argparse
import json
import sys

from .analyzer import analyze_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="winapi-sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan one source file")
    scan.add_argument("file")
    scan.add_argument("--json", action="store_true", help="Emit JSON findings")
    args = parser.parse_args(argv)
    findings = analyze_path(args.file)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{args.file}:{f.line} [{f.severity.upper()}] {f.rule_id} {f.api} — {f.message}")
        if not findings:
            print(f"{args.file}: no risky Windows API patterns found")
    return 1 if any(f.severity in {"high", "critical"} for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
