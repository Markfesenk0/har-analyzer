from __future__ import annotations

import argparse
import os
import sys

from .config import load_run_config
from .graph import run_scan
from .har import export_filtered_records, save_sanitized_har
from .web import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="har-analyzer", description="HAR Analyzer CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run an active scan against scoped domains")
    scan_parser.add_argument("--har", required=True, help="Path to the HAR file")
    scan_parser.add_argument("--scope-domain", action="append", required=True, dest="scope_domains", help="Domain allowed for active replay")
    scan_parser.add_argument("--artifact-dir", default=os.getenv("HAR_ANALYZER_ARTIFACT_DIR", "artifacts"))
    unsafe_group = scan_parser.add_mutually_exclusive_group()
    unsafe_group.add_argument(
        "--unsafe-unredacted",
        dest="unsafe_unredacted",
        action="store_true",
        default=None,
        help="Write unredacted artifacts to disk. If omitted, uses HAR_ANALYZER_UNSAFE_UNREDACTED_DEFAULT.",
    )
    unsafe_group.add_argument(
        "--safe-redacted",
        dest="unsafe_unredacted",
        action="store_false",
        help="Force redacted artifacts to disk, overriding HAR_ANALYZER_UNSAFE_UNREDACTED_DEFAULT.",
    )

    serve_parser = subparsers.add_parser("serve", help="Launch the local web UI")
    serve_parser.add_argument("--host", default=os.getenv("HAR_ANALYZER_UI_HOST", "127.0.0.1"))
    serve_parser.add_argument("--port", type=int, default=int(os.getenv("HAR_ANALYZER_UI_PORT", "8765")))
    serve_parser.add_argument("--artifact-dir", default=os.getenv("HAR_ANALYZER_ARTIFACT_DIR", "artifacts"))

    sanitize_parser = subparsers.add_parser("sanitize-har", help="Create a sanitized HAR fixture")
    sanitize_parser.add_argument("--input", required=True, help="Input HAR path")
    sanitize_parser.add_argument("--output", required=True, help="Output HAR path")

    export_parser = subparsers.add_parser(
        "export-filtered-records",
        help="Export the filtered request records that would be analyzed before LLM prompting",
    )
    export_parser.add_argument("--har", required=True, help="Path to the HAR file")
    export_parser.add_argument("--scope-domain", action="append", required=True, dest="scope_domains", help="Domain included in the filtered export")
    export_parser.add_argument("--output", required=True, help="Output JSON file path")

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "sanitize-har":
        save_sanitized_har(args.input, args.output)
        print("Sanitized HAR written to %s" % args.output)
        return 0

    if args.command == "export-filtered-records":
        config = load_run_config(
            har_path=args.har,
            target_domains=args.scope_domains,
        )
        export_filtered_records(
            args.har,
            args.output,
            config.target_domains,
            config.excluded_path_patterns,
        )
        print("Filtered records exported to %s" % args.output)
        return 0

    if args.command == "scan":
        config = load_run_config(
            har_path=args.har,
            target_domains=args.scope_domains,
            artifact_dir=args.artifact_dir,
            allow_unsafe_artifacts=args.unsafe_unredacted,
        )
        def progress(stage, message, payload):
            print("[%s] %s" % (stage, message))

        run = run_scan(config, progress_callback=progress)
        print("Completed run %s with %d findings" % (run.run_id, run.findings_count))
        print("Markdown report: %s" % run.report_markdown_path)
        print("JSON report: %s" % run.report_json_path)
        return 0

    if args.command == "serve":
        return serve(args.host, args.port, args.artifact_dir)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
