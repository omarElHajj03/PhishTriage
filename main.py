"""
main.py — PhishTriage CLI entry point.

Usage:
    python main.py sample.eml
    python main.py sample.eml --config config.yaml --output report.md
    python main.py sample.eml --offline

Pipeline (one stage per module, in order):
    parse (parser.py) -> extract (extractor.py) -> enrich (enrich.py)
        -> score (scoring.py) -> report (report.py)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from enrich import Enricher
from extractor import extract_iocs
from parser import parse_eml
from report import build_report
from scoring import score_email


def load_config(path: str | None) -> dict:
    """
    Load config.yaml if present. A missing config is NOT an error — the
    tool simply runs in offline mode (extraction + heuristics only).
    """
    candidate = Path(path) if path else Path(__file__).parent / "config.yaml"
    if not candidate.exists():
        return {}
    with candidate.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="phishtriage",
        description="Phishing email triage: parse an .eml, extract IOCs, "
                    "enrich with threat intel, and produce a verdict report.",
    )
    ap.add_argument("eml", help="path to the .eml file to triage")
    ap.add_argument("--config", help="path to config.yaml (default: ./config.yaml)")
    ap.add_argument("--output", "-o", help="report path (default: <eml>_report.md)")
    ap.add_argument("--offline", action="store_true",
                    help="skip API lookups even if keys are configured")
    args = ap.parse_args(argv)

    eml_path = Path(args.eml)
    if not eml_path.exists():
        print(f"error: file not found: {eml_path}", file=sys.stderr)
        return 1

    config = load_config(args.config)
    api_keys = config.get("api_keys", {})

    # Stage 1-2: parse the email and extract IOCs (no network).
    print(f"[*] Parsing {eml_path.name} ...")
    email = parse_eml(eml_path)
    iocs = extract_iocs(email)
    print(f"[*] Extracted: {len(iocs.urls)} URL(s), "
          f"{len(iocs.attachment_hashes)} attachment(s), "
          f"sender IP: {iocs.sender_ip or 'not found'}")

    # Stage 3: enrichment. --offline forces empty keys.
    enricher = Enricher(
        vt_key=None if args.offline else api_keys.get("virustotal"),
        abuseipdb_key=None if args.offline else api_keys.get("abuseipdb"),
    )
    if enricher.offline:
        print("[*] No API keys — running in offline mode (extraction only)")
    else:
        print("[*] Enriching IOCs (free-tier rate limits apply, may be slow)...")
    enrichment = enricher.enrich(iocs)

    # Stage 4: verdict.
    verdict = score_email(email, iocs, enrichment, config)
    print(f"[*] Verdict: {verdict.label} "
          f"(score {verdict.score}, confidence {verdict.confidence})")

    # Stage 5: report.
    report_md = build_report(email, iocs, enrichment, verdict)
    out_path = Path(args.output) if args.output else \
        eml_path.with_name(eml_path.stem + "_report.md")
    out_path.write_text(report_md, encoding="utf-8")
    print(f"[*] Report written to {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
