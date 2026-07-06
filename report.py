"""
report.py — Markdown triage report generation.

The last stage of the pipeline: takes everything the earlier stages
produced and renders a single analyst-ready Markdown report containing:

  * verdict + confidence + score
  * the reasons the verdict engine fired
  * an IOC table (sender IP, URLs, attachment hashes, auth results)
  * enrichment details per indicator
  * a recommended action matched to the verdict

Pure formatting — no analysis logic lives here, so changing the report
layout can never change a verdict.
"""

from __future__ import annotations

from datetime import datetime, timezone

from enrich import EnrichmentResults, Reputation
from extractor import IOCs
from parser import ParsedEmail
from scoring import Verdict

# Analyst playbook per verdict.
RECOMMENDED_ACTIONS = {
    "Malicious": (
        "**Quarantine immediately.** Purge from all recipient mailboxes, "
        "block the sender IP/domain and listed URLs at the gateway, and "
        "check proxy/EDR logs for any user who clicked or opened the attachment."
    ),
    "Suspicious": (
        "**Hold and investigate.** Do not release to the recipient. "
        "Detonate attachments in a sandbox, review the sender's history, "
        "and escalate to a senior analyst if indicators are confirmed."
    ),
    "Likely Benign": (
        "**Release with a note.** No strong indicators found. If the report "
        "came from a user, thank them for reporting and close the ticket."
    ),
}


def _md_escape(text: str) -> str:
    """Neutralize pipes/backticks so IOC values can't break the MD tables."""
    return text.replace("|", "\\|").replace("`", "'")


def _rep_note(rep: Reputation | None) -> str:
    """One-cell summary of an enrichment result."""
    if rep is None or not rep.checked:
        return rep.note if rep and rep.note else "not checked (offline)"
    return rep.note


def build_report(
    email: ParsedEmail,
    iocs: IOCs,
    enrichment: EnrichmentResults,
    verdict: Verdict,
) -> str:
    """Render the full Markdown report as a string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mode = "online (VirusTotal / AbuseIPDB)" if enrichment.online else \
           "offline (extraction only — no API keys configured)"

    lines: list[str] = []
    add = lines.append

    # ---- Header ----------------------------------------------------------
    add("# PhishTriage Report")
    add("")
    add(f"| | |")
    add(f"|---|---|")
    add(f"| **File** | `{_md_escape(email.path)}` |")
    add(f"| **Analyzed** | {now} |")
    add(f"| **Mode** | {mode} |")
    add(f"| **Subject** | {_md_escape(email.subject)} |")
    add(f"| **From** | {_md_escape(email.from_addr)} |")
    add(f"| **To** | {_md_escape(email.to_addr)} |")
    if email.reply_to:
        add(f"| **Reply-To** | {_md_escape(email.reply_to)} |")
    add(f"| **Date** | {_md_escape(email.date)} |")
    add("")

    # ---- Verdict ---------------------------------------------------------
    add("## Verdict")
    add("")
    add(f"> ## {verdict.label}")
    add(f"> **Score:** {verdict.score} &nbsp;|&nbsp; "
        f"**Confidence:** {verdict.confidence}")
    add("")
    add("### Why")
    add("")
    for reason in verdict.reasons:
        add(f"- {_md_escape(reason)}")
    add("")

    # ---- IOC table -------------------------------------------------------
    add("## Indicators of Compromise")
    add("")
    add("| Type | Value | Context |")
    add("|------|-------|---------|")
    add(f"| Sender IP | `{iocs.sender_ip or 'not found'}` "
        f"| first public hop in Received chain |")
    add(f"| SPF | `{iocs.auth.spf}` | from Authentication-Results |")
    add(f"| DKIM | `{iocs.auth.dkim}` | from Authentication-Results |")
    add(f"| DMARC | `{iocs.auth.dmarc}` | from Authentication-Results |")
    for url in iocs.urls:
        ctx = (f"⚠ display text: '{_md_escape(url.anchor_text)}'"
               if url.mismatch else
               (f"anchor text: '{_md_escape(url.anchor_text)}'"
                if url.anchor_text else "plain-text body"))
        add(f"| URL | `{_md_escape(url.url)}` | {ctx} |")
    for filename, sha256 in iocs.attachment_hashes:
        add(f"| Attachment SHA256 | `{sha256}` | {_md_escape(filename)} |")
    add("")

    # ---- Enrichment ------------------------------------------------------
    add("## Enrichment Details")
    add("")
    if not enrichment.online:
        add("_Running in offline mode — add API keys to `config.yaml` to "
            "enable VirusTotal and AbuseIPDB lookups._")
        add("")
    else:
        add("| Service | Indicator | Result |")
        add("|---------|-----------|--------|")
        for rep in enrichment.urls:
            add(f"| VirusTotal | `{_md_escape(rep.indicator)}` "
                f"| {_md_escape(_rep_note(rep))} |")
        for rep in enrichment.hashes:
            add(f"| VirusTotal | `{rep.indicator[:16]}…` "
                f"| {_md_escape(_rep_note(rep))} |")
        if enrichment.sender_ip:
            add(f"| AbuseIPDB | `{enrichment.sender_ip.indicator}` "
                f"| {_md_escape(_rep_note(enrichment.sender_ip))} |")
        add("")

    # ---- Recommended action ----------------------------------------------
    add("## Recommended Action")
    add("")
    add(RECOMMENDED_ACTIONS[verdict.label])
    add("")

    return "\n".join(lines)
