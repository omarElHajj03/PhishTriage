"""
scoring.py — rules-based verdict engine.

Turns the extracted IOCs + enrichment results into one of three verdicts:

    Malicious  /  Suspicious  /  Likely Benign

How it works:
  * Each rule is a small function that inspects the evidence and, if it
    fires, contributes (points, reason). Rules never veto each other —
    they just accumulate.
  * The total score is compared against two thresholds (configurable in
    config.yaml under `scoring:`) to pick the verdict.
  * Every fired rule's reason is kept, so the analyst always sees WHY —
    a verdict without reasons is useless in a SOC.

Confidence is reported separately from the verdict: enrichment data
(VirusTotal / AbuseIPDB) is strong external evidence, so verdicts backed
by it get higher confidence than purely heuristic ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr

from enrich import EnrichmentResults
from extractor import IOCs
from parser import ParsedEmail

# Default rule weights and thresholds — every value can be overridden from
# config.yaml (see merge logic in load_scoring_config below).
DEFAULTS = {
    "weights": {
        "spf_fail": 25,
        "dkim_fail": 15,
        "dmarc_fail": 25,
        "url_mismatch": 30,
        "reply_to_differs": 15,
        "risky_attachment": 20,
        "urgency_language": 10,
        "vt_url_hits_low": 25,    # 1-4 engines flag a URL
        "vt_url_hits_high": 50,   # 5+ engines
        "vt_hash_hits_low": 30,
        "vt_hash_hits_high": 60,
        "abuseipdb_medium": 20,   # abuse confidence 25-74
        "abuseipdb_high": 40,     # abuse confidence 75+
    },
    "thresholds": {
        "malicious": 70,    # score >= 70  -> Malicious
        "suspicious": 35,   # score >= 35  -> Suspicious, else Likely Benign
    },
}

# Attachment extensions that rarely have a legitimate reason to be emailed.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar",
    ".hta", ".iso", ".img", ".lnk", ".html", ".htm", ".xll",
}

# Social-engineering pressure phrases common in credential-phishing lures.
URGENCY_RE = re.compile(
    r"\b(urgent|immediately|verify your account|account (?:will be )?"
    r"(?:suspended|closed|locked)|expires? (?:today|soon|in \d+)|"
    r"final (?:notice|warning)|action required|confirm your (?:identity|password))\b",
    re.IGNORECASE,
)


@dataclass
class Verdict:
    label: str                 # "Malicious" | "Suspicious" | "Likely Benign"
    score: int                 # accumulated rule points
    confidence: str            # "High" | "Medium" | "Low"
    reasons: list[str] = field(default_factory=list)


def load_scoring_config(config: dict | None) -> dict:
    """Merge user overrides from config.yaml on top of DEFAULTS."""
    merged = {
        "weights": dict(DEFAULTS["weights"]),
        "thresholds": dict(DEFAULTS["thresholds"]),
    }
    user = (config or {}).get("scoring", {})
    merged["weights"].update(user.get("weights", {}))
    merged["thresholds"].update(user.get("thresholds", {}))
    return merged


def score_email(
    email: ParsedEmail,
    iocs: IOCs,
    enrichment: EnrichmentResults,
    config: dict | None = None,
) -> Verdict:
    """Run every rule, sum the points, map to a verdict with reasons."""
    cfg = load_scoring_config(config)
    w = cfg["weights"]
    score = 0
    reasons: list[str] = []

    def fire(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(f"[+{points}] {reason}")

    # --- Rule group 1: email authentication -----------------------------
    if iocs.auth.spf in ("fail", "softfail"):
        fire(w["spf_fail"], f"SPF check failed ({iocs.auth.spf}) — sender not "
                            "authorized to send for this domain")
    if iocs.auth.dkim == "fail":
        fire(w["dkim_fail"], "DKIM signature failed — message may have been "
                             "altered or forged")
    if iocs.auth.dmarc == "fail":
        fire(w["dmarc_fail"], "DMARC policy failed — From domain alignment broken")

    # --- Rule group 2: header tricks -------------------------------------
    from_domain = parseaddr(email.from_addr)[1].partition("@")[2].lower()
    reply_domain = parseaddr(email.reply_to)[1].partition("@")[2].lower()
    if reply_domain and from_domain and reply_domain != from_domain:
        fire(w["reply_to_differs"],
             f"Reply-To domain ({reply_domain}) differs from From domain "
             f"({from_domain}) — replies are diverted")

    # --- Rule group 3: body content --------------------------------------
    for url in iocs.urls:
        if url.mismatch:
            fire(w["url_mismatch"],
                 f"Link text shows '{url.anchor_text}' but points to {url.url} "
                 "— classic display-text spoofing")

    lure = URGENCY_RE.search(f"{email.subject}\n{email.body_text}")
    if lure:
        fire(w["urgency_language"],
             f"Urgency/pressure language detected: '{lure.group(0)}'")

    # --- Rule group 4: attachments ----------------------------------------
    for filename, _sha in iocs.attachment_hashes:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext in RISKY_EXTENSIONS:
            fire(w["risky_attachment"],
                 f"Attachment '{filename}' has a high-risk extension ({ext})")

    # --- Rule group 5: threat-intel enrichment ---------------------------
    has_intel = False  # tracks whether any external service confirmed anything
    for rep in enrichment.urls:
        if rep.checked and rep.malicious >= 5:
            fire(w["vt_url_hits_high"],
                 f"URL flagged malicious by {rep.malicious} VirusTotal engines: "
                 f"{rep.indicator}")
            has_intel = True
        elif rep.checked and rep.malicious >= 1:
            fire(w["vt_url_hits_low"],
                 f"URL flagged by {rep.malicious} VirusTotal engine(s): "
                 f"{rep.indicator}")
            has_intel = True

    for rep in enrichment.hashes:
        if rep.checked and rep.malicious >= 5:
            fire(w["vt_hash_hits_high"],
                 f"Attachment hash flagged by {rep.malicious} VirusTotal engines")
            has_intel = True
        elif rep.checked and rep.malicious >= 1:
            fire(w["vt_hash_hits_low"],
                 f"Attachment hash flagged by {rep.malicious} VirusTotal engine(s)")
            has_intel = True

    ip_rep = enrichment.sender_ip
    if ip_rep and ip_rep.checked:
        if ip_rep.abuse_score >= 75:
            fire(w["abuseipdb_high"],
                 f"Sender IP {ip_rep.indicator} has AbuseIPDB confidence "
                 f"{ip_rep.abuse_score}/100")
            has_intel = True
        elif ip_rep.abuse_score >= 25:
            fire(w["abuseipdb_medium"],
                 f"Sender IP {ip_rep.indicator} has AbuseIPDB confidence "
                 f"{ip_rep.abuse_score}/100")
            has_intel = True

    # --- Verdict + confidence ---------------------------------------------
    t = cfg["thresholds"]
    if score >= t["malicious"]:
        label = "Malicious"
    elif score >= t["suspicious"]:
        label = "Suspicious"
    else:
        label = "Likely Benign"
        if not reasons:
            reasons.append("No phishing indicators fired")

    # External intel corroboration (or a clean pass) raises confidence;
    # heuristics-only verdicts in offline mode stay at Medium/Low.
    if has_intel:
        confidence = "High"
    elif enrichment.online or label == "Likely Benign":
        confidence = "Medium"
    else:
        confidence = "Medium" if score >= t["malicious"] else "Low"

    return Verdict(label=label, score=score, confidence=confidence, reasons=reasons)
