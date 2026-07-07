"""
extractor.py — IOC (Indicator of Compromise) extraction.

Takes a ParsedEmail (from parser.py) and pulls out everything worth
investigating, with zero network calls:

  * Sender IP     — walks the Received header chain bottom-up and returns
                    the first *public* IP, i.e. the internet-facing hop
                    closest to the true origin.
  * URLs          — from both plain-text and HTML bodies. For HTML links we
                    also detect the classic phishing trick where the visible
                    anchor text shows one domain but the href points elsewhere.
  * File hashes   — SHA256 of every attachment (the standard pivot for
                    VirusTotal / sandbox lookups).
  * Auth results  — SPF / DKIM / DMARC verdicts parsed out of the
                    Authentication-Results headers.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

from parser import ParsedEmail

# Matches http(s) URLs in free text. Trailing punctuation is stripped later.
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# Matches IPv4 addresses inside Received headers, e.g. "[203.0.113.7]".
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Looks like a URL or bare domain — used to decide whether anchor *text*
# is claiming to be a link destination (only then can it "mismatch").
DOMAINISH_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.IGNORECASE
)


@dataclass
class UrlIOC:
    """One extracted URL, with mismatch context if it came from an <a> tag."""
    url: str
    anchor_text: str = ""      # visible link text ("" for plain-text URLs)
    mismatch: bool = False     # True = anchor text domain != href domain


@dataclass
class AuthResults:
    """SPF / DKIM / DMARC verdicts. 'none' = header absent / not evaluated."""
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"


@dataclass
class IOCs:
    """Everything extracted from one email — the input to enrich + scoring."""
    sender_ip: str | None = None
    urls: list[UrlIOC] = field(default_factory=list)
    # (filename, sha256) per attachment
    attachment_hashes: list[tuple[str, str]] = field(default_factory=list)
    auth: AuthResults = field(default_factory=AuthResults)


def extract_iocs(email: ParsedEmail) -> IOCs:
    """Run every extractor against a parsed email."""
    return IOCs(
        sender_ip=extract_sender_ip(email.received),
        urls=extract_urls(email.body_text, email.body_html),
        attachment_hashes=[
            (a.filename, hashlib.sha256(a.data).hexdigest())
            for a in email.attachments
        ],
        auth=extract_auth_results(email.auth_results),
    )


# --------------------------------------------------------------------------
# Sender IP
# --------------------------------------------------------------------------

def extract_sender_ip(received_headers: list[str]) -> str | None:
    """
    Find the originating public IP from the Received chain.

    Received headers are prepended by each hop, so the *last* header in the
    list is the one closest to the sender. We walk bottom-up and return the
    first public (non-private, non-reserved) IP we see — private ranges are
    just the sender's LAN and useless for reputation lookups.
    """
    # We deliberately exclude only *internal* ranges (RFC 1918, loopback,
    # link-local) rather than using ip.is_global, because is_global also
    # rejects the RFC 5737 documentation ranges (192.0.2.0/24 etc.) that
    # safe synthetic test emails use.
    internal = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    for header in reversed(received_headers):
        for candidate in IPV4_RE.findall(header):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_multicast:
                continue
            if any(ip in net for net in internal):
                continue
            return candidate
    return None


# --------------------------------------------------------------------------
# URLs (plain text + HTML with mismatch detection)
# --------------------------------------------------------------------------

class _LinkCollector(HTMLParser):
    """Minimal HTML parser that records (href, visible text) for each <a>."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href:
            self.links.append((self._href, "".join(self._text_parts).strip()))
            self._href = None


def _registered_domain(host: str) -> str:
    """
    Cheap eTLD+1 approximation: last two labels ("mail.paypal.com" ->
    "paypal.com"). Good enough for mismatch detection without a PSL dep.
    """
    parts = host.lower().removeprefix("www.").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def extract_urls(body_text: str, body_html: str) -> list[UrlIOC]:
    """Extract URLs from both bodies, deduped, flagging href/text mismatches."""
    found: dict[str, UrlIOC] = {}  # url -> IOC (dedupe, keep mismatch info)

    # 1) HTML <a> tags — the interesting case, because the anchor text can lie.
    if body_html:
        collector = _LinkCollector()
        collector.feed(body_html)
        for href, text in collector.links:
            href = href.rstrip(".,;)")
            if not href.lower().startswith(("http://", "https://")):
                continue
            mismatch = False
            text_match = DOMAINISH_RE.match(text)
            if text_match:
                # Anchor text claims a destination — compare domains.
                shown = _registered_domain(text_match.group(1))
                actual = _registered_domain(urlparse(href).hostname or "")
                mismatch = shown != actual
            ioc = UrlIOC(url=href, anchor_text=text, mismatch=mismatch)
            # A mismatch flag should never be overwritten by a benign dupe.
            if href not in found or mismatch:
                found[href] = ioc

    # 2) Plain-text body.
    for raw in URL_RE.findall(body_text or ""):
        url = raw.rstrip(".,;)")
        found.setdefault(url, UrlIOC(url=url))

    return list(found.values())


# --------------------------------------------------------------------------
# SPF / DKIM / DMARC
# --------------------------------------------------------------------------

def extract_auth_results(auth_headers: list[str]) -> AuthResults:
    """
    Parse verdicts out of Authentication-Results headers, e.g.:
        Authentication-Results: mx.example.com; spf=fail ...; dkim=pass ...
    Falls back to Received-SPF ("Received-SPF: fail ...") for SPF.
    """
    results = AuthResults()
    for header in auth_headers:
        lower = header.lower()
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}\s*=\s*(\w+)", lower)
            if m:
                setattr(results, mech, m.group(1))
        # Received-SPF header form: the verdict is the first word.
        if lower.lstrip().startswith(("pass", "fail", "softfail", "neutral")):
            if results.spf == "none":
                results.spf = lower.split()[0]
    return results
