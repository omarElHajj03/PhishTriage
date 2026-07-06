"""
enrich.py — threat-intel enrichment via VirusTotal and AbuseIPDB.

Takes the IOCs from extractor.py and asks two free-tier APIs about them:

  * VirusTotal v3  — URL and file-hash reputation (how many AV engines
                     flag each indicator as malicious/suspicious).
  * AbuseIPDB v2   — sender IP abuse confidence score (0-100).

Design decisions worth explaining:
  * Offline-first: if an API key is missing, that service is silently
    skipped and every result is marked as not-checked. The pipeline never
    crashes because of missing credentials.
  * Free-tier friendly: VirusTotal free allows 4 requests/minute, so we
    pause ~15s between VT calls. On an HTTP 429 (rate limited) we back off
    once and retry; on a second 429 we give up gracefully for that IOC.
  * VT "not found" (404) is a real signal — it means the indicator has
    never been submitted — so we record it rather than treating it as
    an error.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field

import requests

from extractor import IOCs

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

VT_FREE_TIER_DELAY = 15   # seconds between VT calls (4 req/min limit)
RATE_LIMIT_BACKOFF = 60   # seconds to wait after an HTTP 429
HTTP_TIMEOUT = 20


@dataclass
class Reputation:
    """Verdict for one indicator from one service."""
    indicator: str            # the URL / hash / IP that was looked up
    checked: bool = False     # False = offline / error / skipped
    found: bool = False       # False = service has never seen this indicator
    malicious: int = 0        # VT: engines flagging malicious
    suspicious: int = 0       # VT: engines flagging suspicious
    abuse_score: int = 0      # AbuseIPDB: confidence of abuse, 0-100
    note: str = ""            # human-readable status ("offline", "rate limited"...)


@dataclass
class EnrichmentResults:
    """All lookups for one email, keyed back to the IOCs."""
    online: bool = False                      # was any API actually used?
    urls: list[Reputation] = field(default_factory=list)
    hashes: list[Reputation] = field(default_factory=list)
    sender_ip: Reputation | None = None


class Enricher:
    """Wraps both API clients; keys may be None/empty (=> offline mode)."""

    def __init__(self, vt_key: str | None, abuseipdb_key: str | None) -> None:
        self.vt_key = vt_key or None
        self.abuseipdb_key = abuseipdb_key or None
        self._last_vt_call = 0.0

    @property
    def offline(self) -> bool:
        return not (self.vt_key or self.abuseipdb_key)

    def enrich(self, iocs: IOCs) -> EnrichmentResults:
        """Look up every IOC; degrades gracefully per-service."""
        results = EnrichmentResults(online=not self.offline)

        for url_ioc in iocs.urls:
            results.urls.append(self._vt_lookup_url(url_ioc.url))
        for filename, sha256 in iocs.attachment_hashes:
            results.hashes.append(self._vt_lookup_hash(sha256))
        if iocs.sender_ip:
            results.sender_ip = self._abuseipdb_lookup(iocs.sender_ip)

        return results

    # ---------------------------------------------------------------- VT

    def _vt_throttle(self) -> None:
        """Stay under the free-tier 4 requests/minute cap."""
        elapsed = time.monotonic() - self._last_vt_call
        if elapsed < VT_FREE_TIER_DELAY:
            time.sleep(VT_FREE_TIER_DELAY - elapsed)
        self._last_vt_call = time.monotonic()

    def _vt_get(self, endpoint: str, indicator: str) -> Reputation:
        """Shared VT GET with throttling, 429 backoff, and 404 handling."""
        rep = Reputation(indicator=indicator)
        if not self.vt_key:
            rep.note = "skipped (no VirusTotal API key)"
            return rep

        headers = {"x-apikey": self.vt_key}
        for attempt in (1, 2):
            self._vt_throttle()
            try:
                resp = requests.get(
                    f"{VT_BASE}/{endpoint}", headers=headers, timeout=HTTP_TIMEOUT
                )
            except requests.RequestException as exc:
                rep.note = f"network error: {exc.__class__.__name__}"
                return rep

            if resp.status_code == 429 and attempt == 1:
                time.sleep(RATE_LIMIT_BACKOFF)  # back off once, then retry
                continue
            break

        rep.checked = True
        if resp.status_code == 404:
            rep.note = "not found on VirusTotal"
        elif resp.status_code == 429:
            rep.checked = False
            rep.note = "rate limited (gave up after retry)"
        elif resp.status_code != 200:
            rep.checked = False
            rep.note = f"VT HTTP {resp.status_code}"
        else:
            stats = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            rep.found = True
            rep.malicious = stats.get("malicious", 0)
            rep.suspicious = stats.get("suspicious", 0)
            rep.note = f"{rep.malicious} malicious / {rep.suspicious} suspicious engines"
        return rep

    def _vt_lookup_url(self, url: str) -> Reputation:
        # VT v3 addresses URLs by the unpadded base64url of the URL itself.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._vt_get(f"urls/{url_id}", url)

    def _vt_lookup_hash(self, sha256: str) -> Reputation:
        return self._vt_get(f"files/{sha256}", sha256)

    # --------------------------------------------------------- AbuseIPDB

    def _abuseipdb_lookup(self, ip: str) -> Reputation:
        rep = Reputation(indicator=ip)
        if not self.abuseipdb_key:
            rep.note = "skipped (no AbuseIPDB API key)"
            return rep

        try:
            resp = requests.get(
                ABUSEIPDB_URL,
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            rep.note = f"network error: {exc.__class__.__name__}"
            return rep

        if resp.status_code == 429:
            rep.note = "rate limited (AbuseIPDB daily quota reached)"
        elif resp.status_code != 200:
            rep.note = f"AbuseIPDB HTTP {resp.status_code}"
        else:
            data = resp.json().get("data", {})
            rep.checked = True
            rep.found = True
            rep.abuse_score = data.get("abuseConfidenceScore", 0)
            rep.note = (
                f"abuse confidence {rep.abuse_score}/100, "
                f"{data.get('totalReports', 0)} reports"
            )
        return rep
