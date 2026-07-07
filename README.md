# PhishTriage

A command-line phishing email triage tool for SOC analysts. Feed it a raw
`.eml` file and it parses the message, extracts indicators of compromise
(IOCs), enriches them against VirusTotal and AbuseIPDB, runs a transparent
rules-based verdict engine, and writes an analyst-ready Markdown report.

Built with Python 3.11+ — email parsing uses only the standard library.

## Architecture

Each pipeline stage is one module with one job. Data flows strictly left
to right, so every stage can be explained (and tested) in isolation:

```
              ┌────────────┐   ┌──────────────┐   ┌─────────────┐
 sample.eml ─▶│ parser.py  │──▶│ extractor.py │──▶│  enrich.py  │
              │ .eml → MIME│   │ IOCs:        │   │ VirusTotal  │
              │ headers,   │   │ sender IP,   │   │ (URLs,      │
              │ bodies,    │   │ URLs+mismatch│   │  hashes)    │
              │ attachments│   │ SHA256, SPF/ │   │ AbuseIPDB   │
              └────────────┘   │ DKIM/DMARC   │   │ (IPs)       │
                               └──────────────┘   └──────┬──────┘
                                                         │
              ┌────────────┐   ┌──────────────┐          │
 report.md ◀──│ report.py  │◀──│  scoring.py  │◀─────────┘
              │ Markdown   │   │ weighted     │
              │ triage     │   │ rules →      │
              │ report     │   │ verdict +    │
              └────────────┘   │ reasons      │
                               └──────────────┘
```

| Module | Responsibility |
|--------|----------------|
| `main.py` | CLI entry point; wires the pipeline together |
| `parser.py` | `.eml` → structured object (stdlib `email` with `policy.default`) |
| `extractor.py` | Sender IP from the Received chain, URLs (incl. href vs. anchor-text mismatch), attachment SHA256 hashes, SPF/DKIM/DMARC results |
| `enrich.py` | VirusTotal + AbuseIPDB lookups with free-tier rate-limit handling; degrades to offline mode without keys |
| `scoring.py` | Rules-based verdict engine with configurable weights/thresholds; every verdict lists its reasons |
| `report.py` | Renders the final Markdown report (pure formatting, no logic) |

## Installation

```bash
git clone <this-repo>
cd phishtriage
pip install -r requirements.txt
```

### API keys (optional)

```bash
cp config.example.yaml config.yaml
# edit config.yaml and paste your keys
```

- VirusTotal (free, 4 req/min): https://www.virustotal.com/gui/my-apikey
- AbuseIPDB (free, 1000 checks/day): https://www.abuseipdb.com/account/api

`config.yaml` is gitignored so keys never reach the repo. **Without keys the
tool still works** — it runs in offline mode (extraction + heuristics only).

## Usage

```bash
python main.py samples/phish_invoice.eml            # basic
python main.py mail.eml -o triage.md                # custom report path
python main.py mail.eml --offline                   # skip API lookups
python main.py mail.eml --config /path/config.yaml  # explicit config
```

Console output:

```
[*] Parsing phish_invoice.eml ...
[*] Extracted: 2 URL(s), 1 attachment(s), sender IP: 203.0.113.55
[*] No API keys — running in offline mode (extraction only)
[*] Verdict: Malicious (score 140, confidence Medium)
[*] Report written to samples\phish_invoice_report.md
```

## Sample report output

```markdown
# PhishTriage Report

| **Subject** | URGENT: Your account will be suspended - action required |
| **From**    | First National Bank Security <security@firstnational.example> |

## Verdict

> ## Malicious
> **Score:** 140 | **Confidence:** Medium

### Why

- [+25] SPF check failed (fail) — sender not authorized to send for this domain
- [+15] DKIM signature failed — message may have been altered or forged
- [+25] DMARC policy failed — From domain alignment broken
- [+15] Reply-To domain (fn-account-services.example) differs from From domain (firstnational.example)
- [+30] Link text shows 'https://www.firstnational.example/login' but points to
        http://firstnational.example.verify-login-portal.example/session/9f2c
- [+10] Urgency/pressure language detected: 'URGENT'
- [+20] Attachment 'Invoice_88213.html' has a high-risk extension (.html)

## Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| Sender IP | 203.0.113.55 | first public hop in Received chain |
| URL | http://...verify-login-portal.example/session/9f2c | ⚠ display text mismatch |
| Attachment SHA256 | 9f4593bdbfd9d72efcab6767b0b97639a95... | Invoice_88213.html |

## Recommended Action

**Quarantine immediately.** Purge from all recipient mailboxes, block the
sender IP/domain and listed URLs at the gateway...
```

## Verdict engine

Each rule that fires adds weighted points; the total maps to a verdict:

| Score | Verdict |
|-------|---------|
| ≥ 70 | Malicious |
| ≥ 35 | Suspicious |
| < 35 | Likely Benign |

Weights and thresholds are configurable under `scoring:` in `config.yaml`
(see `config.example.yaml` for all knobs and defaults). Rules cover email
authentication failures (SPF/DKIM/DMARC), Reply-To divergence, link
display-text spoofing, urgency language, high-risk attachment extensions,
and threat-intel hits from VirusTotal/AbuseIPDB. Confidence is reported
separately: verdicts corroborated by external intel are High-confidence,
heuristics-only verdicts are Medium/Low.

## Test samples

### Synthetic (all domains are `.example`, all IPs are RFC 5737 documentation
ranges — nothing resolves to real hosts):

| File | Offline verdict | What it demonstrates |
|------|-----------------|----------------------|
| `phish_invoice.eml` | Malicious (140) | full auth failure, Reply-To divergence, link mismatch, urgency lure, risky attachment |
| `eicar_attachment.eml` | Malicious (80) | fake courier lure carrying the harmless [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) as `shipping_label.exe` — with API keys, VirusTotal flags its hash, exercising the intel scoring path |
| `suspicious_password_reset.eml` | Suspicious (50) | SPF softfail + DKIM fail + urgency, but no smoking gun |
| `bec_wire_transfer.eml` | Suspicious (50) | CEO-fraud / BEC: spoofed exec display name, Reply-To diverted to webmail, urgency — no links or attachments at all |
| `benign_newsletter.eml` | Likely Benign (0) | clean auth, honest links |

### Real-world (from the public [phishing_pot](https://github.com/rf-peixoto/phishing_pot)
corpus of genuine phishing emails — recipient details sanitized by the corpus
maintainer, but sender infrastructure, URLs, and lures are real; **do not
visit any URL in these files**):

| File | Lure | Why it's interesting |
|------|------|----------------------|
| `real_phish_1.eml` | credential phish | passes SPF (throwaway sending domain) — heuristics alone score it low; VirusTotal enrichment is what catches it |
| `real_phish_2.eml` | fake Microsoft sign-in alert | no web URLs at all — every link is `mailto:` to a scammer's mailbox (reply-based scam) |
| `real_phish_3.eml` | credential phish | authenticated sending infrastructure with a malicious payload URL |
| `real_phish_4.eml` | advance-fee "donation" scam | pure social engineering, zero technical IOCs beyond headers |

The real samples show an honest limitation: offline heuristics catch spoofing
and header tricks, but well-run phishing campaigns authenticate correctly —
that is exactly why the enrichment stage exists.
