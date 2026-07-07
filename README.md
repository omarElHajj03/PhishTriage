# PhishTriage

**Automated first-pass triage for reported phishing emails.**

In a SOC, user-reported phishing is a high-volume, repetitive queue: open
the `.eml`, read the headers, chase every link, hash every attachment,
paste indicators into VirusTotal and AbuseIPDB, then write up a verdict.
PhishTriage automates that first pass. Feed it a raw `.eml` file and it
parses the message, extracts indicators of compromise (IOCs), enriches
them against threat-intel APIs, scores everything through a transparent
rules engine, and writes an analyst-ready Markdown report — verdict,
evidence, and recommended action.

The verdict engine is deliberately rules-based rather than ML: every
verdict lists exactly which rules fired and how many points each
contributed, so an analyst can audit (and override) the reasoning.

Python 3.11+. Email parsing uses only the standard library.

## Architecture

Five modules, one job each. Data flows strictly left to right — no stage
reaches back — so each module can be understood and tested in isolation:

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
| `parser.py` | `.eml` → structured object (stdlib `email` with `policy.default`); headers, Received chain, text/HTML bodies, decoded attachments |
| `extractor.py` | Sender IP (first public hop, walking the Received chain bottom-up), URLs from both bodies (including href vs. anchor-text mismatch detection), SHA256 per attachment, SPF/DKIM/DMARC verdicts |
| `enrich.py` | VirusTotal (URLs, hashes) + AbuseIPDB (IPs) with free-tier rate-limit handling; degrades to offline mode when keys are absent |
| `scoring.py` | Weighted rules → Malicious / Suspicious / Likely Benign, with every fired rule listed as a reason; weights and thresholds configurable |
| `report.py` | Renders the Markdown report — pure formatting, so layout changes can never alter a verdict |

## Setup

```bash
git clone <your-repo-url>
cd phishtriage
pip install -r requirements.txt
```

### API keys (optional but recommended)

```bash
cp config.example.yaml config.yaml
# then edit config.yaml and add YOUR OWN keys
```

Get free keys here:

- **VirusTotal** (4 lookups/minute): https://www.virustotal.com/gui/my-apikey
- **AbuseIPDB** (1,000 checks/day): https://www.abuseipdb.com/account/api

> ⚠️ **Never commit `config.yaml`.** It holds real API keys and is listed
> in `.gitignore` for exactly that reason. Only the empty template
> `config.example.yaml` belongs in the repo. If a key ever leaks into a
> commit, revoke and reissue it — removing the commit is not enough.

Without keys, PhishTriage still runs in **offline mode**: full parsing,
IOC extraction, and heuristic scoring — just no threat-intel lookups.

## Usage

```bash
python main.py path/to/email.eml               # writes email_report.md
python main.py mail.eml -o triage.md           # custom report path
python main.py mail.eml --offline              # skip API lookups
python main.py mail.eml --config other.yaml    # non-default config
```

## Example: a real phish, and the scoring bug it exposed

`samples/real_phish_1.eml` is a genuine Brazilian-bank credential phish
(from the public [phishing_pot](https://github.com/rf-peixoto/phishing_pot)
corpus): display name **"BANCO DO BRADESCO LIVELO"**, sender domain
`atendimento.com.br`, linking to `blog1seguimentmydomaine2bra.me`.

**Before:** the first version of the verdict engine scored it **0 — Likely
Benign**. Three misses stacked up:

1. Its SPF/DKIM/DMARC results were `temperror`/`none` — the engine only
   scored explicit `fail` values, so "couldn't verify" earned zero points.
2. Nothing compared the claimed brand in the display name against the
   actual sender domain.
3. The campaign URL had aged out of VirusTotal (0 detections), so
   enrichment stayed silent too.

**After** adding partial points for unverified auth states, a
brand-impersonation rule, and an abused-TLD rule, the same email scores
**61 — Suspicious**:

```markdown
### Why

- [+10] SPF not verified (temperror) — sender domain publishes no usable SPF record
- [+8]  DKIM not verified (none) — message carries no valid signature
- [+8]  DMARC not verified (temperror) — From domain publishes no DMARC policy
- [+25] Display name claims 'bradesco' but From domain is atendimento.com.br
        — likely brand impersonation
- [+10] Link domain blog1seguimentmydomaine2bra.me uses .me, a TLD heavily
        abused by phishing campaigns
```

The clean control sample (`benign_newsletter.eml`, valid SPF/DKIM/DMARC,
honest links) still scores exactly 0 — the fix added recall without
adding false positives.

## Verdict engine

Each fired rule adds weighted points; the total maps to a verdict:

| Score | Verdict |
|-------|---------|
| ≥ 70 | Malicious |
| ≥ 35 | Suspicious |
| < 35 | Likely Benign |

Rules cover: SPF/DKIM/DMARC failures (with partial points for
unverified `none`/`temperror` states), Reply-To divergence, brand
impersonation, link display-text spoofing, frequently-abused TLDs,
urgency language, high-risk attachment extensions, and VirusTotal /
AbuseIPDB hits. All weights, both thresholds, and the brand watchlist
are overridable under `scoring:` in `config.yaml` (see
`config.example.yaml`). Confidence is reported separately — verdicts
corroborated by external intel rate High; heuristics-only verdicts
rate Medium/Low.

## Test samples

**Synthetic** (`.example` domains, RFC 5737 documentation IPs — nothing
resolves to a real host):

| File | Offline verdict | Demonstrates |
|------|-----------------|--------------|
| `phish_invoice.eml` | Malicious (140) | full auth failure, Reply-To divergence, link mismatch, urgency, risky attachment |
| `eicar_attachment.eml` | Malicious (88) | courier lure carrying the harmless [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) — with API keys, VirusTotal flags its hash |
| `bec_wire_transfer.eml` | Suspicious (66) | CEO wire fraud: no links or attachments at all |
| `suspicious_password_reset.eml` | Suspicious (58) | SPF softfail + DKIM fail + urgency |
| `benign_newsletter.eml` | Likely Benign (0) | clean control — new rules must keep this at 0 |

**Real-world**, from the public
[phishing_pot](https://github.com/rf-peixoto/phishing_pot) corpus
(recipients sanitized by the corpus maintainer, but sender infrastructure
and URLs are real — **do not visit any URL in these files**):

| File | Lure | Why it's interesting |
|------|------|----------------------|
| `real_phish_1.eml` | Bradesco bank credential phish | the before/after example above |
| `real_phish_2.eml` | fake Microsoft sign-in alert | no web URLs — every link is `mailto:` to the scammer (reply-based scam) |
| `real_phish_3.eml` | credential phish | authenticated sending infrastructure, malicious payload URL |
| `real_phish_4.eml` | advance-fee "donation" scam | pure social engineering, minimal technical IOCs |

Note: Windows Defender may quarantine `eicar_attachment.eml` — detecting
EICAR is exactly what it is designed to do. Restore it from quarantine or
`git checkout -- samples/` if it disappears.

## Rate limits

Free-tier VirusTotal allows 4 lookups/minute, so PhishTriage spaces VT
calls ~15 seconds apart and backs off for 60s on an HTTP 429. An email
with many URLs and attachments can take several minutes to enrich —
that's the API quota, not the tool. Use `--offline` for instant
heuristic-only triage.
