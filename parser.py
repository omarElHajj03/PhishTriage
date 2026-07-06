"""
parser.py — .eml file parsing.

Responsible for ONE thing: turning a raw .eml file into a structured
ParsedEmail object using only the Python standard library (email package).
No analysis happens here — extraction and scoring live in later stages.

Key stdlib pieces used:
  * email.parser.BytesParser with policy.default — gives us the modern
    EmailMessage API (get_body, iter_attachments, sane header decoding).
  * EmailMessage.walk()/get_body() — handles multipart MIME trees for us.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path


@dataclass
class Attachment:
    """A single decoded attachment."""
    filename: str
    content_type: str
    data: bytes  # raw decoded bytes — hashed later in extractor.py

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class ParsedEmail:
    """Structured view of one .eml file. Everything downstream reads this."""
    path: str
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    reply_to: str = ""
    date: str = ""
    message_id: str = ""
    # Received headers in the order they appear in the file:
    # index 0 = most recent hop (our server), last = closest to the sender.
    received: list[str] = field(default_factory=list)
    # Authentication-Results / Received-SPF headers (SPF/DKIM/DMARC verdicts).
    auth_results: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    attachments: list[Attachment] = field(default_factory=list)


def parse_eml(path: str | Path) -> ParsedEmail:
    """Parse an .eml file from disk into a ParsedEmail."""
    path = Path(path)
    with path.open("rb") as fh:
        # policy.default (not the legacy compat32) gives us EmailMessage
        # with automatic RFC 2047 header decoding and charset handling.
        msg: EmailMessage = BytesParser(policy=policy.default).parse(fh)

    parsed = ParsedEmail(
        path=str(path),
        subject=str(msg.get("Subject", "")),
        from_addr=str(msg.get("From", "")),
        to_addr=str(msg.get("To", "")),
        reply_to=str(msg.get("Reply-To", "")),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")),
        received=[str(h) for h in msg.get_all("Received", [])],
        auth_results=(
            [str(h) for h in msg.get_all("Authentication-Results", [])]
            + [str(h) for h in msg.get_all("Received-SPF", [])]
        ),
    )

    _extract_bodies(msg, parsed)
    _extract_attachments(msg, parsed)
    return parsed


def _extract_bodies(msg: EmailMessage, parsed: ParsedEmail) -> None:
    """Pull out the text/plain and text/html bodies (either may be absent)."""
    # get_body() walks the MIME tree and picks the best candidate for us.
    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    if plain is not None:
        parsed.body_text = plain.get_content()
    if html is not None:
        parsed.body_html = html.get_content()


def _extract_attachments(msg: EmailMessage, parsed: ParsedEmail) -> None:
    """Decode every attachment part into an Attachment object."""
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)  # base64/qp decoded bytes
        if payload is None:
            continue
        parsed.attachments.append(
            Attachment(
                filename=part.get_filename() or "(unnamed)",
                content_type=part.get_content_type(),
                data=payload,
            )
        )
