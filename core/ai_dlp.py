"""ai-dlp: mitmproxy addon that redacts secrets from requests sent to AI services.

Works the same on Linux, macOS and Windows; only how traffic reaches it differs
(Linux: nftables redirect; macOS/Windows: mitmproxy local capture mode).

Every outgoing HTTPS connection from user programs reaches this addon. The decision is made by domain name, not by
IP address: when a connection's TLS ClientHello names a domain listed in
DOMAINS_FILE (or a subdomain of one), it is decrypted and inspected; every other
connection is passed through as raw bytes, never decrypted or recorded. So an
AI service changing its IP addresses changes nothing, and a new service is
covered by adding its domain to the list. Each inspected request body is checked for:

  1. exact secret values listed in SECRETS_FILE (one per line), and
  2. anything gitleaks finds, using its default rule set plus the extra rules in
     GITLEAKS_CONFIG (gitleaks `[extend] useDefault = true` format).

JSON bodies are parsed and every string in them is scanned on its own (with real
newlines, as gitleaks expects); results are cached per string, so the unchanged
conversation history Claude Code resends every turn is not rescanned.

Every match is replaced with "[REDACTED:<rule-id>]" before the request leaves the
machine. If a body cannot be scanned (gitleaks error, undecodable encoding, or a
finding that cannot be located, e.g. an encoded secret), the request is blocked
instead: nothing unscanned is ever forwarded. Secret values are never logged.

Images, PDFs and other files sent to Anthropic cannot be scanned for text, so
they are flagged instead: each one is recorded in the event log ("attachments")
the first time it is sent. Claude Code resends the whole conversation every
turn, so already-seen attachments are not flagged again.

A request with the header "x-ai-dlp-echo: 1" is answered locally with the
redacted body and never forwarded (used by `ai-dlp test`).
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import json
import logging
import math
import os
import shutil
import sys
import tempfile
import time
from collections import Counter, OrderedDict
from pathlib import Path
import socket
from urllib.parse import quote, quote_plus, unquote_plus, urlsplit

import re

try:
    from mitmproxy import http
except ImportError:  # allows unit-testing without mitmproxy installed
    http = None

def _default_dirs() -> tuple[Path, Path]:
    """(config dir, log dir) for this platform; AI_DLP_CONFIG_DIR / AI_DLP_LOG_DIR override."""
    if sys.platform == "darwin":
        conf, logs = Path("/Library/Application Support/ai-dlp"), Path("/Library/Logs/ai-dlp")
    elif os.name == "nt":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ai-dlp"
        conf, logs = base, base / "logs"
    else:
        conf, logs = Path("/etc/ai-dlp"), Path("/var/log/ai-dlp")
    return (Path(os.environ.get("AI_DLP_CONFIG_DIR", conf)), Path(os.environ.get("AI_DLP_LOG_DIR", logs)))


CONFIG_DIR, LOG_DIR = _default_dirs()
# On Windows the list lives in the state folder, whose ACL admits only SYSTEM and
# Administrators (the config folder is readable by all users).
SECRETS_FILE = Path(os.environ.get(
    "AI_DLP_SECRETS", CONFIG_DIR / "state" / "secrets.txt" if os.name == "nt" else CONFIG_DIR / "secrets.txt"))
GITLEAKS_CONFIG = Path(os.environ.get("AI_DLP_GITLEAKS_CONFIG", CONFIG_DIR / "gitleaks.toml"))
# The gitleaks command (a list, so tests can run a script through the interpreter).
GITLEAKS_CMD = [os.environ.get("AI_DLP_GITLEAKS") or shutil.which("gitleaks") or "gitleaks"]
GITLEAKS_TIMEOUT = 120
GITLEAKS_CHUNK = 400_000      # characters per gitleaks run; big requests are split and run in parallel
GITLEAKS_PARALLEL = 4         # gitleaks processes at once, across all requests
# Shortest secret value that is matched exactly. Values shorter than SHORT_LEN only
# match as whole words, so a 4-character password does not redact every word that
# happens to contain it.
MIN_LEN = 4
SHORT_LEN = 8
CACHE_SIZE = 50_000
# Domains (and their subdomains) whose traffic is decrypted and inspected, one per
# line. Everything else passes through untouched. Reloaded when the file changes.
DOMAINS_FILE = Path(os.environ.get("AI_DLP_DOMAINS", CONFIG_DIR / "domains.txt"))
DEFAULT_DOMAINS = ("anthropic.com", "claude.ai", "claude.com")
# The CA only vouches for the names it was created with (installer: from the same
# list). A listed domain the CA does not cover is NOT intercepted, or the site would
# fail to load; it is passed through and a warning tells you to re-run the installer.
CA_FILE = Path(os.environ.get("AI_DLP_CA", CONFIG_DIR / "ca.pem"))
_DOMAIN_RX = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ECHO_HEADER = "x-ai-dlp-echo"
# One JSON line per request (action, host, path, rule names/counts; never values),
# read by the Omarchy bar widget. Rotated to events.jsonl.1 past EVENTS_MAX_BYTES.
EVENTS_FILE = Path(os.environ.get("AI_DLP_EVENTS", LOG_DIR / "events.jsonl"))
EVENTS_MAX_BYTES = 5_000_000

log = logging.getLogger("ai-dlp")


class ScanError(Exception):
    """The body could not be scanned reliably; the request must be blocked."""


def placeholder(rule: str) -> bytes:
    return b"[REDACTED:" + rule.encode() + b"]"


def encodings(value: str) -> list[bytes]:
    """The ways a string can appear in a raw body: as-is, JSON-escaped, percent-encoded."""
    forms = {value, json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value, ensure_ascii=True)[1:-1],
             quote(value, safe=""), quote_plus(value, safe="")}
    return [f.encode("utf-8", errors="surrogateescape") for f in forms]


def _entries(text: str, relay: bool, warn=None) -> tuple[str, ...]:
    found = []
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if not entry:
            continue
        is_relay = entry.startswith("relay ")
        if is_relay:
            entry = entry[len("relay "):].strip()
        entry = entry.rstrip(".")
        if is_relay != relay:
            continue
        if _DOMAIN_RX.match(entry):
            found.append(entry)
        elif warn:
            warn(entry)
    return tuple(dict.fromkeys(found))


def parse_domains(text: str, warn=None) -> tuple[str, ...]:
    """Domains to inspect, from a domains.txt text: one per line, '#' comments, lowercased."""
    return _entries(text, relay=False, warn=warn)


def parse_relay(text: str, warn=None) -> tuple[str, ...]:
    """Domains to relay ("relay <domain>" lines): decrypted with a certificate for the exact
    site only, then passed on without inspection or logging. Used for sites whose real
    certificates also cover an inspected domain (Google's *.google.com covers Gemini), so a
    browser cannot send inspected traffic over a connection opened to one of them."""
    return _entries(text, relay=True, warn=warn)


def ca_domains(text: str) -> tuple[str, ...]:
    """Every domain the CA must cover: inspected and relayed."""
    return tuple(dict.fromkeys(parse_domains(text) + parse_relay(text)))


def _covered(domain: str, names) -> bool:
    return any(domain == n or domain.endswith("." + n) for n in names)


def ca_permitted_names(path: Path) -> tuple[str, ...] | None:
    """DNS names the CA may vouch for (its name constraints); None = unknown/unrestricted."""
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except Exception:
        return None
    return tuple(t.value.lower().lstrip(".") for t in (nc.permitted_subtrees or []) if isinstance(t, x509.DNSName))


class DomainList:
    """Domains to inspect, from DOMAINS_FILE (a missing file means DEFAULT_DOMAINS),
    limited to those the CA in CA_FILE covers."""

    def __init__(self, path: Path, ca_path: Path = CA_FILE):
        self.path, self.ca_path = path, ca_path
        self._stamp: tuple | None = None
        self.domains: tuple[str, ...] = DEFAULT_DOMAINS
        self.relay: tuple[str, ...] = ()
        self.uncovered: tuple[str, ...] = ()

    @staticmethod
    def _mtime(path: Path) -> float | None:
        try:
            return path.stat().st_mtime
        except OSError:
            return None

    def _listed(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if self._mtime(self.path) is None:
            return DEFAULT_DOMAINS, ()
        text = self.path.read_text(encoding="utf-8", errors="replace")
        warn = lambda e: log.warning("ai-dlp: ignoring invalid domain %r in %s", e[:80], self.path)  # noqa: E731
        return parse_domains(text, warn), parse_relay(text, warn)

    def current(self) -> tuple[str, ...]:
        stamp = (self._mtime(self.path), self._mtime(self.ca_path))
        if stamp != self._stamp:
            self._stamp = stamp
            listed, relay = self._listed()
            permitted = ca_permitted_names(self.ca_path)
            if permitted is None:
                self.domains, self.relay, self.uncovered = listed, relay, ()
            else:
                self.domains = tuple(d for d in listed if _covered(d, permitted))
                self.relay = tuple(d for d in relay if _covered(d, permitted))
                self.uncovered = tuple(d for d in listed + relay if not _covered(d, permitted))
            log.info("ai-dlp: inspecting %d domain(s): %s", len(self.domains), ", ".join(self.domains))
            if self.uncovered:
                log.warning("ai-dlp: NOT inspecting %s: the CA does not cover them yet; "
                            "run the ai-dlp installer again to issue a matching CA",
                            ", ".join(self.uncovered))
        return self.domains

    def matches(self, host: str | None) -> bool:
        if not host:
            return False
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.current())

    def relayed(self, host: str | None) -> bool:
        if not host:
            return False
        self.current()
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.relay)


class SecretList:
    """Exact secret values, reloaded whenever the file changes."""

    def __init__(self, path: Path):
        self.path = path
        self._mtime: float | None = None
        self.values: list[str] = []

    def current(self) -> list[str]:
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            self._mtime, self.values = None, []
            return self.values
        if mtime != self._mtime:
            self._mtime = mtime
            text = self.path.read_text(encoding="utf-8", errors="surrogateescape")
            self.values = sorted({l for l in text.splitlines() if len(l) >= MIN_LEN}, key=len, reverse=True)
            log.info("ai-dlp: loaded %d known secret(s)", len(self.values))
        return self.values


class Gitleaks:
    """Runs `gitleaks stdin` on batches of strings, caching findings per string."""

    def __init__(self, cmd: list[str] | None = None, config: Path | None = None):
        self.cmd = list(cmd or GITLEAKS_CMD)
        self.config = config or GITLEAKS_CONFIG
        self.cache: OrderedDict[bytes, list[tuple[str, str]]] = OrderedDict()
        self._limit: asyncio.Semaphore | None = None
        self._config_mtime: float | None = None

    def _check_config(self) -> None:
        mtime = self.config.stat().st_mtime if self.config.exists() else None
        if mtime != self._config_mtime:  # rules changed: old results are stale
            self._config_mtime = mtime
            self.cache.clear()

    async def run(self, data: str) -> list[tuple[str, str, str]]:
        """Return (rule id, secret, match) for every finding in data."""
        with tempfile.TemporaryDirectory(prefix="ai-dlp-") as tmp:
            report = Path(tmp) / "report.json"
            cmd = [*self.cmd, "stdin", "--no-banner", "--log-level", "error", "--exit-code", "0",
                   "--report-format", "json", "--report-path", str(report)]
            if self.config.exists():
                cmd += ["--config", str(self.config)]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE)
            try:
                _, err = await asyncio.wait_for(
                    proc.communicate(data.encode("utf-8", errors="surrogateescape")), GITLEAKS_TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                raise ScanError("gitleaks timed out")
            if proc.returncode != 0:
                raise ScanError(f"gitleaks exited {proc.returncode}: {err.decode(errors='replace')[:300]}")
            raw = report.read_text(encoding="utf-8", errors="replace") if report.exists() else ""
        findings = json.loads(raw) if raw.strip() else []
        return [(f.get("RuleID", "secret"), f.get("Secret") or "", f.get("Match") or "") for f in findings]

    async def scan(self, texts: list[str]) -> list[tuple[str, str]]:
        """Return the unique (rule id, literal secret text) found across texts."""
        self._check_config()
        keyed = {hashlib.sha256(t.encode("utf-8", errors="surrogateescape")).digest(): t for t in texts}
        # Results already cached are taken now: the cache can change while this scan waits
        # (other requests evict entries; a rules change clears it).
        known = {k: self.cache[k] for k in keyed if k in self.cache}
        pending = {k: t for k, t in keyed.items() if k not in known}
        if pending:
            found = await self._run_chunked(list(pending.values()))
            per_text: dict[bytes, list[tuple[str, str]]] = {k: [] for k in pending}
            for rule, secret, match in found:
                located = False
                for candidate in (secret, match):  # the secret group, else the whole match
                    if not candidate:
                        continue
                    for k, t in pending.items():
                        if candidate in t:
                            per_text[k].append((rule, candidate))
                            located = True
                    if located:
                        break
                if not located:
                    raise ScanError(f"gitleaks finding '{rule}' could not be located (encoded secret?)")
            for k, hits in per_text.items():
                self.cache[k] = hits
                known[k] = hits
            while len(self.cache) > CACHE_SIZE:
                self.cache.popitem(last=False)
        results = set()
        for k in keyed:
            if k in self.cache:
                self.cache.move_to_end(k)
            results.update(known[k])
        return sorted(results, key=lambda rs: len(rs[1]), reverse=True)

    async def _run_chunked(self, texts: list[str]) -> list[tuple[str, str, str]]:
        """Run gitleaks over texts in chunks of about GITLEAKS_CHUNK characters, several at
        once (at most GITLEAKS_PARALLEL processes across all requests)."""
        if self._limit is None:
            self._limit = asyncio.Semaphore(GITLEAKS_PARALLEL)
        chunks, cur, size = [], [], 0
        for t in texts:
            if cur and size + len(t) > GITLEAKS_CHUNK:
                chunks.append(cur)
                cur, size = [], 0
            cur.append(t)
            size += len(t) + 2
        if cur:
            chunks.append(cur)

        async def one(chunk):
            async with self._limit:
                return await self.run("\n\n".join(chunk))
        found = []
        for part in await asyncio.gather(*(one(c) for c in chunks)):
            found += part
        return found


# JSON-schema limit keywords. Inside the request's top-level "tools" (tool definitions)
# their numbers are bounds, not data: not scanned or rewritten, so redaction cannot turn a
# schema's "maximum" into a string. Everywhere else, and for data keywords such as
# default/const/enum/examples, numbers are scanned as usual.
_SCHEMA_NUMBER_KEYS = frozenset({
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength",
    "maxLength", "minItems", "maxItems", "minProperties", "maxProperties", "minContains",
    "maxContains",
})


class _Pairs(list):
    """A JSON object as the full list of its (key, value) pairs, duplicates included."""


_B64_RX = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def _is_base64(data: str) -> bool:
    return len(data) % 4 == 0 and _B64_RX.fullmatch(data) is not None


_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"%PDF-")


def _is_image_or_pdf(head: bytes) -> bool:
    """True if the bytes really start like a PNG, JPEG, GIF, WebP or PDF file."""
    return head.startswith(_MAGIC) or (head[:4] == b"RIFF" and head[8:12] == b"WEBP")


_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{8,}")


def _readable_runs(raw: bytes) -> str:
    """The readable ASCII runs in binary data (like `strings`): text hidden inside or
    appended to an image or PDF is scanned this way."""
    return "\n".join(m.group().decode("ascii") for m in _PRINTABLE_RUN.finditer(raw))


# Images and PDFs found while parsing a body, for OCR (set by redact()).
_MEDIA: contextvars.ContextVar[list[bytes] | None] = contextvars.ContextVar("ai_dlp_media", default=None)
# Notes about the request for the event log (content sent unscanned, files removed, ...).
_NOTES: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar("ai_dlp_notes", default=None)


def _note(text: str) -> None:
    notes = _NOTES.get()
    if notes is not None and text not in notes and len(notes) < 20:
        notes.append(text[:200])

OCR_MAX_BYTES = 25_000_000
OCR_MAX_PAGES = 20          # PDF pages OCR'd per document (text-less pages and pages with images)
OCR_MAX_PIXELS = 40_000_000 # larger images are refused rather than OCR'd
OCR_DPI = 200               # PDF pages are rendered at this resolution, never shrunk to fit
OCR_MAX_PDF_IMAGES = 50     # embedded images OCR'd (at native resolution) per PDF
OCR_TIMEOUT = 60            # seconds per tool run
OCR_REQUEST_DEADLINE = 180  # seconds of OCR per request, in total
OCR_MAX_ITEMS = 20          # new (not cached) images/PDFs OCR'd per request
OCR_MEMORY = 2 << 30        # address-space limit for OCR tools (POSIX)
OCR_FILE_SIZE = 512 << 20   # largest file an OCR tool may write (POSIX)
OCR_CACHE = 2_000


def image_size(raw: bytes) -> tuple[int, int] | None:
    """(width, height) from a PNG, GIF, JPEG or WebP header, or None if not recognised."""
    if raw.startswith(b"\x89PNG\r\n\x1a\n") and raw[12:16] == b"IHDR":
        return int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return int.from_bytes(raw[6:8], "little"), int.from_bytes(raw[8:10], "little")
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        chunk = raw[12:16]
        if chunk == b"VP8X":
            return 1 + int.from_bytes(raw[24:27], "little"), 1 + int.from_bytes(raw[27:30], "little")
        if chunk == b"VP8L":
            b = int.from_bytes(raw[21:25], "little")
            return 1 + (b & 0x3FFF), 1 + ((b >> 14) & 0x3FFF)
        if chunk == b"VP8 ":
            return int.from_bytes(raw[26:28], "little") & 0x3FFF, int.from_bytes(raw[28:30], "little") & 0x3FFF
    if raw[:2] == b"\xff\xd8":  # JPEG: walk segments to a start-of-frame marker
        i = 2
        while i + 9 < len(raw):
            if raw[i] != 0xFF:
                i += 1
                continue
            marker = raw[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            length = int.from_bytes(raw[i + 2:i + 4], "big")
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                return int.from_bytes(raw[i + 7:i + 9], "big"), int.from_bytes(raw[i + 5:i + 7], "big")
            i += 2 + length
    return None


def image_listing(listing: str) -> list[tuple[int, int, int]]:
    """(page, width, height) of every embedded image, from `pdfimages -list` output."""
    images = []
    for line in listing.splitlines()[2:]:  # two header lines
        cols = line.split()
        if len(cols) >= 5 and cols[0].isdigit() and cols[3].isdigit() and cols[4].isdigit():
            images.append((int(cols[0]), int(cols[3]), int(cols[4])))
    return images


def pages_with_images(listing: str) -> set[int]:
    """Page numbers that embed images, from `pdfimages -list` output."""
    return {page for page, _, _ in image_listing(listing)}


def page_sizes(pdfinfo_output: str) -> dict[int, tuple[float, float]]:
    """{page: (width, height) in points as rendered} from `pdfinfo -box -f 1 -l N` output.

    Takes the larger of the MediaBox and CropBox in each direction (whichever box a
    renderer uses, the page fits) and swaps the sides for pages rotated 90 or 270 degrees.
    """
    boxes: dict[int, list[tuple[float, float]]] = {}
    rot: dict[int, int] = {}
    for m in re.finditer(r"^Page\s+(\d+)\s+(MediaBox|CropBox):\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)",
                         pdfinfo_output, re.M):
        x1, y1, x2, y2 = (float(m.group(i)) for i in range(3, 7))
        boxes.setdefault(int(m.group(1)), []).append((abs(x2 - x1), abs(y2 - y1)))
    for m in re.finditer(r"^Page\s+(\d+)\s+rot:\s+(-?\d+)", pdfinfo_output, re.M):
        rot[int(m.group(1))] = int(m.group(2)) % 360
    sizes = {}
    for page, dims in boxes.items():
        w, h = max(d[0] for d in dims), max(d[1] for d in dims)
        sizes[page] = (h, w) if rot.get(page) in (90, 270) else (w, h)
    return sizes


def _limit_resources() -> None:  # runs in the OCR tool's process before exec (POSIX)
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (OCR_MEMORY, OCR_MEMORY))
    resource.setrlimit(resource.RLIMIT_FSIZE, (OCR_FILE_SIZE, OCR_FILE_SIZE))


class OCR:
    """Text inside images and PDFs: pdftotext for a PDF's text layer, tesseract for images
    and for PDF pages that have no text layer (scans). Results are cached per file, so
    the history an agent resends every turn is not OCR'd again. If the tools are not
    installed, OCR is skipped and only the readable-text scan applies.
    """

    def __init__(self) -> None:
        self.tesseract = shutil.which("tesseract")
        self.pdftotext = shutil.which("pdftotext")
        self.pdftoppm = shutil.which("pdftoppm")
        self.pdfimages = shutil.which("pdfimages")
        self.pdfinfo = shutil.which("pdfinfo")
        self.cache: OrderedDict[bytes, str] = OrderedDict()
        if not self.tesseract:
            log.info("ai-dlp: tesseract not found; images and PDFs get the readable-text scan only")

    @property
    def available(self) -> bool:
        return bool(self.tesseract)

    async def _run(self, cmd: list[str], data: bytes | None) -> bytes:
        extra = {"preexec_fn": _limit_resources} if os.name == "posix" else {}
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE if data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, **extra)
        try:
            out, err = await asyncio.wait_for(proc.communicate(data), OCR_TIMEOUT)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            proc.kill()
            await proc.wait()
            raise ScanError(f"{Path(cmd[0]).name} timed out reading an image or PDF")
        if proc.returncode != 0:
            raise ScanError(f"{Path(cmd[0]).name} could not read an image or PDF: "
                            f"{err.decode(errors='replace').strip()[:160]}")
        return out

    async def _image(self, raw: bytes) -> str:
        size = image_size(raw)
        if size and size[0] * size[1] > OCR_MAX_PIXELS:
            raise ScanError(f"image of {size[0]}x{size[1]} pixels is too large to check for secrets")
        return (await self._run([self.tesseract, "stdin", "stdout", "-l", "eng"], raw)).decode("utf-8", "replace")

    async def _pdf(self, raw: bytes) -> str:
        if not (self.pdftotext and self.pdftoppm and self.pdfimages and self.pdfinfo):
            raise ScanError("PDF text cannot be checked: poppler (pdftotext, pdftoppm, pdfimages, pdfinfo) "
                            "is not installed")
        with tempfile.TemporaryDirectory(prefix="ai-dlp-ocr-") as tmp:
            src = Path(tmp) / "in.pdf"
            src.write_bytes(raw)
            text = (await self._run([self.pdftotext, "-layout", str(src), "-"], None)).decode("utf-8", "replace")
            pages = text.split("\f")
            if pages and not pages[-1].strip():
                pages = pages[:-1]
            # OCR every page without a text layer (scans) AND every page that embeds an
            # image (a screenshot inside a text document), whatever its text layer says.
            listing = (await self._run([self.pdfimages, "-list", str(src)], None)).decode("utf-8", "replace")
            embedded = image_listing(listing)
            # Refuse before extracting anything: too many images, or any image too large.
            if len(embedded) > OCR_MAX_PDF_IMAGES:
                raise ScanError(f"PDF embeds {len(embedded)} images; at most {OCR_MAX_PDF_IMAGES} are checked")
            for page, w, h in embedded:
                if w * h > OCR_MAX_PIXELS:
                    raise ScanError(f"PDF page {page} embeds a {w}x{h} image, too large to check for secrets")
            need = {n for n, page in enumerate(pages, 1) if len(page.strip()) < 20} | pages_with_images(listing)
            if len(need) > OCR_MAX_PAGES:
                raise ScanError(f"PDF has {len(need)} pages with images or without text; OCR is limited "
                                f"to {OCR_MAX_PAGES}")
            parts = [text]
            if need:
                info = (await self._run([self.pdfinfo, "-box", "-f", "1", "-l", str(max(need)), str(src)], None))
                sizes = page_sizes(info.decode("utf-8", "replace"))
            for n in sorted(need):
                # Rendered at a fixed resolution (never shrunk, which could make small text
                # unreadable); a page too large at that resolution is refused instead.
                w, h = sizes.get(n, (0, 0))
                wpx, hpx = math.ceil(w / 72 * OCR_DPI), math.ceil(h / 72 * OCR_DPI)
                if not wpx or not hpx or wpx * hpx > OCR_MAX_PIXELS:
                    raise ScanError(f"PDF page {n} is too large to check for secrets at {OCR_DPI} dpi")
                out = Path(tmp) / f"p{n}"
                # The full page (MediaBox), so content outside the CropBox is read too; -W/-H
                # cap the output at the size just checked (the larger box), whatever the file claims.
                await self._run([self.pdftoppm, "-f", str(n), "-l", str(n), "-r", str(OCR_DPI),
                                 "-x", "0", "-y", "0", "-W", str(wpx), "-H", str(hpx),
                                 "-png", "-singlefile", str(src), str(out)], None)
                parts.append(await self._image(out.with_suffix(".png").read_bytes()))
            # Embedded images at their native resolution too, so a high-resolution
            # screenshot is read in full detail rather than as it appears on the page.
            images = Path(tmp) / "images"
            images.mkdir()
            await self._run([self.pdfimages, "-png", str(src), str(images / "img")], None)
            extracted = sorted(images.iterdir())
            if len(extracted) > OCR_MAX_PDF_IMAGES:
                raise ScanError(f"PDF embeds {len(extracted)} images; at most {OCR_MAX_PDF_IMAGES} are checked")
            for f in extracted:
                if f.suffix == ".png":
                    parts.append(await self._image(f.read_bytes()))
                else:  # formats pdfimages could not convert (e.g. JBIG2/CCITT as .pbm): unreadable here
                    raise ScanError(f"PDF embeds an image ({f.suffix}) that cannot be checked for secrets")
        return "\n".join(parts)

    def cached(self, raw: bytes) -> bool:
        return hashlib.sha256(raw).digest() in self.cache

    async def text_of(self, raw: bytes) -> str | None:
        if not self.available:
            return None
        key = hashlib.sha256(raw).digest()
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        if len(raw) > OCR_MAX_BYTES:
            raise ScanError(f"image or PDF of {len(raw) // 1_000_000} MB is too large to check for secrets")
        text = await (self._pdf(raw) if raw.startswith(b"%PDF-") else self._image(raw))
        self.cache[key] = text
        while len(self.cache) > OCR_CACHE:
            self.cache.popitem(last=False)
        return text


def _bytes_views(raw: bytes, media: str) -> list[str]:
    """Scannable text for decoded content, or ScanError if it cannot be scanned.

    Images and PDFs (recognised by their bytes, not the declared type): their readable
    text runs. Text: the text. Audio and video: nothing (flagged as attachments; voice
    features keep working). Any other binary content: ScanError, so the request is blocked.
    """
    media = (media or "").lower().split(";")[0].strip()
    if _is_image_or_pdf(raw[:16]):
        collected = _MEDIA.get()
        if collected is not None:  # redact() OCRs these after parsing
            collected.append(raw)
        return [_readable_runs(raw)]
    try:
        return [raw.decode("utf-8")]
    except UnicodeDecodeError:
        pass
    if media.startswith(("audio/", "video/")):
        return []
    _note(f"sent without being scanned: binary content ({media or 'unknown type'})")
    return []


def _multipart_views(body: bytes, content_type: str) -> list[str]:
    from email import policy
    from email.parser import BytesParser
    msg = BytesParser(policy=policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1", "replace") + b"\r\n\r\n" + body)
    if not msg.is_multipart():
        _note("malformed multipart body: scanned as plain text")
        return [body.decode("utf-8", errors="surrogateescape")]
    views = [body.decode("utf-8", errors="surrogateescape")]  # raw view, for rewriting
    for part in msg.walk():
        if part.is_multipart():
            continue
        views += _bytes_views(part.get_payload(decode=True) or b"", part.get_content_type())
    return views


def _numbers_only(value) -> bool:
    if isinstance(value, list):
        return all(_numbers_only(v) for v in value)
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def json_strings(obj, out: list[str], in_tools: bool = False, top: bool = True) -> None:
    """Collect every string in a parsed JSON document (objects as _Pairs).

    Every value of a duplicated key is collected: a server may read a different copy
    than Python's json would keep. Base64 payloads are decoded and scanned through
    _bytes_views (a finding inside one cannot be rewritten in place, so the request is
    then blocked); images and PDFs are also flagged as attachments.
    """
    if isinstance(obj, str):
        if len(obj) >= MIN_LEN:
            out.append(obj)
    elif isinstance(obj, int) and not isinstance(obj, bool):
        if obj >= 10 ** (MIN_LEN - 1):  # ID numbers sent as JSON numbers
            out.append(str(obj))
    elif isinstance(obj, _Pairs):
        keys = [k for k, _ in obj]
        unique = dict(obj) if len(set(keys)) == len(keys) else None
        payload = None
        if unique is not None and unique.get("type") == "base64" and isinstance(unique.get("data"), str):
            payload = unique["data"]
            media = str(unique.get("media_type", "")).lower()[:60]
            if _is_base64(payload):
                out.extend(_bytes_views(base64.b64decode(payload), media))
            else:
                payload = None  # not really base64: scan it like any other string
        for key, value in obj:
            if len(key) >= MIN_LEN:
                out.append(key)
            if payload is not None and key == "data":
                continue
            if in_tools and key in _SCHEMA_NUMBER_KEYS and _numbers_only(value):
                continue
            json_strings(value, out, in_tools or (top and key == "tools"), False)
    elif isinstance(obj, list):
        for item in obj:
            json_strings(item, out, in_tools, False)


def texts_of(body: bytes, content_type: str = "") -> list[str]:
    """Every text view of a request body that must be scanned (may raise ScanError)."""
    try:
        doc = json.loads(body, object_pairs_hook=_Pairs)
    except ValueError:
        if content_type.lower().startswith("multipart/"):
            return _multipart_views(body, content_type)
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:  # binary body
            return [body.decode("utf-8", errors="surrogateescape")] + _bytes_views(body, content_type)
        views = [text]
        if "%" in text or "+" in text:  # form bodies: scan the decoded view too
            decoded = unquote_plus(text)
            if decoded != text:
                views.append(decoded)
        return views
    out: list[str] = []
    json_strings(doc, out)
    return out


# In a raw JSON body the text "line\n1234" is stored as "line\\n1234": the escape ends in a
# letter. When rewriting raw bytes, a JSON escape right before a value counts as a boundary,
# exactly as the newline it stands for does in the decoded text that detection sees.
_ESCAPE_BEFORE = rb'(?<=\\[ntrbf/"\\])|(?<=\\u[0-9A-Fa-f]{4})'


def _word_rx(value: str | bytes):
    """Match value only where it is not part of a longer word (for short secrets)."""
    if isinstance(value, bytes):
        return re.compile(rb"(?:" + _ESCAPE_BEFORE + rb"|(?<![A-Za-z0-9]))" + re.escape(value) + rb"(?![A-Za-z0-9])")
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])")


# Labels ai-dlp writes into markers: "known-secret" plus every rule id gitleaks has
# reported (ids come from the rules, never from request content).
MARKER_LABELS: set[str] = {"known-secret", "url-password", "password-assignment"}


def is_own_marker(value: str) -> bool:
    """True if value is exactly a marker ai-dlp writes, e.g. [REDACTED:aws-access-token]
    echoed back in a conversation. Text merely shaped like one ([REDACTED:hunter2]) is not."""
    return (value.startswith("[REDACTED:") and value.endswith("]")
            and value[len("[REDACTED:"):-1] in MARKER_LABELS)


def _without_markers(text: str, labels) -> str:
    """Text with the markers ai-dlp itself inserted ([REDACTED:<label>] for these exact
    labels) blanked out, so a secret that happens to be part of a marker (a URL password
    "password" and the marker [REDACTED:url-password]) is not mistaken for one that is
    still there. Only real labels are matched: text merely shaped like a marker, such as
    [REDACTED:<the secret>], is still checked."""
    if not labels:
        return text
    marker = re.compile(r"\[REDACTED:(?:" + "|".join(map(re.escape, sorted(labels))) + r")\]")
    return marker.sub(" ", text)


_DIGITS = re.compile(r"[0-9][0-9 \-]*[0-9]")


def _is_number(secret: str) -> bool:
    """ID numbers and the like: matched only where they stand alone, never as part of a
    longer number or word (so a FIN's digits inside a timestamp are left alone)."""
    return _DIGITS.fullmatch(secret) is not None


def _number_rx(value):
    """The same boundaries as the ID-number rules: not next to letters, digits, '_' or '-',
    not after '.', and not before '.' + digit. So the digits inside a decimal (0.123...),
    a negative number, a UUID or a version are never touched."""
    if isinstance(value, bytes):
        return re.compile(rb"(?:" + _ESCAPE_BEFORE + rb"|(?<![0-9A-Za-z_.\-]))" + re.escape(value)
                          + rb"(?![0-9A-Za-z_\-]|\.[0-9])")
    return re.compile(r"(?<![0-9A-Za-z_.\-])" + re.escape(value) + r"(?![0-9A-Za-z_\-]|\.[0-9])")


def contains_secret(text: str, secret: str) -> bool:
    if _is_number(secret):
        return _number_rx(secret).search(text) is not None
    if len(secret) >= SHORT_LEN:
        return secret in text
    return _word_rx(secret).search(text) is not None


def _valid_json(body: bytes) -> bool:
    try:
        json.loads(body)
        return True
    except ValueError:
        return False


def _json_string_spans(body: bytes) -> list[tuple[int, int]] | None:
    """(start, end) of every string literal in a JSON body, or None if it is not JSON."""
    if body.lstrip()[:1] not in (b"{", b"["):
        return None
    spans, i, n = [], 0, len(body)
    while i < n:
        if body[i] == 0x22:  # "
            start, i = i, i + 1
            while i < n and body[i] != 0x22:
                i += 2 if body[i] == 0x5C else 1  # skip escaped characters
            spans.append((start, i))
        i += 1
    return spans


def _inside(spans: list[tuple[int, int]], pos: int) -> bool:
    import bisect
    k = bisect.bisect_right(spans, (pos, float("inf"))) - 1
    return k >= 0 and spans[k][0] < pos < spans[k][1]


_SCHEMA_KEY_BEFORE = re.compile(rb'"(' + b"|".join(k.encode() for k in sorted(_SCHEMA_NUMBER_KEYS))
                                + rb')"\s*:\s*$')


def _tools_span(body: bytes) -> tuple[int, int] | None:
    """Byte range of the value of the top-level "tools" key in a JSON object body."""
    i, n, depth = 0, len(body), 0
    while i < n:
        c = body[i]
        if c == 0x22:  # string
            start, i = i, i + 1
            while i < n and body[i] != 0x22:
                i += 2 if body[i] == 0x5C else 1
            if depth == 1 and body[start + 1:i] == b"tools":
                j = i + 1
                while j < n and body[j] in b" \t\r\n":
                    j += 1
                if j < n and body[j] == 0x3A:  # ':' : this string is the key
                    j += 1
                    while j < n and body[j] in b" \t\r\n":
                        j += 1
                    if j >= n or body[j] not in b"[{":
                        return None  # only a list or object can hold tool definitions
                    k, d = j, 0
                    while k < n:  # find the end of the value
                        b = body[k]
                        if b == 0x22:
                            k += 1
                            while k < n and body[k] != 0x22:
                                k += 2 if body[k] == 0x5C else 1
                        elif b in b"[{":
                            d += 1
                        elif b in b"]}":
                            d -= 1
                            if d == 0:
                                return j, k + 1
                        k += 1
                    return None
        elif c in b"[{":
            depth += 1
        elif c in b"]}":
            depth -= 1
        i += 1
    return None


def _schema_limit(body: bytes, pos: int, tools: tuple[int, int] | None) -> bool:
    """True if the bare number at pos is a schema limit inside the top-level "tools"."""
    if tools is None or not tools[0] <= pos < tools[1]:
        return False
    return _SCHEMA_KEY_BEFORE.search(body[max(tools[0], pos - 80):pos]) is not None


def _replace_number(body: bytes, secret: str, mark: bytes) -> tuple[bytes, int]:
    """Replace a stand-alone number. Where it is a bare JSON number ("fin": 123456789012,
    outside any string) the marker is quoted, so the request stays valid JSON; inside a
    string it is replaced as text."""
    forms = {secret.encode(), quote(secret, safe="").encode(), quote_plus(secret, safe="").encode()}
    spans = tools = None

    def sub(m: re.Match[bytes]) -> bytes:
        bare = spans is not None and not _inside(spans, m.start())
        if bare and _schema_limit(m.string, m.start(), tools):
            return m.group(0)  # a JSON-schema limit, not data: leave the number as it is
        return b'"' + mark + b'"' if bare else mark
    total = 0
    for form in forms:
        spans = _json_string_spans(body)
        tools = _tools_span(body) if spans is not None else None
        changed = 0

        def counted(m: re.Match[bytes]) -> bytes:
            nonlocal changed
            new = sub(m)
            changed += new != m.group(0)
            return new
        body = _number_rx(form).sub(counted, body)
        total += changed
    return body, total


def replace_all(body: bytes, hits: list[tuple[str, str]], counts: Counter) -> bytes:
    """Replace every encoding of each secret in the raw body (short ones as whole words)."""
    for rule, secret in hits:
        found = 0
        if _is_number(secret):
            body, n = _replace_number(body, secret, placeholder(rule))
            found += n
            if found:
                counts[rule] += found
            continue
        for form in encodings(secret):
            if len(secret) >= SHORT_LEN:
                n = body.count(form)
                if n:
                    body = body.replace(form, placeholder(rule))
            else:
                body, n = _word_rx(form).subn(placeholder(rule), body)
            found += n
        if found:
            counts[rule] += found
    return body


# Built-in patterns, used only if gitleaks itself fails, so a request is still redacted
# rather than blocked or sent unscanned. (rule id, pattern, group holding the secret)
_FALLBACK_RULES = [(rule, re.compile(rx), group) for rule, rx, group in [
    ("private-key", r"-----BEGIN[A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]{0,20000}?-----END[A-Z0-9 ]{0,40}PRIVATE KEY-----", 0),
    ("anthropic-api-key", r"sk-ant-[A-Za-z0-9]{2,12}-[A-Za-z0-9_\-]{30,}", 0),
    ("openai-api-key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{30,}", 0),
    ("aws-access-token", r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b", 0),
    ("github-pat", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", 0),
    ("github-fine-grained-pat", r"\bgithub_pat_[A-Za-z0-9_]{50,255}\b", 0),
    ("gitlab-pat", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", 0),
    ("slack-token", r"\bxox[abposr]-[A-Za-z0-9\-]{10,}", 0),
    ("gcp-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0),
    ("stripe-access-token", r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b", 0),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 0),
    ("url-password", r"(?i)[a-z][a-z0-9+.\-]{1,20}://[^\s:/@\"'\\]{1,64}:([^\s@/\"'\\$<>{}]{3,128})@", 1),
    ("password-assignment", r"(?i)(?:password|passwd|pwd|secret)[\"']?[ \t]{0,3}[:=][ \t]{0,3}[\"']?([^\s\"'$\{\(\);,]{4,200})", 1),
    ("fayda-regid", r"(?<![0-9A-Za-z_.\-])([0-9]{29})(?![0-9A-Za-z_\-]|\.[0-9])", 1),
    ("fayda-fan-vid", r"(?<![0-9A-Za-z_.\-])([0-9]{16}|[0-9]{4}[ \-][0-9]{4}[ \-][0-9]{4}[ \-][0-9]{4})(?![0-9A-Za-z_\-]|\.[0-9])", 1),
    ("fayda-fin-uin", r"(?<![0-9A-Za-z_.\-])([0-9]{12}|[0-9]{4}[ \-][0-9]{4}[ \-][0-9]{4})(?![0-9A-Za-z_\-]|\.[0-9])", 1),
]]
_FALLBACK_PLACEHOLDERS = re.compile(r"(?i)^(null|none|true|false|password|secret|changeme|example|x+|\*+|<[^>]*>|\[REDACTED:[^\]]*\]"
                                    r"|9007199254740991|9007199254740992|4503599627370496)$")


def fallback_scan(texts: list[str]) -> list[tuple[str, str]]:
    found = set()
    for text in texts:
        for rule, rx, group in _FALLBACK_RULES:
            for m in rx.finditer(text):
                secret = m.group(group)
                if secret and not _FALLBACK_PLACEHOLDERS.match(secret):
                    found.add((rule, secret))
    return sorted(found, key=lambda rs: len(rs[1]), reverse=True)


def _redact_str(text: str, secrets: list[tuple[str, str]], counts: Counter) -> str:
    for rule, secret in secrets:
        mark = placeholder(rule).decode()
        if _is_number(secret):
            text, n = _number_rx(secret).subn(mark, text)
        elif len(secret) >= SHORT_LEN:
            n = text.count(secret)
            text = text.replace(secret, mark)
        else:
            text, n = _word_rx(secret).subn(mark, text)
        if n:
            counts[rule] += n
    return text


def _media_payload(node) -> bytes | None:
    """The decoded bytes of a {"type": "base64", "data": ...} node, if it is one."""
    if not isinstance(node, _Pairs):
        return None
    d = dict(node)
    if d.get("type") == "base64" and isinstance(d.get("data"), str) and _is_base64(d["data"]):
        return base64.b64decode(d["data"])
    return None


def _rebuild_json(obj, secrets, removals: dict, counts: Counter, in_tools=False, top=True, key=None):
    """A copy of the parsed request with every secret replaced in every string (and ID-shaped
    JSON number), and every image/document holding a secret replaced by a short note."""
    if isinstance(obj, str):
        return _redact_str(obj, secrets, counts)
    if isinstance(obj, int) and not isinstance(obj, bool):
        if not (in_tools and key in _SCHEMA_NUMBER_KEYS):
            for rule, secret in secrets:
                if _is_number(secret) and secret.replace(" ", "").replace("-", "") == str(obj):
                    counts[rule] += 1
                    return placeholder(rule).decode()
        return obj
    if isinstance(obj, list) and not isinstance(obj, _Pairs):  # (_Pairs, a JSON object, is a list too)
        return [_rebuild_json(v, secrets, removals, counts, in_tools, False, key) for v in obj]
    if isinstance(obj, _Pairs):
        d = dict(obj) if len({k for k, _ in obj}) == len(obj) else {}
        source = d.get("source")
        raw = _media_payload(source) if d.get("type") in ("image", "document") else _media_payload(obj)
        if raw is not None:
            rules = removals.get(hashlib.sha256(raw).digest())
            if not rules:
                text = raw.decode("utf-8", errors="ignore")
                rules = {r for r, sec in secrets if contains_secret(text, sec)}
            if rules:
                kind = "image" if raw[:16] and not raw.startswith(b"%PDF-") and d.get("type") != "document" else "document"
                note = f"[REDACTED: {kind} removed by ai-dlp, it contained {', '.join(sorted(rules))}]"
                for r in rules:
                    counts[r] += 1
                if d.get("type") in ("image", "document"):  # an API content block: becomes a text block
                    return {"type": "text", "text": note}
                return {k: (base64.b64encode(note.encode()).decode() if k == "data" else
                            ("text/plain" if k == "media_type" else v)) for k, v in obj}
        out = {}
        for k, v in obj:
            out[_redact_str(k, secrets, counts)] = _rebuild_json(v, secrets, removals, counts,
                                                                in_tools or (top and k == "tools"), False, k)
        return out
    return obj


def _rebuild_form(body: bytes, secrets, counts: Counter) -> bytes:
    from urllib.parse import parse_qsl, urlencode
    pairs = parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return urlencode([(_redact_str(k, secrets, counts), _redact_str(v, secrets, counts)) for k, v in pairs],
                     quote_via=quote).encode()


def _rebuild_multipart(body: bytes, content_type: str, secrets, removals: dict, counts: Counter) -> bytes:
    """Replace the content of every part that still holds a secret (an encoded text part, or a
    file holding one) by a short note; everything else is kept byte for byte."""
    m = re.search(r'boundary="?([^";]+)"?', content_type, re.I)
    if not m:
        return body
    sep = b"--" + m.group(1).encode()
    pieces = body.split(sep)
    for i, piece in enumerate(pieces):
        head, gap, content = piece.partition(b"\r\n\r\n")
        if not gap:
            continue
        tail = b"\r\n" if content.endswith(b"\r\n") else b""
        payload = content[:-2] if tail else content
        b64 = re.search(rb"(?im)^content-transfer-encoding:\s*base64", head) is not None
        try:
            data = base64.b64decode(payload) if b64 else payload
        except ValueError:
            continue
        rules = set(removals.get(hashlib.sha256(data).digest(), ()))
        text = data.decode("utf-8", errors="ignore")
        rules |= {r for r, sec in secrets if contains_secret(text, sec)}
        if rules:
            note = f"[REDACTED: content removed by ai-dlp, it contained {', '.join(sorted(rules))}]".encode()
            for r in rules:
                counts[r] += 1
            pieces[i] = head + gap + (base64.b64encode(note) if b64 else note) + tail
    return sep.join(pieces)


async def redact(body: bytes, known: list[str], gitleaks: Gitleaks, content_type: str = "",
                 ocr: OCR | None = None, notes: list[str] | None = None) -> tuple[bytes, Counter]:
    """Redact every secret and ID in a request. Nothing is refused: what cannot be replaced
    in place is rebuilt (JSON, forms, upload parts), images/PDFs holding a secret are
    replaced by a short note, and content that cannot be read is sent and noted."""
    notes = notes if notes is not None else []
    token_notes = _NOTES.set(notes)
    try:
        return await _redact(body, known, gitleaks, content_type, ocr, notes)
    finally:
        _NOTES.reset(token_notes)


async def _redact(body, known, gitleaks, content_type, ocr, notes):
    original = body
    counts: Counter = Counter()
    known_hits = [("known-secret", s) for s in known]
    body = replace_all(body, [h for h in known_hits if any(f in body for f in encodings(h[1]))], counts)
    media: list[bytes] = []
    token = _MEDIA.set(media)
    try:
        texts = texts_of(original, content_type)
    finally:
        _MEDIA.reset(token)

    # Text inside images and PDFs (OCR). Limits and tool failures are noted, never refused.
    media_text: dict[bytes, str] = {}
    if ocr is not None and ocr.available and media:
        todo = [raw for raw in media if ocr.cached(raw)]
        new = [raw for raw in media if not ocr.cached(raw)]
        if len(new) > OCR_MAX_ITEMS:
            _note(f"{len(new) - OCR_MAX_ITEMS} images/PDFs sent without OCR (limit {OCR_MAX_ITEMS} per request)")
            new = new[:OCR_MAX_ITEMS]

        async def read_all():
            for raw in todo + new:
                try:
                    text = await ocr.text_of(raw)
                except ScanError as e:
                    _note(f"image/PDF sent without OCR: {e}")
                    continue
                if text:
                    media_text[hashlib.sha256(raw).digest()] = text
        try:
            await asyncio.wait_for(read_all(), OCR_REQUEST_DEADLINE)
        except asyncio.TimeoutError:
            _note(f"OCR stopped after {OCR_REQUEST_DEADLINE} s; remaining images/PDFs sent without OCR")
    readable = {hashlib.sha256(raw).digest(): _readable_runs(raw) for raw in media}

    scanned = texts + list(media_text.values())
    try:
        hits = await gitleaks.scan(scanned) if scanned else []
    except ScanError as e:
        log.warning("ai-dlp: gitleaks failed (%s); using the built-in rules", e)
        _note(f"scanned with ai-dlp's built-in rules (gitleaks failed: {str(e)[:80]})")
        hits = fallback_scan(scanned)
    MARKER_LABELS.update(rule for rule, _ in hits)
    hits = [(rule, secret) for rule, secret in hits if not is_own_marker(secret)]
    secrets = sorted(set(known_hits) | set(hits), key=lambda rs: len(rs[1]), reverse=True)

    # Images/PDFs holding a secret are removed (replaced by a note), not sent.
    removals: dict[bytes, set[str]] = {}
    for key in set(media_text) | set(readable):
        views = [media_text.get(key, ""), readable.get(key, "")]
        rules = {rule for rule, sec in secrets if any(contains_secret(v, sec) for v in views)}
        if rules:
            removals[key] = rules
            _note(f"removed an image/PDF holding {', '.join(sorted(rules))}")

    def remaining(b: bytes) -> list[str]:
        token = _MEDIA.set(None)
        try:
            views = [_without_markers(t, MARKER_LABELS) for t in texts_of(b, content_type)]
        finally:
            _MEDIA.reset(token)
        return [rule for rule, sec in secrets if any(contains_secret(v, sec) for v in views)]

    # Fast path: replace in place (keeps the request byte-for-byte otherwise).
    if not removals:
        fast = replace_all(body, hits, counts)
        if (not _valid_json(original) or _valid_json(fast)) and not remaining(fast):
            return fast, counts

    # Otherwise rebuild the request from its decoded form, so nothing is left behind.
    counts = Counter()
    ctype = (content_type or "").lower()
    if _valid_json(original):
        doc = json.loads(original, object_pairs_hook=_Pairs)
        rebuilt = json.dumps(_rebuild_json(doc, secrets, removals, counts), ensure_ascii=False,
                             separators=(",", ":")).encode()
    elif "x-www-form-urlencoded" in ctype:
        rebuilt = _rebuild_form(original, secrets, counts)
    elif ctype.startswith("multipart/"):
        rebuilt = replace_all(_rebuild_multipart(original, content_type, secrets, removals, counts), secrets, counts)
    elif removals and _is_image_or_pdf(original[:16]):
        rules = sorted(set().union(*removals.values()))
        for r in rules:
            counts[r] += 1
        rebuilt = f"[REDACTED: file removed by ai-dlp, it contained {', '.join(rules)}]".encode()
    else:
        rebuilt = replace_all(original, secrets, counts)
    left = remaining(rebuilt)
    if left:
        log.warning("ai-dlp: could not remove every finding (%s); sent with the rest redacted", ", ".join(left))
        _note(f"could not fully redact: {', '.join(sorted(set(left)))}")
    return rebuilt, counts


def _fallback_redact(body: bytes, known: list[str]) -> tuple[bytes, Counter]:
    """Last resort after an unexpected scanner error: built-in rules on the raw text."""
    counts: Counter = Counter()
    try:
        text = body.decode("utf-8", errors="surrogateescape")
        secrets = [("known-secret", s) for s in known] + fallback_scan([text])
        return replace_all(body, secrets, counts), counts
    except Exception:
        log.exception("ai-dlp: built-in rules failed too; request sent as is")
        return body, counts


def _summary(counts: Counter) -> str:
    return ", ".join(f"{rule} x{n}" for rule, n in sorted(counts.items()))


ATTACHMENTS_SEEN_MAX = 20_000
_MULTIPART_PART = re.compile(
    rb'Content-Disposition:([^\r\n]*)\r?\n(?:[^\r\n]+\r?\n)*?Content-Type:\s*([\w.+\-]+/[\w.+\-]+)', re.I)
_FILENAME = re.compile(rb'filename="([^"\r\n]{0,200})"', re.I)


def _kind(media: str) -> str:
    media = media.lower()
    if media.startswith("image/"):
        return "image"
    if media == "application/pdf":
        return "pdf"
    return "file"


class AttachmentTracker:
    """Finds images/PDFs/files in a request and reports only ones not seen before."""

    def __init__(self) -> None:
        self.seen: OrderedDict[bytes, None] = OrderedDict()

    def _new(self, fingerprint: bytes) -> bool:
        key = hashlib.sha256(fingerprint).digest()
        if key in self.seen:
            self.seen.move_to_end(key)
            return False
        self.seen[key] = None
        while len(self.seen) > ATTACHMENTS_SEEN_MAX:
            self.seen.popitem(last=False)
        return True

    def find(self, body: bytes, content_type: str) -> list[dict]:
        found: list[tuple[bytes, dict]] = []
        ctype = (content_type or "").split(";")[0].strip().lower()
        if ctype.startswith("image/") or ctype == "application/pdf":
            found.append((body, {"kind": _kind(ctype), "media": ctype, "bytes": len(body), "source": "upload"}))
        elif ctype.startswith("multipart/"):
            for disposition, media in _MULTIPART_PART.findall(body):
                m = _FILENAME.search(disposition)
                name = m.group(1) if m else b""
                media_s = media.decode(errors="replace").lower()
                if media_s.startswith(("text/", "application/json")):
                    continue
                info = {"kind": _kind(media_s), "media": media_s, "bytes": len(body), "source": "upload"}
                if name:
                    info["name"] = name.decode(errors="replace")[:120]
                found.append((body + media + name, info))
        else:
            try:
                doc = json.loads(body)
            except ValueError:
                doc = None
            self._walk(doc, found)
        return [info for fingerprint, info in found if self._new(fingerprint)]

    def _walk(self, obj, found: list) -> None:
        if isinstance(obj, list):
            for item in obj:
                self._walk(item, found)
            return
        if not isinstance(obj, dict):
            return
        source = obj.get("source")
        if obj.get("type") in ("image", "document") and isinstance(source, dict):
            stype = source.get("type")
            media = str(source.get("media_type") or ("image/*" if obj["type"] == "image" else "application/pdf"))
            info = {"kind": _kind(media) if obj["type"] == "document" or media.startswith("image/") else "image",
                    "media": media[:80], "source": str(stype)[:20]}
            if stype == "base64" and isinstance(source.get("data"), str):
                info["bytes"] = len(source["data"]) * 3 // 4
                fingerprint = source["data"].encode()
            elif stype == "text" and isinstance(source.get("data"), str):
                info["kind"], info["bytes"] = "document", len(source["data"].encode())
                fingerprint = source["data"].encode()
            else:  # url, file (Files API), content
                ref = source.get("url") or source.get("file_id") or json.dumps(source, sort_keys=True)[:2000]
                if source.get("url"):
                    # Scheme and host only: signed URLs carry access tokens in the path/query.
                    parts = urlsplit(str(source["url"]))
                    info["url"] = f"{parts.scheme}://{parts.hostname or ''}"[:120]
                fingerprint = str(ref).encode()
            if isinstance(obj.get("title"), str):
                info["name"] = obj["title"][:120]
            found.append((fingerprint, info))
            return  # do not descend into the payload
        if obj.get("type") == "base64" and isinstance(obj.get("data"), str):
            media = str(obj.get("media_type") or "application/octet-stream")[:80]
            found.append((obj["data"].encode(), {"kind": _kind(media), "media": media,
                                                 "bytes": len(obj["data"]) * 3 // 4, "source": "base64"}))
            return
        for value in obj.values():
            self._walk(value, found)


ECH_EXTENSION = 0xFE0D       # TLS Encrypted Client Hello
AI_ADDRESSES_MAX = 20_000
RESOLVE_EVERY = 600          # seconds between DNS refreshes of the listed domains


def _address_ip(conn) -> str | None:
    address = getattr(conn, "address", None)
    return address[0] if isinstance(address, tuple) and address else None


# Stored copies of inspected requests, for the widget's detail view. Off unless
# AI_DLP_KEEP_REQUESTS is set (the Linux service keeps the last 50). Only what actually
# left the machine is stored (redacted), never a blocked body; login headers are masked.
REQUESTS_DIR = Path(os.environ.get("AI_DLP_REQUESTS_DIR", LOG_DIR / "requests"))
KEEP_REQUESTS = int(os.environ.get("AI_DLP_KEEP_REQUESTS", "0") or 0)
REQUEST_MAX_BYTES = 1_000_000
# Only these headers keep their values in stored copies; every other header is shown as
# [hidden] (login headers, cookies, and anything whose purpose is not known to be harmless).
_SAFE_HEADERS = frozenset({
    "host", "content-type", "content-length", "content-encoding", "accept", "accept-encoding",
    "accept-language", "user-agent", "origin", "connection", "te", "priority", "cache-control",
    "pragma", "dnt", "anthropic-version", "anthropic-beta", "openai-beta", "x-app",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
})
# Stored copies are kept only for this account (set by the installer): the proxy sees every
# user's traffic, and no one should be able to read another user's requests.
REQUESTS_UID = int(os.environ.get("AI_DLP_REQUESTS_UID", "-1") or -1)
_REQUEST_ID = re.compile(r"^\d{13}-[0-9a-f]{8}$")
_last_request_ms = 0


def _proc_ip(hexaddr: str) -> str:
    raw = bytes.fromhex(hexaddr)
    if len(raw) == 4:
        return socket.inet_ntoa(raw[::-1])
    import ipaddress
    addr = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return str(addr.ipv4_mapped or addr)


def uid_from_proc(table: str, ip: str, port: int, rip: str, rport: int) -> int | None:
    """The uid owning the TCP socket ip:port -> rip:rport, from /proc/net/tcp(6) text.

    Both ends must match. If entries for that exact connection disagree about the owner,
    None is returned: a request is never attributed to an account by guesswork.
    """
    uids = set()
    for line in table.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 8 or ":" not in cols[1] or ":" not in cols[2] or cols[3] == "0A":  # 0A = listening
            continue
        laddr, lport = cols[1].rsplit(":", 1)
        raddr, rport_hex = cols[2].rsplit(":", 1)
        try:
            if (int(lport, 16) == port and int(rport_hex, 16) == rport
                    and _proc_ip(laddr) == ip and _proc_ip(raddr) == rip):
                uids.add(int(cols[7]))
        except ValueError:
            continue
    return uids.pop() if len(uids) == 1 else None


def client_uid(flow) -> int | None:
    """Which local account opened this connection (Linux; None if unknown)."""
    peer = getattr(getattr(flow, "client_conn", None), "peername", None)
    # The original destination: the app's own socket still points there (NAT is invisible to it).
    dest = getattr(getattr(flow, "server_conn", None), "address", None)
    if not (isinstance(peer, tuple) and len(peer) >= 2 and isinstance(dest, tuple) and len(dest) >= 2):
        return None
    ip, rip = str(peer[0]).removeprefix("::ffff:"), str(dest[0]).removeprefix("::ffff:")
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in rip else socket.AF_INET, rip)
    except OSError:
        return None  # not an address (a hostname): cannot match the socket table exactly
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            uid = uid_from_proc(Path(table).read_text(), ip, int(peer[1]), rip, int(dest[1]))
        except OSError:
            continue
        if uid is not None:
            return uid
    return None


def safe_headers(fields, known: list[str]) -> list[list[str]]:
    """Request headers fit to store: values only for known-harmless headers (with listed
    secrets redacted); every other header is [hidden]."""
    out = []
    for name, value in fields:
        name = name.decode("latin-1") if isinstance(name, bytes) else str(name)
        value = value.decode("latin-1") if isinstance(value, bytes) else str(value)
        if name.lower() not in _SAFE_HEADERS and not name.lower().startswith("x-stainless-"):
            value = "[hidden]"
        else:
            for secret in known:
                if contains_secret(value, secret):
                    value = value.replace(secret, "[REDACTED:known-secret]")
        out.append([name[:100], value[:2000]])
    return out


def _compact(obj):
    """Replace long base64 payloads (images, PDFs) with a short description."""
    if isinstance(obj, dict):
        return {k: _compact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_compact(v) for v in obj]
    if isinstance(obj, str) and len(obj) > 1000 and _is_base64(obj):
        return f"[base64 data, {len(obj) * 3 // 4 // 1024} KB]"
    return obj


def displayable_body(body: bytes, content_type: str = "") -> tuple[str, bool]:
    """(text, truncated): the body as readable text, JSON pretty-printed."""
    try:
        text = json.dumps(_compact(json.loads(body)), indent=2, ensure_ascii=False)
    except ValueError:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return f"[binary body, {len(body)} bytes, {content_type or 'unknown type'}]", False
    data = text.encode("utf-8")
    if len(data) > REQUEST_MAX_BYTES:
        return data[:REQUEST_MAX_BYTES].decode("utf-8", "ignore"), True
    return text, False


def store_request(method: str, host: str, path: str, headers: list[list[str]],
                  body: str | None, truncated: bool = False) -> str | None:
    """Save one request for the detail view; returns its id (None when off or on error)."""
    global _last_request_ms
    if KEEP_REQUESTS <= 0:
        return None
    # Ids start with a strictly increasing millisecond time, so sorting them by name
    # orders them oldest first even when several arrive in the same millisecond.
    _last_request_ms = max(int(time.time() * 1000), _last_request_ms + 1)
    rid = f"{_last_request_ms}-{os.urandom(4).hex()}"
    record = {"id": rid, "method": method[:10], "host": host[:253],
              "path": path.split("?")[0][:2000],  # query dropped: some APIs put keys there
              "headers": headers, "body": body, "truncated": truncated}
    try:
        REQUESTS_DIR.mkdir(mode=0o750, exist_ok=True)
        tmp = REQUESTS_DIR / f".{rid}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False)
        os.replace(tmp, REQUESTS_DIR / f"{rid}.json")
        stored = sorted(REQUESTS_DIR.glob("*.json"))  # ids start with the time: oldest first
        for old in stored[:-KEEP_REQUESTS]:
            old.unlink(missing_ok=True)
    except OSError as e:
        log.warning("ai-dlp: could not store request details: %s", e)
        return None
    return rid


def record_event(action: str, host: str, path: str, method: str = "", size: int = 0,
                 counts: Counter | None = None, reason: str = "", test: bool = False,
                 attachments: list[dict] | None = None, request_id: str | None = None,
                 notes: list[str] | None = None) -> None:
    event = {"time": int(time.time() * 1000), "action": action, "host": host[:253],
             "method": method[:10], "path": path.split("?")[0][:200], "bytes": size}
    if request_id:
        event["id"] = request_id
    if notes:
        event["notes"] = [n[:200] for n in notes[:20]]
    if counts:
        event["rules"] = dict(counts)
    if reason:
        event["reason"] = reason[:200]
    if test:
        event["test"] = True
    if attachments:
        event["attachments"] = attachments[:50]
    try:
        if EVENTS_FILE.exists() and EVENTS_FILE.stat().st_size > EVENTS_MAX_BYTES:
            EVENTS_FILE.replace(EVENTS_FILE.with_name(EVENTS_FILE.name + ".1"))
        with EVENTS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        log.warning("ai-dlp: could not write event log: %s", e)


class AiDLP:
    def __init__(self) -> None:
        self.secrets = SecretList(SECRETS_FILE)
        self.gitleaks = Gitleaks()
        self.attachments = AttachmentTracker()
        self.ocr = OCR()
        self.domains = DomainList(DOMAINS_FILE)
        # Addresses known to serve a listed domain: from the proxy's own DNS lookups and
        # from connections it intercepted. Used to catch connections that hide the name.
        self.ai_addresses: set[str] = set()
        self._resolver = None

    def _learn(self, ip: str | None) -> None:
        if ip and len(self.ai_addresses) < AI_ADDRESSES_MAX:
            self.ai_addresses.add(ip)

    async def _resolve_once(self) -> None:
        loop = asyncio.get_running_loop()
        for domain in self.domains.current():
            for name in (domain, "api." + domain, "www." + domain):
                try:
                    infos = await asyncio.wait_for(loop.getaddrinfo(name, 443, type=socket.SOCK_STREAM), 5)
                except Exception:
                    continue
                for info in infos:
                    self._learn(info[4][0])

    async def _resolve_loop(self) -> None:
        while True:
            await self._resolve_once()
            await asyncio.sleep(RESOLVE_EVERY)

    def running(self) -> None:
        if self._resolver is None:
            self._resolver = asyncio.ensure_future(self._resolve_loop())

    def tls_clienthello(self, data) -> None:
        """Decide per connection, from the TLS ClientHello.

        - A listed name (SNI): intercept, decrypt and inspect.
        - A relay name (SNI): intercept with a certificate for that exact name, then pass the
          traffic on without inspecting or logging it. The browser then cannot send an
          inspected site's requests over this connection (as it could over one carrying the
          site's real, many-name certificate); those requests are inspected by Host.
        - No name, or Encrypted Client Hello (which hides the real name), to an address
          known to serve a listed domain: intercept too. The request is then inspected,
          or the client refuses the proxy's certificate; it never passes unscanned.
        - Anything else: passed through untouched, never decrypted.
        """
        hello = data.client_hello
        ip = _address_ip(getattr(getattr(data, "context", None), "server", None))
        if self.domains.matches(hello.sni):
            self._learn(ip)
            return
        if self.domains.relayed(hello.sni):
            return
        ech = any(ext[0] == ECH_EXTENSION for ext in (getattr(hello, "extensions", None) or []))
        if ip and ip in self.ai_addresses and (not hello.sni or ech):
            why = "Encrypted Client Hello" if ech else "no server name"
            log.warning("ai-dlp: forcing inspection of a connection to AI address %s (%s)", ip, why)
            record_event("blocked", hello.sni or ip, "/", "TLS",
                         reason=f"{why} on a connection to an AI service address: forced through inspection")
            return
        data.ignore_connection = True

    def _may_store(self, flow) -> bool:
        """Keep a copy only of requests from the account the installer gave access to."""
        return KEEP_REQUESTS > 0 and REQUESTS_UID >= 0 and client_uid(flow) == REQUESTS_UID

    def _block(self, flow, reason: str) -> None:
        body = json.dumps({"type": "error", "error": {
            "type": "invalid_request_error", "message": f"ai-dlp blocked this request: {reason}"}})
        flow.response = http.Response.make(400, body, {"content-type": "application/json"})
        req = flow.request
        rid = None
        try:  # headers only: a blocked body holds the secret that could not be removed
            if self._may_store(flow):
                rid = store_request(req.method, req.pretty_host, req.path,
                                    safe_headers(req.headers.fields, self.secrets.current()), None)
        except Exception as e:
            log.warning("ai-dlp: could not store request details: %s", e)
        record_event("blocked", req.pretty_host, req.path, req.method, reason=reason,
                     test=req.headers.get(ECHO_HEADER) == "1", request_id=rid)

    def _inspected(self, flow) -> bool:
        """Scan when the connection was opened to a listed name (TLS SNI) OR the request
        names a listed host, so a mismatched Host header cannot skip the scan."""
        sni = getattr(getattr(flow, "client_conn", None), "sni", None)
        if self.domains.matches(sni) or self.domains.matches(flow.request.pretty_host):
            return True
        ip = _address_ip(getattr(flow, "server_conn", None))
        return not sni and ip is not None and ip in self.ai_addresses

    async def request(self, flow) -> None:
        req = flow.request
        if not self._inspected(flow):
            return
        where = f"{req.pretty_host} {req.path.split('?')[0]}"
        notes: list[str] = []
        try:
            content = req.get_content(strict=True) or b""
        except ValueError:
            log.warning("ai-dlp: %s: undecodable content-encoding; sent without being scanned", where)
            record_event("allowed", req.pretty_host, req.path, req.method,
                         reason="sent without being scanned: undecodable content-encoding")
            return
        try:
            cleaned, counts = await redact(content, self.secrets.current(), self.gitleaks,
                                           req.headers.get("content-type", ""), self.ocr, notes)
        except Exception as e:
            # Never refuse a request: on an unexpected error, redact with the built-in rules.
            log.exception("ai-dlp: %s: scanner error (%s); redacted with the built-in rules", where, type(e).__name__)
            notes.append(f"scanner error ({type(e).__name__}): redacted with ai-dlp's built-in rules only")
            cleaned, counts = _fallback_redact(content, self.secrets.current())
        if cleaned != content:
            req.set_content(cleaned)
        if counts:
            log.warning("ai-dlp: redacted %s in %s", _summary(counts), where)
        for n in notes:
            log.warning("ai-dlp: %s: %s", where, n)
        echo = req.headers.get(ECHO_HEADER) == "1"
        try:
            attachments = self.attachments.find(content, req.headers.get("content-type", ""))
        except Exception as e:  # flagging is best effort; never break the request over it
            log.warning("ai-dlp: attachment check failed for %s: %s", where, e)
            attachments = []
        if attachments:
            kinds = Counter(a["kind"] for a in attachments)
            log.warning("ai-dlp: flagged %s sent to %s", _summary(kinds), where)
        rid = None
        if self._may_store(flow):
            try:  # what actually left the machine: the redacted body
                text, truncated = displayable_body(cleaned, req.headers.get("content-type", ""))
                rid = store_request(req.method, req.pretty_host, req.path,
                                    safe_headers(req.headers.fields, self.secrets.current()), text, truncated)
            except Exception as e:
                log.warning("ai-dlp: could not store request details: %s", e)
        record_event("redacted" if counts else "allowed", req.pretty_host, req.path, req.method,
                     len(content), counts, test=echo, attachments=attachments, request_id=rid,
                     notes=notes)
        if echo:
            flow.response = http.Response.make(200, cleaned, {"content-type": "application/octet-stream"})

    def requestheaders(self, flow) -> None:
        # Relayed (not inspected) uploads stream straight through instead of being buffered.
        if not self._inspected(flow):
            flow.request.stream = True

    def responseheaders(self, flow) -> None:
        # Responses are never inspected: stream them all (SSE output, video, downloads).
        flow.response.stream = True

    async def websocket_message(self, flow) -> None:
        if not self._inspected(flow):
            return
        msg = flow.websocket.messages[-1]
        if not msg.from_client:
            return
        try:
            # Binary frames (e.g. voice audio) are treated like audio: flagged, not blocked.
            kind = "text/plain" if getattr(msg, "is_text", True) else "audio/x-websocket-binary"
            cleaned, counts = await redact(msg.content, self.secrets.current(), self.gitleaks, kind, self.ocr)
        except Exception:
            # Never drop a message: on an unexpected error, redact with the built-in rules.
            log.exception("ai-dlp: websocket scanner error; redacted with the built-in rules")
            cleaned, counts = _fallback_redact(msg.content, self.secrets.current())
        if counts:
            msg.content = cleaned
            log.warning("ai-dlp: redacted %s in websocket %s", _summary(counts), flow.request.pretty_host)
            record_event("redacted", flow.request.pretty_host, flow.request.path, "WS", len(msg.content), counts)


addons = [AiDLP()]
