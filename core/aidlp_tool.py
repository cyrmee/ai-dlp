#!/usr/bin/env python3
"""Cross-platform helpers behind the ai-dlp command on Linux, macOS and Windows.

  aidlp_tool.py selftest CA_PEM [--claude]
      1. sends random fake secrets to https://api.anthropic.com through the proxy with
         the echo header (answered locally by the proxy, never forwarded) and checks
         they come back redacted;
      2. checks an unlisted site (example.com) keeps its real certificate;
      3. with --claude, checks a new Claude Code session can connect.
  aidlp_tool.py domains DOMAINS_FILE CA_PEM
      lists each domain and whether the CA covers it (only covered ones are inspected).
  aidlp_tool.py add-secrets DEST [--pgpass FILE] [ENV_FILE ...]   (values also read from stdin)
      merges secret values (8+ characters) into the exact-match list DEST. Run with
      the rights needed to write DEST (root / Administrator). Prints counts only.
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import socket
import ssl
import string
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ai_dlp import ECHO_HEADER, DomainList, MIN_LEN  # noqa: E402

TEST_URL = "https://api.anthropic.com/v1/messages"


def _rnd(n: int, abc: str = string.ascii_letters + string.digits) -> str:
    return "".join(random.choice(abc) for _ in range(n))


def fake_secrets() -> dict[str, str]:
    """Random values in formats gitleaks recognises; never real credentials."""
    return {
        "AWS access key": "AK" + "IA" + _rnd(16, string.ascii_uppercase + "234567"),
        "GitHub token": "gh" + "p_" + _rnd(36),
        "Anthropic key": "sk-" + "ant-api03-" + _rnd(93, string.ascii_letters + string.digits + "_-") + "AA",
        "GitLab token": "gl" + "pat-" + _rnd(20),
        "DB URL password": _rnd(14) + "9x",
        "password assignment": _rnd(14) + "7!",
    }


def check_redaction(ca_pem: str) -> bool:
    fakes = fake_secrets()
    text = "\n".join([
        "aws " + fakes["AWS access key"], "gh " + fakes["GitHub token"], "key " + fakes["Anthropic key"],
        "gitlab " + fakes["GitLab token"],
        "url postgres://app:" + fakes["DB URL password"] + "@db.internal:5432/app",
        "DB_PASSWORD=" + fakes["password assignment"],
    ])
    body = json.dumps({"messages": [{"role": "user", "content": text}]}).encode()
    req = urllib.request.Request(TEST_URL, data=body, method="POST",
                                 headers={ECHO_HEADER: "1", "content-type": "application/json"})
    ctx = ssl.create_default_context(cafile=ca_pem)  # trust ONLY the ai-dlp CA
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            out = resp.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"  FAIL  could not reach the proxy: {e}")
        print("        (is it on? a real Anthropic certificate is not trusted by this test)")
        return False
    if '"role"' not in out:
        print("  FAIL  the proxy did not answer the test request:", out[:200])
        return False
    ok = True
    for what, value in fakes.items():
        leaked = value in out
        print(f"  {'FAIL (leaked)' if leaked else 'PASS'}  {what} redacted")
        ok &= not leaked
    print("        rules that fired:", ", ".join(sorted(set(re.findall(r"\[REDACTED:[^\]]+\]", out)))))
    return ok


def check_passthrough(host: str = "example.com") -> bool:
    """An unlisted site must keep its real certificate (never decrypted)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we only read who issued the certificate
    try:
        with socket.create_connection((host, 443), timeout=15) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as e:
        print(f"  SKIP  passthrough check ({host} unreachable: {e})")
        return True
    from cryptography import x509
    issuer = x509.load_der_x509_certificate(der).issuer.rfc4514_string()
    if "ai-dlp" in issuer:
        print(f"  FAIL  {host} was intercepted: {issuer}")
        return False
    print(f"  PASS  unlisted sites pass through untouched ({host} issuer: {issuer})")
    return True


def check_claude() -> bool:
    claude = shutil.which("claude")
    if not claude:
        print("  SKIP  claude not found in PATH")
        return True
    try:
        out = subprocess.run([claude, "-p", "Reply with exactly: OK"], capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("  FAIL  Claude Code timed out")
        return False
    if out.returncode == 0 and "OK" in out.stdout:
        print("  PASS  a new Claude Code session reached Anthropic through the proxy")
        return True
    print("  FAIL  Claude Code could not connect:")
    for line in (out.stdout + out.stderr).strip().splitlines()[-3:]:
        print("        " + line)
    return False


def cmd_selftest(args: list[str]) -> int:
    if not args:
        print(__doc__)
        return 2
    ok = check_redaction(args[0]) and check_passthrough()
    if ok and "--claude" in args[1:]:
        ok = check_claude()
    print("All checks passed." if ok else "Self-test FAILED.")
    return 0 if ok else 1


def cmd_domains(args: list[str]) -> int:
    if len(args) != 2:
        print(__doc__)
        return 2
    import logging
    logging.getLogger("ai-dlp").setLevel(logging.ERROR)  # this command prints its own report
    d = DomainList(Path(args[0]), Path(args[1]))
    for name in d.current():
        print(f"  inspected      {name}")
    for name in d.relay:
        print(f"  relayed        {name}  (decrypted, not inspected or logged)")
    for name in d.uncovered:
        print(f"  NOT inspected  {name}  (the CA does not cover it: run the installer again)")
    return 0


def _env_values(path: Path):
    for raw in path.read_text(errors="surrogateescape").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        value = line.split("=", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        yield value


def _pgpass_values(path: Path):
    for raw in path.read_text(errors="surrogateescape").splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields, cur, esc = [], "", False
        for ch in raw:
            if esc:
                cur, esc = cur + ch, False
            elif ch == "\\":
                esc = True
            elif ch == ":" and len(fields) < 4:
                fields.append(cur)
                cur = ""
            else:
                cur += ch
        if len(fields) == 4:
            yield cur


def cmd_add_secrets(args: list[str]) -> int:
    if not args:
        print(__doc__)
        return 2
    dest, rest, values = Path(args[0]), args[1:], []
    i = 0
    while i < len(rest):
        if rest[i] == "--pgpass" and i + 1 < len(rest):
            values += _pgpass_values(Path(rest[i + 1]).expanduser())
            i += 2
            continue
        values += _env_values(Path(rest[i]).expanduser())
        i += 1
    if not sys.stdin.isatty():
        values += sys.stdin.read().splitlines()
    new = {v for v in values if len(v) >= MIN_LEN}
    existing = set(dest.read_text(errors="surrogateescape").splitlines()) if dest.exists() else set()
    merged = sorted(existing | new)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", errors="surrogateescape") as f:
        f.write("\n".join(merged) + ("\n" if merged else ""))
    if os.name == "nt":
        # POSIX modes mean nothing on Windows: restrict the ACL explicitly before the
        # file takes the list's place (SYSTEM and Administrators only).
        subprocess.run(["icacls", str(tmp), "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"],
                       check=True, capture_output=True)
    os.replace(tmp, dest)
    print(f"Added {len(new - existing)} new value(s); the list now holds {len(merged)}.")
    return 0


def main(argv: list[str]) -> int:
    commands = {"selftest": cmd_selftest, "domains": cmd_domains, "add-secrets": cmd_add_secrets}
    if not argv or argv[0] not in commands:
        print(__doc__)
        return 2
    return commands[argv[0]](argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
