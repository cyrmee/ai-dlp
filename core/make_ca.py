#!/usr/bin/env python3
"""Create, or keep, the ai-dlp certificate authority.

usage: make_ca.py DOMAINS_FILE STATE_DIR CA_OUT      (CA_OUT "-" prints the certificate)
       make_ca.py --verify CERT_FILE DOMAINS_FILE    (exit 1 unless CERT_FILE is a proper ai-dlp CA)

The CA may only vouch for the domains in DOMAINS_FILE (inspected and relay) and their subdomains (a
critical X.509 name constraint with DNS names only: an IP-address constraint makes
some clients, Claude Code among them, reject every certificate it issues). If
STATE_DIR already holds a CA with exactly those constraints it is kept; otherwise a
new one is created.

Writes, in STATE_DIR, the files mitmproxy reads from its confdir:
  mitmproxy-ca.pem       private key + certificate (owner read/write only)
  mitmproxy-ca-cert.pem  certificate
and a copy of the certificate to CA_OUT (public; this is what the OS trusts). With
CA_OUT "-" the certificate is printed after the two status lines instead: on Linux the
installer runs this script as the proxy's own user, so root never creates, follows or
reads files in a directory that user controls.

Files are created with O_EXCL and O_NOFOLLOW after removing the old ones, so a link
placed in STATE_DIR is never followed.

Prints two lines for the installer:  "domains: a.com b.com ..."  and  "ca: kept" or "ca: new".
Same code on Linux, macOS and Windows; needs the `cryptography` package (a
mitmproxy dependency).
"""

from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ai_dlp import ca_domains  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

SUBJECT = "ai-dlp local inspection CA (listed AI domains only)"
KEY_FILE, CERT_FILE = "mitmproxy-ca.pem", "mitmproxy-ca-cert.pem"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)  # not on Windows


def _write_new(path: Path, data: bytes, mode: int) -> None:
    """Create path fresh (never through an existing file or link) and write data."""
    if path.is_symlink() or path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _read_regular(path: Path) -> bytes | None:
    """Contents of a regular file; None if missing or not a regular file (e.g. a link)."""
    if path.is_symlink() or not path.is_file():
        return None
    return path.read_bytes()


def verify_ca_cert(cert_pem: bytes, domains) -> list[str]:
    """Problems that make cert_pem unfit to be trusted as the ai-dlp CA for these domains.

    Required: a CA (critical basicConstraints, pathlen 0) with key-cert-sign usage and a
    CRITICAL name constraint whose permitted subtrees are exactly the listed domains, as
    DNS names only, with no excluded subtrees. Run as root on whatever the unprivileged
    side produced, before the OS is told to trust it.
    """
    try:
        certs = x509.load_pem_x509_certificates(cert_pem)
    except Exception as e:
        return [f"not a PEM certificate: {e}"]
    if len(certs) != 1:
        return [f"expected exactly one certificate, found {len(certs)}"]
    cert, problems = certs[0], []
    ext = cert.extensions
    try:
        bc = ext.get_extension_for_class(x509.BasicConstraints)
        if not (bc.critical and bc.value.ca and bc.value.path_length == 0):
            problems.append("basicConstraints must be critical, CA:TRUE, pathlen 0")
    except x509.ExtensionNotFound:
        problems.append("no basicConstraints")
    try:
        ku = ext.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign:
            problems.append("keyUsage lacks keyCertSign")
    except x509.ExtensionNotFound:
        problems.append("no keyUsage")
    try:
        nc = ext.get_extension_for_class(x509.NameConstraints)
    except x509.ExtensionNotFound:
        return problems + ["no name constraints: it could sign for ANY site"]
    if not nc.critical:
        problems.append("name constraints are not critical")
    permitted = list(nc.value.permitted_subtrees or [])
    if any(not isinstance(t, x509.DNSName) for t in permitted):
        problems.append("name constraints contain non-DNS entries")
    if nc.value.excluded_subtrees:
        problems.append("unexpected excluded subtrees")
    names = {t.value.lower() for t in permitted if isinstance(t, x509.DNSName)}
    if names != set(domains):
        problems.append(f"permitted names {sorted(names)} differ from the domain list")
    return problems


def _key_matches(key_file_pem: bytes, cert_pem: bytes) -> bool:
    try:
        key = serialization.load_pem_private_key(key_file_pem, password=None)
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception:
        return False
    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key.public_key().public_bytes(*fmt) == cert.public_key().public_bytes(*fmt)


def constraints_of(cert_pem: bytes) -> tuple[set[str], bool] | None:
    """(permitted DNS names, has non-DNS constraints) of a CA, or None if unreadable."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except Exception:
        return None
    permitted = list(nc.permitted_subtrees or [])
    dns = {t.value.lower() for t in permitted if isinstance(t, x509.DNSName)}
    other = len(permitted) != len(dns) or bool(nc.excluded_subtrees)
    return dns, other


def new_ca(domains: tuple[str, ...]) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SUBJECT)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.NameConstraints(permitted_subtrees=[x509.DNSName(d) for d in domains],
                                            excluded_subtrees=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


def ensure_ca(domains_file: Path, state: Path, ca_out: Path | None) -> tuple[tuple[str, ...], bool, bytes]:
    domains = ca_domains(domains_file.read_text(encoding="utf-8", errors="replace"))
    if not domains:
        raise SystemExit(f"No valid domains in {domains_file}")
    state.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = state / CERT_FILE, state / KEY_FILE

    cert_pem, key_pem = _read_regular(cert_path), _read_regular(key_path)
    # Keep the existing CA only if it is exactly right AND its key belongs to it.
    created = not (cert_pem and key_pem and not verify_ca_cert(cert_pem, domains)
                   and _key_matches(key_pem, cert_pem))
    if created:
        for old in state.glob("mitmproxy-*"):  # stale CA and anything mitmproxy derived from it
            old.unlink()
        key_pem, cert_pem = new_ca(domains)
        _write_new(key_path, key_pem + cert_pem, 0o600)
        _write_new(cert_path, cert_pem, 0o644)
    if ca_out is not None:
        ca_out.parent.mkdir(parents=True, exist_ok=True)
        _write_new(ca_out, cert_pem, 0o644)
    return domains, created, cert_pem


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "--verify":
        domains = ca_domains(Path(argv[2]).read_text(encoding="utf-8", errors="replace"))
        problems = verify_ca_cert(Path(argv[1]).read_bytes(), domains)
        for problem in problems:
            print("ai-dlp CA check failed: " + problem, file=sys.stderr)
        return 1 if problems else 0
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    to_stdout = argv[2] == "-"
    domains, created, cert_pem = ensure_ca(Path(argv[0]), Path(argv[1]), None if to_stdout else Path(argv[2]))
    print("domains: " + " ".join(domains))
    print("ca: " + ("new" if created else "kept"))
    if to_stdout:
        sys.stdout.write(cert_pem.decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
