#!/bin/bash
# ai-dlp installer for Linux (Arch-based; uses pacman, systemd and nftables).
# Run as root:  sudo ./linux/install.sh
# Installs and starts the proxy. Routing is turned on separately (`ai-dlp on`); if it
# is already on, re-running this reloads the rules. Safe to run again, for example
# after editing /etc/ai-dlp/domains.txt.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
SRC=$(dirname "$(readlink -f "$0")")
CORE=$(readlink -f "$SRC/../core")
STATE=/var/lib/ai-dlp
ETC=/etc/ai-dlp

step() { printf '\n==> %s\n' "$*"; }

if [[ -f /etc/systemd/system/claude-dlp-proxy.service ]]; then
  echo "An older install named claude-dlp is present. Remove it first with its uninstall.sh." >&2
  exit 1
fi

step "Installing mitmproxy, gitleaks and OCR tools (tesseract, poppler) from the Arch repos"
pacman -S --needed --noconfirm mitmproxy gitleaks python-cryptography tesseract tesseract-data-eng poppler

step "Creating system user ai-dlp"
install -Dm644 "$SRC/ai-dlp.sysusers" /etc/sysusers.d/ai-dlp.conf
systemd-sysusers /etc/sysusers.d/ai-dlp.conf

step "Installing files"
install -dm755 "$ETC"
install -m644 "$CORE/ai_dlp.py" "$CORE/make_ca.py" "$CORE/aidlp_tool.py" "$CORE/gitleaks.toml" "$SRC/ai-dlp.nft" "$ETC/"
[[ -f $ETC/domains.txt ]] || install -m644 "$CORE/domains.txt" "$ETC/domains.txt"   # keep your edits
[[ -f $ETC/secrets.txt ]] || install -m640 -o root -g ai-dlp /dev/null "$ETC/secrets.txt"
install -Dm755 "$SRC/merge-secrets" /usr/local/lib/ai-dlp/merge-secrets
install -Dm755 "$SRC/ai-dlp" /usr/local/bin/ai-dlp
install -Dm755 "$SRC/ai-dlp-secrets" /usr/local/bin/ai-dlp-secrets
install -m644 "$SRC/ai-dlp-proxy.service" "$SRC/ai-dlp-firewall.service" /etc/systemd/system/

step "Chrome/Chromium: no QUIC and no Encrypted Client Hello (both would hide or skip the proxy)"
for dir in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed /etc/brave/policies/managed; do
  install -Dm644 "$CORE/chrome-policy.json" "$dir/ai-dlp.json"
done
# Firefox reads a single policies.json: install ours only if there is none (or it is ours).
ff=/etc/firefox/policies/policies.json
if [[ ! -e $ff ]] || cmp -s "$ff" "$CORE/firefox-policies.json"; then
  install -Dm644 "$CORE/firefox-policies.json" "$ff"
else
  echo "NOTE: $ff already exists; merge $CORE/firefox-policies.json into it by hand (turns off ECH)." >&2
fi

step "Certificate authority limited to the listed domains"
install -dm700 -o ai-dlp -g ai-dlp "$STATE"
old_ca=$(mktemp); new_ca=$(mktemp); trap 'rm -f "$old_ca" "$new_ca"' EXIT
[[ -f $ETC/ca.pem ]] && cp "$ETC/ca.pem" "$old_ca" || : > "$old_ca"
# $STATE belongs to the proxy user, so the CA is made AS that user: root never creates,
# follows or reads files there. The public certificate comes back on stdout.
result=$(runuser -u ai-dlp -- python3 -I "$ETC/make_ca.py" "$ETC/domains.txt" "$STATE" -)
sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p' <<< "$result" > "$new_ca"
# Never trust what the unprivileged side returned without checking it as root: exactly
# one CA certificate whose critical name constraints are exactly the listed domains.
python3 -I "$ETC/make_ca.py" --verify "$new_ca" "$ETC/domains.txt" \
  || { echo "Refusing to trust the certificate returned for the proxy (see above)." >&2; exit 1; }
grep -E '^(domains|ca): ' <<< "$result"
install -m644 -o root -g root "$new_ca" "$ETC/ca.pem"
NEW_CA=0
if grep -qx 'ca: new' <<< "$result"; then
  NEW_CA=1
  [[ -s $old_ca ]] && trust anchor --remove "$old_ca" 2>/dev/null || true
fi

step "Trusting the CA system-wide (browsers, Electron apps, curl)"
trust anchor --remove "$ETC/ca.pem" 2>/dev/null || true
trust anchor --store "$ETC/ca.pem"
update-ca-trust

step "Setting NODE_EXTRA_CA_CERTS for Node/Bun apps (/etc/environment)"
if grep -q '^NODE_EXTRA_CA_CERTS=' /etc/environment; then
  if ! grep -qx "NODE_EXTRA_CA_CERTS=$ETC/ca.pem" /etc/environment; then
    echo "WARNING: /etc/environment already sets a different NODE_EXTRA_CA_CERTS; left unchanged." >&2
  fi
else
  echo "NODE_EXTRA_CA_CERTS=$ETC/ca.pem" >> /etc/environment
fi

step "Request details for the bar widget (last 50 requests, redacted; readable by you only)"
# The proxy keeps redacted copies of recent requests so the widget can show headers and
# payload. The folder is readable only by the proxy and the user who ran this installer.
owner=${SUDO_USER:-}
[[ -z $owner && -n ${PKEXEC_UID:-} ]] && owner=$(id -nu "$PKEXEC_UID" 2>/dev/null || true)
install -d -m 755 -o ai-dlp -g ai-dlp /var/log/ai-dlp
install -d -m 750 -o ai-dlp -g ai-dlp /var/log/ai-dlp/requests
if [[ -n $owner && $owner != root ]] && command -v setfacl >/dev/null; then
  setfacl -m "u:$owner:rx" -d -m "u:$owner:r" /var/log/ai-dlp/requests
  find /var/log/ai-dlp/requests -type f -exec setfacl -m "u:$owner:r" {} +
  echo "Readable by: ai-dlp, $owner"
else
  echo "NOTE: could not tell which user to give access; the widget will not show request details." >&2
fi

step "Starting the proxy"
systemctl daemon-reload
systemctl enable ai-dlp-proxy
systemctl restart ai-dlp-proxy   # also picks up an updated addon/unit on re-install
sleep 2
if ! systemctl is-active -q ai-dlp-proxy; then
  journalctl -u ai-dlp-proxy -n 40 --no-pager
  echo "The proxy failed to start (log above). Routing was NOT enabled." >&2
  exit 1
fi
if systemctl is-active -q ai-dlp-firewall; then
  systemctl restart ai-dlp-firewall
  echo "Routing was on: reloaded the routing rules."
fi

if (( NEW_CA )); then
  cat <<EOF

NOTE: a new certificate authority was issued. Restart your browser and every AI app
(Claude Code sessions included): they read trusted certificates at startup.
EOF
fi

cat <<EOF

Installed. Inspected domains: see \`ai-dlp domains\`.

Next steps:
  1. Add your own secret values (exact match, on top of gitleaks):
       ai-dlp add-secrets path/to/.env        # see ai-dlp add-secrets --help
  2. Turn routing on:        ai-dlp on
  3. Check it works:         ai-dlp test --claude
  4. Claude Code: add  "env": {"NODE_EXTRA_CA_CERTS": "$ETC/ca.pem"}  to ~/.claude/settings.json
     so every session trusts the CA however it is launched.

To cover another service, add its domain to $ETC/domains.txt and run this installer again.
Undo everything with: sudo $SRC/uninstall.sh
EOF
