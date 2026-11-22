#!/bin/bash
# ai-dlp installer for macOS (EXPERIMENTAL: not yet tested on a Mac).
#
# No prerequisites. Run:   sudo ./macos/install.sh
#
# Traffic capture uses mitmproxy's local capture mode. The first time the proxy
# starts, macOS asks you to allow the "Mitmproxy Redirector" network extension in
# System Settings > General > Login Items & Extensions (or Privacy & Security).
# Installs the proxy but does not start it; turn it on with `ai-dlp on`.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd)
CORE=$(cd "$SRC/../core" && pwd)
MITMPROXY_VERSION=12.2.3
GITLEAKS_VERSION=8.30.1
UV_VERSION=0.13.0
# Under /Library, which is always root-owned (Homebrew can make /usr/local user-owned).
PREFIX=/Library/ai-dlp
CONF="/Library/Application Support/ai-dlp"
STATE="$CONF/state"
LOGS=/Library/Logs/ai-dlp
LABEL=dev.ai-dlp.proxy
PLIST=/Library/LaunchDaemons/$LABEL.plist
KEYCHAIN=/Library/Keychains/System.keychain
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"   # nothing from user-writable Homebrew folders

step() { printf '\n==> %s\n' "$*"; }

# The proxy runs as root: every file it executes must be root-owned and not writable by
# group/other, including every directory on the way to it.
assert_root_only() {
  local p=$1
  while :; do
    read -r owner perms <<< "$(stat -f '%Su %Sp' "$p")"
    [[ $owner == root && ${perms:5:1} != w && ${perms:8:1} != w ]] \
      || { echo "Refusing: $p is owned by $owner with $perms (must be root-owned, not group/other writable)." >&2; exit 1; }
    [[ $p == / ]] && break
    p=$(dirname "$p")
  done
}

fetch_verified() {   # fetch_verified URL SHA256 DEST
  curl -fsSL -o "$3" "$1"
  [[ -n $2 && $(shasum -a 256 "$3" | awk '{print $1}') == "$2" ]] || { echo "Checksum mismatch for $1" >&2; exit 1; }
}

case $(uname -m) in
  arm64) uv_arch=aarch64; gl_arch=arm64 ;;
  x86_64) uv_arch=x86_64; gl_arch=x64 ;;
  *) echo "Unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
install -d -m 755 -o root -g wheel "$PREFIX" "$PREFIX/bin"
assert_root_only "$PREFIX"
dl=$(mktemp -d); trap 'rm -rf "$dl"' EXIT

step "uv $UV_VERSION (checksum verified, into $PREFIX/bin)"
uv_tar="uv-${uv_arch}-apple-darwin.tar.gz"
uv_url="https://github.com/astral-sh/uv/releases/download/$UV_VERSION"
curl -fsSL -o "$dl/uv.sha256" "$uv_url/$uv_tar.sha256"
fetch_verified "$uv_url/$uv_tar" "$(awk '{print $1}' "$dl/uv.sha256")" "$dl/$uv_tar"
tar -xzf "$dl/$uv_tar" -C "$dl"
install -m 755 -o root -g wheel "$dl/uv-${uv_arch}-apple-darwin/uv" "$PREFIX/bin/uv"
UV="$PREFIX/bin/uv"

step "Python 3.12 and mitmproxy $MITMPROXY_VERSION (uv-managed, inside $PREFIX only)"
export UV_PYTHON_INSTALL_DIR="$PREFIX/python" UV_CACHE_DIR="$PREFIX/cache" UV_NO_CONFIG=1
"$UV" python install --quiet --managed-python --install-dir "$PREFIX/python" 3.12
"$UV" venv --quiet --allow-existing --managed-python --python 3.12 "$PREFIX/venv"
"$UV" pip install --quiet --python "$PREFIX/venv/bin/python" "mitmproxy==$MITMPROXY_VERSION"
PY="$PREFIX/venv/bin/python"
chown -R root:wheel "$PREFIX"
chmod -R go-w "$PREFIX"
for p in "$(realpath "$PY")" "$("$PY" -I -c 'import os, sys; print(os.path.realpath(sys.base_prefix))')"; do
  [[ $p == "$PREFIX"/* ]] || { echo "Refusing: the proxy's Python resolves to $p, outside $PREFIX." >&2; exit 1; }
  assert_root_only "$p"
done

step "gitleaks $GITLEAKS_VERSION (checksum verified, into $PREFIX/bin)"
gl_tar="gitleaks_${GITLEAKS_VERSION}_darwin_${gl_arch}.tar.gz"
gl_url="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
curl -fsSL -o "$dl/sums.txt" "$gl_url/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
fetch_verified "$gl_url/$gl_tar" "$(awk -v f="$gl_tar" '$2 == f {print $1}' "$dl/sums.txt")" "$dl/$gl_tar"
tar -xzf "$dl/$gl_tar" -C "$dl" gitleaks
install -m 755 -o root -g wheel "$dl/gitleaks" "$PREFIX/bin/gitleaks"
rm -rf "$dl"; trap - EXIT

step "Installing files"
install -d -m 755 "$CONF" "$LOGS"
install -d -m 700 "$STATE"
for f in ai_dlp.py make_ca.py aidlp_tool.py gitleaks.toml; do install -m 644 "$CORE/$f" "$CONF/"; done
[[ -f $CONF/domains.txt ]] || install -m 644 "$CORE/domains.txt" "$CONF/domains.txt"   # keep your edits
[[ -f $CONF/secrets.txt ]] || install -m 600 /dev/null "$CONF/secrets.txt"
install -m 755 "$SRC/ai-dlp" /usr/local/bin/ai-dlp

step "Certificate authority limited to the listed domains"
old_sha=""
[[ -f $CONF/ca.pem ]] && old_sha=$(openssl x509 -in "$CONF/ca.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)
result=$("$PY" -I "$CONF/make_ca.py" "$CONF/domains.txt" "$STATE" "$CONF/ca.pem")
echo "$result"
"$PY" -I "$CONF/make_ca.py" --verify "$CONF/ca.pem" "$CONF/domains.txt" \
  || { echo "Refusing to trust the generated certificate (see above)." >&2; exit 1; }
chmod 644 "$CONF/ca.pem"
NEW_CA=0
if grep -qx 'ca: new' <<< "$result"; then
  NEW_CA=1
  [[ -n $old_sha ]] && security delete-certificate -Z "$old_sha" "$KEYCHAIN" >/dev/null 2>&1 || true
fi

step "Trusting the CA in the System keychain"
# macOS asks for confirmation here. AI_DLP_SKIP_TRUST=1 skips this step; it exists only
# for CI runners, which cannot answer that prompt (without trust, nothing is inspected).
if [[ ${AI_DLP_SKIP_TRUST:-} == 1 ]]; then
  echo "AI_DLP_SKIP_TRUST=1: not trusting the CA (CI only)."
else
  security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN" "$CONF/ca.pem"
fi

step "Chrome and Edge: no QUIC and no Encrypted Client Hello (both would hide or skip the proxy)"
install -d -m 755 "/Library/Managed Preferences"
for app in com.google.Chrome com.microsoft.Edge com.brave.Browser; do
  defaults write "/Library/Managed Preferences/$app" QuicAllowed -bool false
  defaults write "/Library/Managed Preferences/$app" EncryptedClientHelloEnabled -bool false
done
ffp=/Library/Preferences/org.mozilla.firefox
defaults write "$ffp" EnterprisePoliciesEnabled -bool true
defaults write "$ffp" DNSOverHTTPS -dict Enabled -bool false Locked -bool true
for pref in network.dns.echconfig.enabled network.dns.http3_echconfig.enabled network.http.http3.enable; do
  defaults write "$ffp" Preferences -dict-add "$pref" '<dict><key>Value</key><false/><key>Status</key><string>locked</string></dict>'
done

step "Launch daemon $LABEL (installed, not started)"
was_running=0
launchctl print "system/$LABEL" >/dev/null 2>&1 && was_running=1
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PREFIX/venv/bin/mitmdump</string>
    <string>--mode</string><string>local</string>
    <string>--set</string><string>confdir=$STATE</string>
    <string>--set</string><string>flow_detail=0</string>
    <string>--set</string><string>termlog_verbosity=info</string>
    <string>-s</string><string>$CONF/ai_dlp.py</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/usr/bin:/bin</string>
    <key>AI_DLP_GITLEAKS</key><string>$PREFIX/bin/gitleaks</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOGS/proxy.log</string>
  <key>StandardErrorPath</key><string>$LOGS/proxy.log</string>
</dict>
</plist>
EOF
chmod 644 "$PLIST"
if (( was_running )); then
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  launchctl bootstrap system "$PLIST"
  echo "The proxy was on: restarted it with the new files."
fi

if (( NEW_CA )); then
  echo
  echo "NOTE: a new certificate authority was issued. Restart your browser and AI apps."
fi

cat <<EOF

Installed. Next steps:
  1. Turn it on:              ai-dlp on
     The first time, allow the "Mitmproxy Redirector" network extension when macOS asks.
  2. Check it works:          ai-dlp test --claude
  3. Add your own secrets:    sudo ai-dlp add-secrets path/to/.env
  4. Claude Code: add  "env": {"NODE_EXTRA_CA_CERTS": "$CONF/ca.pem"}  to ~/.claude/settings.json

Unlike Linux, if the proxy is stopped, traffic flows normally (unscanned): keep it on.
Undo everything with: sudo $SRC/uninstall.sh
EOF
