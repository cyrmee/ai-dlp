#!/bin/bash
# Remove ai-dlp from macOS: proxy, CA trust, CA key, browser policies, files.
# Removes everything under /Library/ai-dlp too (uv, Python, gitleaks, mitmproxy).
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }

CONF="/Library/Application Support/ai-dlp"
LABEL=dev.ai-dlp.proxy

launchctl bootout "system/$LABEL" 2>/dev/null
rm -f "/Library/LaunchDaemons/$LABEL.plist"
if [[ -f $CONF/ca.pem ]]; then
  sha=$(openssl x509 -in "$CONF/ca.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)
  security delete-certificate -Z "$sha" /Library/Keychains/System.keychain >/dev/null 2>&1
fi
defaults delete /Library/Preferences/org.mozilla.firefox DNSOverHTTPS 2>/dev/null
defaults delete /Library/Preferences/org.mozilla.firefox Preferences 2>/dev/null
for app in com.google.Chrome com.microsoft.Edge com.brave.Browser; do
  defaults delete "/Library/Managed Preferences/$app" QuicAllowed 2>/dev/null
  defaults delete "/Library/Managed Preferences/$app" EncryptedClientHelloEnabled 2>/dev/null
done
rm -rf "$CONF" /Library/Logs/ai-dlp /Library/ai-dlp
rm -f /usr/local/bin/ai-dlp
echo "ai-dlp removed. You can also remove the Mitmproxy Redirector extension in System Settings."
