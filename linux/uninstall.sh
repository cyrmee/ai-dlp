#!/bin/bash
# Remove ai-dlp completely: routing, proxy, CA trust, CA key, secret list, user.
# mitmproxy and gitleaks packages are left installed (remove with: pacman -Rs mitmproxy gitleaks).
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }

systemctl disable --now ai-dlp-firewall ai-dlp-proxy 2>/dev/null
nft delete table inet ai_dlp 2>/dev/null
if [[ -f /etc/ai-dlp/ca.pem ]]; then
  trust anchor --remove /etc/ai-dlp/ca.pem 2>/dev/null
  update-ca-trust
fi
sed -i '\|^NODE_EXTRA_CA_CERTS=/etc/ai-dlp/ca.pem$|d' /etc/environment
rm -f /etc/systemd/system/ai-dlp-proxy.service /etc/systemd/system/ai-dlp-firewall.service
systemctl daemon-reload
rm -rf /etc/ai-dlp /var/lib/ai-dlp /usr/local/lib/ai-dlp /var/log/ai-dlp   # logs include stored request copies
rm -f /usr/local/bin/ai-dlp /usr/local/bin/ai-dlp-secrets /etc/sysusers.d/ai-dlp.conf
rm -f /etc/opt/chrome/policies/managed/ai-dlp.json /etc/chromium/policies/managed/ai-dlp.json /etc/brave/policies/managed/ai-dlp.json
ff=/etc/firefox/policies/policies.json
[[ -f $ff ]] && grep -q 'network.dns.echconfig.enabled' "$ff" && grep -q '"DNSOverHTTPS"' "$ff" && [[ $(wc -l < "$ff") -le 12 ]] && rm -f "$ff"
userdel ai-dlp 2>/dev/null
echo "ai-dlp removed. Log out and back in to clear NODE_EXTRA_CA_CERTS from your session."
