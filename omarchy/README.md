# ai-dlp bar widget for Omarchy

A bar widget for [Omarchy](https://omarchy.org) that shows what ai-dlp is doing:

- **Shield icon:**
  - a check mark while inspecting;
  - crossed out when off;
  - an alert when the proxy is down while routing is on.
- **Flashes:**
  - the accent colour when secrets are redacted or a new image or PDF is sent;
  - the alert colour when a request is blocked.
- **Panel:**
  - today's allowed, redacted and blocked counts, plus images and PDFs;
  - a live list of recent requests, showing matched rules, block reasons and attachments;
  - a switch to turn inspection on or off (asks for your password).
- **Notifications** for blocks, redactions (at most once a minute) and new attachments. Each can be turned off in the widget's settings.

It reads the proxy's event log (`/var/log/ai-dlp/events.jsonl`), which never contains secret values.

## Install

Install ai-dlp for Linux first (`sudo ./linux/install.sh`), then:

```sh
cp -r omarchy/ai-dlp.widget ~/.config/omarchy/plugins/
omarchy plugin enable ai-dlp.widget --section right
```

Keys in the panel:
- `A`: show all requests or only flagged ones.
- `R`: refresh.
- `Enter` twice: flip the switch.
