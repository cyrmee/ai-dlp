# ai-dlp

**Stop secrets from leaking into AI chats and APIs.**

ai-dlp is a local data-loss-prevention proxy. Every request your computer sends to an AI service (Claude, ChatGPT, Gemini, Mistral, DeepSeek, Perplexity, Grok, OpenRouter and more) is inspected on the way out. API keys, tokens, passwords and your own listed secret values are replaced with `[REDACTED:<rule>]` before they leave the machine. Images and PDFs, which cannot be scanned for text, are flagged.

It targets the most common way secrets reach an AI service by accident: a coding agent reads a `.env` file, a config, a log or command output that contains a key, or someone pastes one into a chat, and it becomes part of the prompt.

> Not affiliated with Anthropic, OpenAI, Google or any other AI provider.

## Platforms

- **Linux:** used daily on Arch (Omarchy). Packages come from pacman, routing from nftables, services from systemd.
- **macOS:** experimental. CI runs the installer on GitHub's macOS runners, but capture itself has not been tested on a Mac. Uses mitmproxy's local capture mode, a launchd daemon and the System keychain. Everything the root daemon runs lives in root-owned `/Library/ai-dlp`: pinned, checksum-verified downloads of uv, Python and gitleaks.
- **Windows:** experimental. CI runs the installer on GitHub's Windows runners, but capture itself has not been tested on Windows. Uses mitmproxy's local capture mode (WinDivert), a SYSTEM scheduled task and the machine certificate store. It requires an all-users Python, because the proxy runs as SYSTEM.

The core (`core/`) is the same everywhere; CI runs its tests on Linux, macOS and Windows. Reports from macOS and Windows users are very welcome.

## How it works

1. **Capture.** Every outgoing HTTPS connection from your apps is sent to a local [mitmproxy](https://mitmproxy.org) instance.
   - **Linux:** an nftables redirect. It covers user programs; root, local and private addresses are exempt.
   - **macOS and Windows:** mitmproxy's local capture mode.
2. **Decision by domain name.** The proxy reads the name in each TLS handshake (SNI).
   - Domains in `domains.txt`, and their subdomains, are decrypted and inspected.
   - Everything else is passed through as raw bytes, never decrypted or recorded.

   Nothing depends on a provider's IP addresses, so a provider moving to new addresses changes nothing. Lookalikes such as `evilanthropic.com` do not match.
3. **Scanning.** Each inspected request body is checked two ways:
   - against your own **exact secret values**;
   - with **[gitleaks](https://github.com/gitleaks/gitleaks)**: its full default rule set (about 200 credential formats, with keyword and entropy checks) plus extra rules for passwords in URLs and `password=` lines (values of 4+ characters; placeholders such as `null` or `<value>` are ignored).

   Listed values shorter than 8 characters only match as whole words, so a short password does not redact every word containing it.

   **Images and PDFs** are read too. On Linux, OCR is done with [tesseract](https://github.com/tesseract-ocr/tesseract), PDFs' text layers with poppler, and scanned PDF pages with OCR. Elsewhere, only the readable text inside the file is checked. A secret found inside an image or PDF cannot be blacked out in the file, so that request is blocked. Results are cached, so a resent conversation is not OCR'd again.

   JSON bodies are parsed and each string is scanned separately. Results are cached, so conversation history an agent resends every turn is not scanned again.
4. **Redaction.** Each match is replaced with `[REDACTED:<rule-id>]` and the request continues.
5. **Fail closed.** If a body cannot be scanned reliably (scanner error, undecodable encoding, a finding that cannot be located), the request is blocked with a clear error instead of being sent.
6. **Attachments.** Each image or PDF is recorded the first time it is sent, with its type, size and name. Other binary uploads that cannot be read (zip, docx and the like) are blocked; audio and video are allowed and flagged.
7. **Event log.** `events.jsonl` gets one line per inspected request: outcome, host, path, rule names and attachments. It never contains secret values.

### The certificate authority

To read HTTPS, the proxy signs certificates with a local CA that your system trusts. That CA is **name-constrained**: it can only vouch for the domains in `domains.txt`. Even if its private key were stolen, it could not be used to impersonate your bank or any other site.
- The key is readable only by the proxy (Linux) or root/SYSTEM (macOS/Windows).
- The installer issues a new CA whenever the domain list changes.
- The CA deliberately has no IP-address constraint: some clients, Claude Code among them, cannot check one and reject every certificate from a CA that has it.

A listed domain is only intercepted once the CA covers it, so editing the list never breaks a site; `ai-dlp domains` shows which are covered.

## Install

### Linux (Arch-based)

```sh
git clone https://github.com/cyrmee/ai-dlp && cd ai-dlp
sudo ./linux/install.sh        # installs mitmproxy, gitleaks; creates the CA; starts the proxy
ai-dlp on                      # start routing HTTPS through the proxy
ai-dlp test --claude           # check redaction, passthrough, and Claude Code
```

The installer also:
- sets browser policies for Chrome, Chromium, Brave and Firefox: no QUIC/HTTP3 and no Encrypted Client Hello, plus no DNS-over-HTTPS for Firefox;
- trusts the CA system-wide;
- sets `NODE_EXTRA_CA_CERTS` in `/etc/environment`. Restart your browser and AI apps afterwards.

On Linux, if the proxy stops while routing is on, HTTPS from your apps cannot connect until it restarts (automatic) or you run `ai-dlp off`. Unlisted sites are only relayed, never decrypted.

### macOS (experimental)

```sh
git clone https://github.com/cyrmee/ai-dlp && cd ai-dlp
sudo ./macos/install.sh
ai-dlp on                      # first time: allow the "Mitmproxy Redirector" network extension
ai-dlp test --claude
```

### Windows (experimental)

From an Administrator PowerShell:

```powershell
winget install -e --id Python.Python.3.12 --scope machine   # all-users install is required
git clone https://github.com/cyrmee/ai-dlp; cd ai-dlp
powershell -ExecutionPolicy Bypass -File .\windows\install.ps1
# open a new terminal, then:
ai-dlp on
ai-dlp test --claude
```

On macOS and Windows, if the proxy is stopped, traffic flows normally (unscanned): keep it on.

### Claude Code

Claude Code trusts the operating system's certificate store, but reads it once at startup: restart running sessions after installing. As a backstop, point it at the CA in `~/.claude/settings.json`:

```json
{ "env": { "NODE_EXTRA_CA_CERTS": "/etc/ai-dlp/ca.pem" } }
```

On macOS use `/Library/Application Support/ai-dlp/ca.pem`; on Windows, `C:\\ProgramData\\ai-dlp\\ca.pem`.

## Choosing which services are inspected

The list lives in `domains.txt`:
- **Linux:** `/etc/ai-dlp/domains.txt`
- **macOS:** `/Library/Application Support/ai-dlp/domains.txt`
- **Windows:** `C:\ProgramData\ai-dlp\domains.txt`

By default it covers Anthropic/Claude, OpenAI/ChatGPT (including Azure OpenAI), Google Gemini and AI Studio, Microsoft Copilot (chat), Mistral, Groq, DeepSeek, Perplexity, xAI/Grok, Cohere, OpenRouter, Together, Fireworks, Meta AI and Hugging Face inference.

Coding assistants (GitHub Copilot, Cursor, Codeium/Windsurf, Tabnine) are listed but commented out: some of them pin certificates or relay through their own servers and may stop connecting when intercepted. Enable them one at a time.

After editing the list, run the installer again (it issues a matching CA), then restart your browser and AI apps.

## Commands

- `ai-dlp status`: is the proxy (and, on Linux, routing) running.
- `ai-dlp domains`: inspected domains, and whether the CA covers each one.
- `ai-dlp on` / `ai-dlp off`: start or stop inspection.
- `ai-dlp test [--claude]`: three checks:
  - random fake keys sent through the proxy come back redacted (answered locally, never sent);
  - an unlisted site keeps its real certificate;
  - with `--claude`, a new Claude Code session connects.
- `ai-dlp log`: redaction, block and attachment events.
- `ai-dlp add-secrets FILE...`: add your own secret values to the exact-match list.
  - Accepts `.env` files, `--pgpass FILE`, or values piped on stdin.
  - On Linux, `--pass` also reads your `pass` store.

## Omarchy bar widget (Linux)

`omarchy/ai-dlp.widget` is a bar widget for [Omarchy](https://omarchy.org). Its shield shows the state, lights up on redactions, blocks and attachments, and opens a panel with today's counts, a live request list and an on/off switch. See [omarchy/README.md](omarchy/README.md).

## Limits

- **Pattern-based detection.** Unusual passwords, secrets that are encoded, split or disguised, and values not on your list can get through. Treat ai-dlp as a safety net behind keeping secrets out of an agent's reach (sandboxes, read-deny rules), not as a replacement.
- **Images and PDFs:** OCR (Linux) reads printed and screenshot text well, but handwriting, tiny or distorted text, and text in other scripts can be missed. Scanned PDFs are OCR'd up to 20 text-less pages; longer ones are blocked.
- **The domain name must be visible, or the address known.**
  - Connections without a name, or with Encrypted Client Hello, are forced through inspection when they go to an address a listed service uses; the proxy learns these from DNS and from its own connections.
  - A client that deliberately sends a different, unlisted name to a shared CDN address (domain fronting) is not caught. That is deliberate evasion, which ai-dlp does not try to stop.
- **Not covered:** root processes on Linux, containers and VMs, and apps that pin certificates.
- **Responses are not inspected**, only what is sent.

## Uninstall

- **Linux:** `sudo ./linux/uninstall.sh`
- **macOS:** `sudo ./macos/uninstall.sh`
- **Windows:** `.\windows\uninstall.ps1`, from an Administrator PowerShell.

Each removes the proxy, the CA and its trust, the browser policies and all files.

## Development

```sh
python -m pip install cryptography
python -I tests/test_ai_dlp.py
```

The tests use a stand-in for gitleaks, so neither mitmproxy nor gitleaks is needed to run them.

## License

[MIT](LICENSE)
