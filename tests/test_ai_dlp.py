"""Unit tests for the ai-dlp addon (no mitmproxy or real gitleaks needed).

Run:  python3 -I tests/test_ai_dlp.py      (from the repository root; needs `cryptography`)
"""
import asyncio
import importlib.util
import json
import os
import random
import string
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / "core"
LINUX = HERE.parent / "linux"
TMP = Path(tempfile.mkdtemp(prefix="ai-dlp-test-"))
SECRETS = TMP / "secrets.txt"
os.environ["AI_DLP_SECRETS"] = str(SECRETS)
EVENTS = TMP / "events.jsonl"
DOMAINS = TMP / "domains.txt"
os.environ["AI_DLP_DOMAINS"] = str(DOMAINS)
os.environ["AI_DLP_CA"] = str(TMP / "no-ca.pem")  # hermetic: ignore the installed CA
os.environ["AI_DLP_EVENTS"] = str(EVENTS)
os.environ["AI_DLP_GITLEAKS_CONFIG"] = str(ROOT / "gitleaks.toml")

sys.path.insert(0, str(ROOT))
import ai_dlp as dlp  # noqa: E402
import make_ca  # noqa: E402

# Run the stand-in gitleaks through this interpreter (works on Windows too).
dlp.GITLEAKS_CMD = [sys.executable, str(HERE / "fake_gitleaks.py")]


def rnd(n, abc=string.ascii_letters + string.digits):
    return "".join(random.choice(abc) for _ in range(n))


def run(coro):
    return asyncio.run(coro)


def body_of(*texts):
    return json.dumps({"model": "claude-x", "messages": [
        {"role": "user", "content": [{"type": "text", "text": t} for t in texts]}]}).encode()


class RedactTests(unittest.TestCase):
    def setUp(self):
        SECRETS.write_text("")
        self.gl = dlp.Gitleaks()
        self.secrets = dlp.SecretList(SECRETS)

    def redact(self, body):
        return run(dlp.redact(body, self.secrets.current(), self.gl))

    def test_known_secret_exact_match_including_json_escaping(self):
        secret = 'Tg"api\\hash' + rnd(12)  # quote and backslash get JSON-escaped
        SECRETS.write_text(secret + "\nshort\n")
        out, counts = self.redact(body_of(f"TG_API_HASH={secret}\nnext line"))
        self.assertNotIn(json.dumps(secret)[1:-1].encode(), out)
        self.assertIn(b"[REDACTED:known-secret]", out)
        self.assertEqual(counts["known-secret"], 1)
        json.loads(out)  # still valid JSON

    def test_known_secret_hidden_by_json_unicode_escapes_is_blocked(self):
        secret = "s3cretValue" + rnd(10)
        SECRETS.write_text(secret + "\n")
        escaped = "".join(f"\\u{ord(c):04x}" for c in secret)  # decodes to the secret
        body = ('{"messages":[{"role":"user","content":"token ' + escaped + '"}]}').encode()
        self.assertNotIn(secret.encode(), body)
        self.assertEqual(json.loads(body)["messages"][0]["content"], "token " + secret)
        with self.assertRaises(dlp.ScanError):
            self.redact(body)

    def test_gitleaks_rules_fire_and_body_stays_valid_json(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        gh = "gh" + "p_" + rnd(36)
        out, counts = self.redact(body_of(f"key {aws}", f"token {gh} done"))
        self.assertNotIn(aws.encode(), out)
        self.assertNotIn(gh.encode(), out)
        self.assertEqual(counts["aws-access-token"], 1)
        self.assertEqual(counts["github-pat"], 1)
        json.loads(out)

    def test_url_password_only_password_is_replaced(self):
        pw = rnd(12) + "9x"
        out, _ = self.redact(body_of(f"DATABASE_URL=postgres://app:{pw}@db.internal:5432/app"))
        text = json.loads(out)["messages"][0]["content"][0]["text"]
        self.assertEqual(text, "DATABASE_URL=postgres://app:[REDACTED:url-password]@db.internal:5432/app")

    def test_short_passwords_are_caught(self):
        for template in ("password=ab12", 'DB_PASSWORD="xy9!"', "secret: 'qz7w'", "pwd=hunt3r"):
            v = template.split("=")[-1].split(":")[-1].strip(" '\"")
            out, counts = self.redact(body_of(template))
            self.assertNotIn(v.encode(), out, template)
            self.assertEqual(counts["password-assignment"], 1, template)

    def test_password_placeholders_are_left_alone(self):
        for text in ("password = null", "password: none", "pwd=true", "password=****", 'password="<value>"',
                     "password=[REDACTED:known-secret]", "password=abc"):
            body = body_of(text)
            out, counts = self.redact(body)
            self.assertEqual(out, body, text)

    def test_placeholder_url_passwords_are_left_alone(self):
        for url in ("postgres://user:password@localhost:5432/db", "redis://:secret@cache:6379",
                    "mysql://root:changeme@db/app", "amqp://guest:****@mq:5672"):
            body = body_of("DATABASE_URL=" + url)
            out, counts = self.redact(body)
            self.assertEqual(out, body, url)

    def test_secret_that_is_part_of_a_marker_does_not_block(self):
        # "known" is inside the marker [REDACTED:known-secret]; that must not look like a leak.
        SECRETS.write_text("known\n")
        out, counts = self.redact(body_of("the known value and a real one: postgres://app:Kangaroo42@db:5432/app"))
        text = json.loads(out)["messages"][0]["content"][0]["text"]
        self.assertIn("the [REDACTED:known-secret] value", text)
        self.assertIn("app:[REDACTED:url-password]@db", text)

    def test_fake_markers_and_your_prefix_are_not_allowlisted(self):
        for text, secret in (("postgres://app:[REDACTED:hunter2]@db:5432/x", "hunter2"),
                             ("password=yourRealPassword123", "yourRealPassword123"),
                             ("DB_PASSWORD=[REDACTED:Kangaroo42]", "Kangaroo42")):
            out, counts = self.redact(body_of(text))
            self.assertNotIn(secret.encode(), out, text)

    def test_echoed_real_markers_are_left_alone(self):
        for text in ("postgres://app:[REDACTED:url-password]@db:5432/x", "password=[REDACTED:known-secret]",
                     "password=your_password", "postgres://app:your-secret@db/x"):
            body = body_of(text)
            out, counts = self.redact(body)
            self.assertEqual(out, body, text)
            self.assertFalse(counts, text)

    def test_secret_hidden_in_a_fake_marker_is_still_caught(self):
        SECRETS.write_text("Zebra7731\n")
        hidden = "".join(f"\\u{ord(c):04x}" for c in "Zebra7731")  # decodes to the secret
        body = ('{"messages":[{"role":"user","content":"x [REDACTED:' + hidden + '] y"}]}').encode()
        with self.assertRaises(dlp.ScanError):
            self.redact(body)

    def test_short_listed_secret_matches_whole_words_only(self):
        SECRETS.write_text("k9x2\n")
        out, counts = self.redact(body_of("pin k9x2 here; also k9x2z and ak9x2 stay"))
        text = json.loads(out)["messages"][0]["content"][0]["text"]
        self.assertEqual(text, "pin [REDACTED:known-secret] here; also k9x2z and ak9x2 stay")

    def test_password_assignment_forms(self):
        for template in ("DB_PASSWORD={v}", 'password = "{v}"', "client_secret: {v}\nother: 1",
                         "spring.datasource.password={v}"):
            v = rnd(10) + "4!"
            out, _ = self.redact(body_of(template.format(v=v)))
            self.assertNotIn(v.encode(), out, template)

    def test_code_and_placeholders_are_left_alone(self):
        for text in ("String password = request.getPassword();",
                     "password: ${SPRING_DATASOURCE_PASSWORD}",
                     "DB_PASSWORD=${DB_PASSWORD}",
                     "postgres://app:${DB_PASS}@db:5432/app",
                     "if (password == null) return;"):
            body = body_of(text)
            out, counts = self.redact(body)
            self.assertEqual(out, body, text)
            self.assertFalse(counts, text)

    def test_unchanged_history_is_served_from_cache(self):
        history = [f"old message {i} " + rnd(30) for i in range(5)]
        self.redact(body_of(*history))
        cached = len(self.gl.cache)
        calls = []
        original = self.gl.run

        async def counting_run(data):
            calls.append(data)
            return await original(data)
        self.gl.run = counting_run
        self.redact(body_of(*history, "brand new message"))
        self.assertEqual(len(calls), 1)
        self.assertNotIn("old message 0", calls[0])  # only the new text was scanned
        self.assertGreater(len(self.gl.cache), cached)

    def test_real_image_payloads_are_not_scanned(self):
        import base64 as b64
        data = b64.b64encode(b"\x89PNG\r\n\x1a\n" + os.urandom(300)).decode()
        body = json.dumps({"messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}},
            {"type": "text", "text": "plain words here"}]}]}).encode()
        texts = dlp.texts_of(body)
        self.assertNotIn(data, texts)
        out, counts = self.redact(body)
        self.assertEqual(out, body)

    def test_text_disguised_as_an_image_is_scanned(self):
        import base64 as b64
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        data = b64.b64encode(f"not a png at all, key {aws}".encode()).decode()
        body = json.dumps({"x": {"type": "base64", "media_type": "image/png", "data": data}}).encode()
        with self.assertRaises(dlp.ScanError):  # found in decoded text, cannot be rewritten
            self.redact(body)

    def test_unscannable_binary_payload_is_blocked(self):
        import base64 as b64
        data = b64.b64encode(b"\x00\xff\xfe" + os.urandom(200)).decode()
        body = json.dumps({"x": {"type": "base64", "media_type": "application/octet-stream", "data": data}}).encode()
        with self.assertRaises(dlp.ScanError):
            self.redact(body)

    def test_secret_appended_to_a_real_png_is_caught(self):
        import base64 as b64
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        png = b"\x89PNG\r\n\x1a\n" + os.urandom(120) + f" key {aws} ".encode() + os.urandom(40)
        body = json.dumps({"messages": [{"role": "user", "content": [{"type": "image", "source": {
            "type": "base64", "media_type": "image/png", "data": b64.b64encode(png).decode()}}]}]}).encode()
        with self.assertRaises(dlp.ScanError):
            self.redact(body)

    def _multipart(self, *parts):
        b = b""
        for headers, payload in parts:
            b += b"--XyZ\r\n" + headers + b"\r\n\r\n" + payload + b"\r\n"
        return b + b"--XyZ--\r\n"

    def redact_ct(self, body, ct):
        return run(dlp.redact(body, self.secrets.current(), self.gl, ct))

    def test_multipart_text_part_secret_is_redacted(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        body = self._multipart((b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\nContent-Type: text/plain',
                                f"config key={aws}".encode()))
        out, counts = self.redact_ct(body, "multipart/form-data; boundary=XyZ")
        self.assertNotIn(aws.encode(), out)

    def test_multipart_base64_part_with_secret_is_blocked(self):
        import base64 as b64
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        body = self._multipart((b'Content-Disposition: form-data; name="f"\r\nContent-Type: text/plain\r\n'
                                b"Content-Transfer-Encoding: base64", b64.b64encode(f"key {aws}".encode())))
        with self.assertRaises(dlp.ScanError):
            self.redact_ct(body, "multipart/form-data; boundary=XyZ")

    def test_multipart_unscannable_binary_part_is_blocked(self):
        body = self._multipart((b'Content-Disposition: form-data; name="f"; filename="x.zip"\r\n'
                                b"Content-Type: application/zip", b"PK\x03\x04\x00\xff\xfe" + os.urandom(64)))
        with self.assertRaises(dlp.ScanError):
            self.redact_ct(body, "multipart/form-data; boundary=XyZ")

    def test_audio_body_is_allowed(self):
        audio = b"\x1aE\xdf\xa3" + os.urandom(200)  # WebM/Matroska header + data
        out, counts = self.redact_ct(audio, "audio/webm")
        self.assertEqual(out, audio)

    def test_binary_body_of_unknown_type_is_blocked(self):
        with self.assertRaises(dlp.ScanError):
            self.redact_ct(b"\x00\xff\xfe" + os.urandom(100), "application/octet-stream")

    def test_form_encoded_secret_is_caught(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        hidden = "".join(f"%{ord(c):02X}" for c in aws)  # fully percent-encoded
        with self.assertRaises(dlp.ScanError):
            self.redact(f"note=hello&key={hidden}".encode())

    def test_percent_encoded_known_secret_is_redacted(self):
        secret = "my secret/value+" + rnd(8)
        SECRETS.write_text(secret + "\n")
        from urllib.parse import quote_plus
        out, counts = self.redact(f"a=1&pw={quote_plus(secret)}".encode())
        self.assertEqual(counts["known-secret"], 1)
        self.assertNotIn(quote_plus(secret).encode(), out)

    def test_fake_base64_shape_is_still_scanned(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        body = json.dumps({"x": {"type": "base64", "media_type": "image/png",
                                 "data": "not base64 at all: " + aws}}).encode()
        out, counts = self.redact(body)
        self.assertNotIn(aws.encode(), out)

    def test_secret_inside_base64_text_document_is_blocked(self):
        import base64 as b64
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        data = b64.b64encode(f"config\nkey={aws}\n".encode()).decode()
        body = json.dumps({"messages": [{"role": "user", "content": [
            {"type": "document", "source": {"type": "base64", "media_type": "text/plain", "data": data}}]}]}).encode()
        with self.assertRaises(dlp.ScanError):
            self.redact(body)

    def test_every_copy_of_a_duplicated_key_is_scanned(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        body = ('{"messages":[{"role":"user","content":"' + aws + '","content":"harmless"}]}').encode()
        self.assertEqual(json.loads(body)["messages"][0]["content"], "harmless")  # what json keeps
        out, counts = self.redact(body)
        self.assertNotIn(aws.encode(), out)
        self.assertEqual(counts["aws-access-token"], 1)

    def test_gitleaks_failure_fails_closed(self):
        with self.assertRaises(dlp.ScanError):
            self.redact(body_of("FORCE_GITLEAKS_ERROR please"))

    def test_non_json_body_is_scanned_as_text(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        out, counts = self.redact(f"--boundary\r\nfile contents {aws}\r\n--boundary--".encode())
        self.assertNotIn(aws.encode(), out)
        self.assertEqual(counts["aws-access-token"], 1)

    def test_secret_list_reloads_on_change(self):
        a, b = rnd(16), rnd(16)
        SECRETS.write_text(a + "\n")
        os.utime(SECRETS, (1_000_000, 1_000_000))
        self.assertEqual(self.secrets.current(), [a])
        SECRETS.write_text(b + "\n")
        os.utime(SECRETS, (2_000_000, 2_000_000))  # distinct times: Windows clocks can tick every ~15 ms
        self.assertEqual(self.secrets.current(), [b])


class AddonHookTests(unittest.TestCase):
    """Drive AiDLP.request with a minimal fake flow."""

    class Headers(dict):
        def get(self, k, d=None):
            return super().get(k.lower(), d)

    class Req:
        def __init__(self, host, body, headers=None):
            self.pretty_host, self.path, self._body = host, "/v1/messages?beta=true", body
            self.method = "POST"
            self.headers = AddonHookTests.Headers(headers or {})

        def get_content(self, strict=True):
            return self._body

        def set_content(self, b):
            self._body = b

    class Flow:
        def __init__(self, req, sni=None):
            self.request, self.response = req, None
            self.client_conn = type("Client", (), {"sni": sni if sni is not None else req.pretty_host})()

    class FakeResponse:
        @staticmethod
        def make(status, body, headers):
            return (status, body if isinstance(body, bytes) else body.encode(), headers)

    def setUp(self):
        SECRETS.write_text("")
        EVENTS.unlink(missing_ok=True)
        dlp.http = type("http", (), {"Response": self.FakeResponse})
        self.addon = dlp.AiDLP()

    def events(self):
        return [json.loads(l) for l in EVENTS.read_text().splitlines()] if EVENTS.exists() else []

    def test_events_record_action_rules_and_never_values(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        run(self.addon.request(self.Flow(self.Req("api.anthropic.com", body_of("plain hello")))))
        run(self.addon.request(self.Flow(self.Req("api.anthropic.com", body_of(f"k={aws}")))))
        run(self.addon.request(self.Flow(self.Req("claude.ai", body_of("FORCE_GITLEAKS_ERROR")))))
        run(self.addon.request(self.Flow(self.Req("example.com", body_of(f"k={aws}")))))
        ev = self.events()
        self.assertEqual([e["action"] for e in ev], ["allowed", "redacted", "blocked"])
        self.assertEqual(ev[0]["path"], "/v1/messages")  # query string dropped
        self.assertEqual(ev[1]["rules"], {"aws-access-token": 1})
        self.assertIn("gitleaks exited", ev[2]["reason"])
        self.assertNotIn(aws, EVENTS.read_text())

    def test_event_log_rotates(self):
        dlp.EVENTS_MAX_BYTES, old = 10, dlp.EVENTS_MAX_BYTES
        try:
            for _ in range(3):
                run(self.addon.request(self.Flow(self.Req("api.anthropic.com", body_of("plain hello")))))
            self.assertTrue((TMP / "events.jsonl.1").exists())
            self.assertEqual(len(self.events()), 1)
        finally:
            dlp.EVENTS_MAX_BYTES = old

    def test_redacts_request_to_anthropic(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        flow = self.Flow(self.Req("api.anthropic.com", body_of(f"k={aws}")))
        run(self.addon.request(flow))
        self.assertNotIn(aws.encode(), flow.request._body)
        self.assertIsNone(flow.response)  # forwarded, not answered locally

    def test_listed_sni_is_scanned_even_with_an_unlisted_host_header(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        flow = self.Flow(self.Req("unlisted.example", body_of(f"k={aws}")), sni="api.anthropic.com")
        run(self.addon.request(flow))
        self.assertNotIn(aws.encode(), flow.request._body)

    def test_other_hosts_untouched(self):
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        body = body_of(f"k={aws}")
        flow = self.Flow(self.Req("example.com", body))
        run(self.addon.request(flow))
        self.assertEqual(flow.request._body, body)

    def test_scanner_error_blocks_request(self):
        flow = self.Flow(self.Req("claude.ai", body_of("FORCE_GITLEAKS_ERROR now")))
        run(self.addon.request(flow))
        status, body, _ = flow.response
        self.assertEqual(status, 400)
        self.assertIn(b"ai-dlp blocked", body)

    def test_echo_header_answers_locally(self):
        flow = self.Flow(self.Req("api.anthropic.com", body_of("hello there"), {"x-ai-dlp-echo": "1"}))
        run(self.addon.request(flow))
        status, body, _ = flow.response
        self.assertEqual(status, 200)
        self.assertIn(b"hello there", body)


class AttachmentTests(unittest.TestCase):
    def setUp(self):
        self.tracker = dlp.AttachmentTracker()

    def body(self, *blocks):
        return json.dumps({"messages": [{"role": "user", "content": list(blocks)}]}).encode()

    def image(self, data):
        return {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}}

    def pdf(self, data, title=None):
        block = {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": data}}
        if title:
            block["title"] = title
        return block

    def test_images_and_pdfs_are_flagged_once(self):
        img, pdf = rnd(400), rnd(800)
        first = self.tracker.find(self.body(self.image(img), self.pdf(pdf, "contract.pdf")), "application/json")
        self.assertEqual(sorted(a["kind"] for a in first), ["image", "pdf"])
        self.assertEqual([a.get("name") for a in first if a["kind"] == "pdf"], ["contract.pdf"])
        # next turn resends the history plus a new image: only the new one is flagged
        again = self.tracker.find(self.body(self.image(img), self.pdf(pdf), {"type": "text", "text": "hi"},
                                            self.image(rnd(300))), "application/json")
        self.assertEqual([a["kind"] for a in again], ["image"])

    def test_attachment_urls_are_logged_without_path_or_query(self):
        found = self.tracker.find(self.body(
            {"type": "image", "source": {"type": "url",
                                         "url": "https://cdn.example.com/a/b.png?X-Amz-Signature=abc123&token=zzz"}}),
            "application/json")
        self.assertEqual(found[0]["url"], "https://cdn.example.com")

    def test_url_and_file_sources(self):
        found = self.tracker.find(self.body(
            {"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}},
            {"type": "document", "source": {"type": "file", "file_id": "file_abc"}}), "application/json")
        self.assertEqual(sorted((a["kind"], a["source"]) for a in found), [("image", "url"), ("pdf", "file")])

    def test_multipart_upload(self):
        b = (b"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"scan.pdf\"\r\n"
             b"Content-Type: application/pdf\r\n\r\n%PDF-1.7 ...\r\n--x--\r\n")
        found = self.tracker.find(b, "multipart/form-data; boundary=x")
        self.assertEqual(found, [{"kind": "pdf", "media": "application/pdf", "bytes": len(b),
                                  "source": "upload", "name": "scan.pdf"}])

    def test_any_base64_payload_is_flagged(self):
        body = json.dumps({"tools": [{"blob": {"type": "base64", "media_type": "application/zip",
                                               "data": "UEsDBA" + "A" * 30}}]}).encode()
        found = self.tracker.find(body, "application/json")
        self.assertEqual([(a["kind"], a["media"]) for a in found], [("file", "application/zip")])

    def test_plain_text_request_flags_nothing(self):
        self.assertEqual(self.tracker.find(body_of("just text"), "application/json"), [])

    def test_event_records_attachment(self):
        EVENTS.unlink(missing_ok=True)
        addon = dlp.AiDLP()
        addon.ocr.tesseract = None  # this test is about the event; the bytes are not a readable image
        dlp.http = type("http", (), {"Response": AddonHookTests.FakeResponse})
        import base64 as b64
        png = b64.b64encode(b"\x89PNG\r\n\x1a\n" + os.urandom(90)).decode()
        req = AddonHookTests.Req("api.anthropic.com", self.body(self.image(png)),
                                 {"content-type": "application/json"})
        run(addon.request(AddonHookTests.Flow(req)))
        ev = json.loads(EVENTS.read_text().splitlines()[-1])
        self.assertEqual(ev["attachments"][0]["kind"], "image")


class DomainTests(unittest.TestCase):
    def setUp(self):
        DOMAINS.unlink(missing_ok=True)

    def hello(self, sni, ip=None, ech=False):
        data = type("Data", (), {})()
        data.client_hello = type("Hello", (), {"sni": sni, "extensions": [(0xFE0D, b"")] if ech else []})()
        data.context = type("Ctx", (), {"server": type("Srv", (), {"address": (ip, 443) if ip else None})()})()
        data.ignore_connection = False
        return data

    def test_defaults_when_file_missing(self):
        d = dlp.DomainList(DOMAINS)
        self.assertEqual(d.current(), dlp.DEFAULT_DOMAINS)

    def test_matching_is_by_name_and_subdomain_only(self):
        DOMAINS.write_text("anthropic.com\nclaude.ai  # web app\n\nopenai.com\n")
        d = dlp.DomainList(DOMAINS)
        for host in ("api.anthropic.com", "ANTHROPIC.COM", "claude.ai.", "api.openai.com"):
            self.assertTrue(d.matches(host), host)
        for host in ("evilanthropic.com", "anthropic.com.evil.net", "claude.aim", "example.com", "", None):
            self.assertFalse(d.matches(host), host)

    def test_invalid_entries_are_ignored(self):
        DOMAINS.write_text("anthropic.com\n*.bad.com\nbad domain.com\nhttp://x.com\n-x.com\n")
        self.assertEqual(dlp.DomainList(DOMAINS).current(), ("anthropic.com",))

    def test_list_reloads_on_change(self):
        DOMAINS.write_text("anthropic.com\n")
        os.utime(DOMAINS, (1_000_000, 1_000_000))
        d = dlp.DomainList(DOMAINS)
        self.assertFalse(d.matches("chatgpt.com"))
        DOMAINS.write_text("anthropic.com\nchatgpt.com\n")
        os.utime(DOMAINS, (2_000_000, 2_000_000))  # distinct times: Windows clocks can tick every ~15 ms
        self.assertTrue(d.matches("chatgpt.com"))

    def test_domains_the_ca_does_not_cover_are_passed_through(self):
        ca = TMP / "ca.pem"
        (TMP / "ca-domains.txt").write_text("anthropic.com\nclaude.ai\n")
        make_ca.ensure_ca(TMP / "ca-domains.txt", TMP / "ca-state-cov", ca)
        DOMAINS.write_text("anthropic.com\nclaude.ai\nchatgpt.com\n")
        d = dlp.DomainList(DOMAINS, ca)
        self.assertEqual(d.current(), ("anthropic.com", "claude.ai"))
        self.assertEqual(d.uncovered, ("chatgpt.com",))
        self.assertFalse(d.matches("chatgpt.com"))
        self.assertTrue(d.matches("api.anthropic.com"))

    def test_clienthello_intercepts_listed_and_passes_everything_else(self):
        DOMAINS.write_text("anthropic.com\nclaude.ai\n")
        addon = dlp.AiDLP()
        for sni, ignored in (("api.anthropic.com", False), ("claude.ai", False),
                             ("www.google.com", True), ("evilanthropic.com", True), (None, True)):
            data = self.hello(sni)
            addon.tls_clienthello(data)
            self.assertEqual(data.ignore_connection, ignored, sni)


class MakeCATests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.state = TMP / "ca-state"
        shutil.rmtree(self.state, ignore_errors=True)
        self.dom = TMP / "ca-list.txt"
        self.out = TMP / "ca-out" / "ca.pem"

    def test_ca_is_limited_to_listed_domains_dns_only(self):
        from cryptography import x509
        self.dom.write_text("anthropic.com\nchatgpt.com  # chat\n# off.com\n")
        domains, created, _ = make_ca.ensure_ca(self.dom, self.state, self.out)
        self.assertTrue(created)
        self.assertEqual(domains, ("anthropic.com", "chatgpt.com"))
        cert = x509.load_pem_x509_certificate(self.out.read_bytes())
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints)
        self.assertTrue(nc.critical)
        self.assertEqual({t.value for t in nc.value.permitted_subtrees}, {"anthropic.com", "chatgpt.com"})
        self.assertTrue(all(isinstance(t, x509.DNSName) for t in nc.value.permitted_subtrees))
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(bc.ca)
        self.assertEqual(bc.path_length, 0)
        key = (self.state / make_ca.KEY_FILE).read_text()
        self.assertIn("PRIVATE KEY", key)
        self.assertIn("BEGIN CERTIFICATE", key)  # mitmproxy wants key + cert in one file
        if os.name == "posix":
            self.assertEqual((self.state / make_ca.KEY_FILE).stat().st_mode & 0o777, 0o600)

    def test_kept_when_unchanged_new_when_list_changes(self):
        self.dom.write_text("anthropic.com\n")
        make_ca.ensure_ca(self.dom, self.state, self.out)
        first = self.out.read_bytes()
        _, created, _ = make_ca.ensure_ca(self.dom, self.state, self.out)
        self.assertFalse(created)
        self.assertEqual(self.out.read_bytes(), first)
        self.dom.write_text("anthropic.com\nopenai.com\n")
        _, created, _ = make_ca.ensure_ca(self.dom, self.state, self.out)
        self.assertTrue(created)
        self.assertNotEqual(self.out.read_bytes(), first)

    def test_old_ca_with_ip_constraint_is_replaced(self):
        import ipaddress
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        self.dom.write_text("anthropic.com\n")
        key = ec.generate_private_key(ec.SECP256R1())
        import datetime as dt
        name = x509_name = make_ca.x509.Name([make_ca.x509.NameAttribute(make_ca.NameOID.COMMON_NAME, "old")])
        now = dt.datetime.now(dt.timezone.utc)
        old = (make_ca.x509.CertificateBuilder().subject_name(name).issuer_name(x509_name)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
               .add_extension(make_ca.x509.NameConstraints(permitted_subtrees=[
                   make_ca.x509.DNSName("anthropic.com"),
                   make_ca.x509.IPAddress(ipaddress.ip_network("160.79.104.0/23"))], excluded_subtrees=None), True)
               .sign(key, hashes.SHA256()))
        self.state.mkdir(parents=True)
        pem = old.public_bytes(serialization.Encoding.PEM)
        (self.state / make_ca.CERT_FILE).write_bytes(pem)
        (self.state / make_ca.KEY_FILE).write_bytes(pem)
        _, created, _ = make_ca.ensure_ca(self.dom, self.state, self.out)
        self.assertTrue(created)

    @unittest.skipUnless(os.name == "posix", "symlinks need privileges on Windows")
    def test_links_planted_in_state_dir_are_never_followed(self):
        self.dom.write_text("anthropic.com\n")
        self.state.mkdir(parents=True)
        victim = TMP / "victim.txt"
        victim.write_text("do not touch")
        for name in (make_ca.KEY_FILE, make_ca.CERT_FILE):
            (self.state / name).symlink_to(victim)
        _, created, cert = make_ca.ensure_ca(self.dom, self.state, None)
        self.assertTrue(created)
        self.assertEqual(victim.read_text(), "do not touch")
        for name in (make_ca.KEY_FILE, make_ca.CERT_FILE):
            self.assertFalse((self.state / name).is_symlink())
        self.assertIn(b"BEGIN CERTIFICATE", cert)

    def test_stdout_mode_prints_status_and_certificate(self):
        import io, contextlib
        self.dom.write_text("anthropic.com\nclaude.ai\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            make_ca.main([str(self.dom), str(self.state), "-"])
        out = buf.getvalue().splitlines()
        self.assertEqual(out[0], "domains: anthropic.com claude.ai")
        self.assertEqual(out[1], "ca: new")
        self.assertEqual(out[2], "-----BEGIN CERTIFICATE-----")
        self.assertFalse((self.state.parent / "-").exists())

    def _ca(self, constraints, critical=True, pathlen=0):
        import datetime as dt
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        X = make_ca.x509
        key = ec.generate_private_key(ec.SECP256R1())
        name = X.Name([X.NameAttribute(make_ca.NameOID.COMMON_NAME, "t")])
        now = dt.datetime.now(dt.timezone.utc)
        b = (X.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
             .serial_number(7).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
             .add_extension(X.BasicConstraints(ca=True, path_length=pathlen), True)
             .add_extension(X.KeyUsage(False, False, False, False, False, True, True, False, False), True))
        if constraints is not None:
            b = b.add_extension(X.NameConstraints(permitted_subtrees=constraints, excluded_subtrees=None), critical)
        return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def test_verify_accepts_only_a_properly_limited_ca(self):
        X, doms = make_ca.x509, ("anthropic.com", "claude.ai")
        dns = [X.DNSName(d) for d in doms]
        self.assertEqual(make_ca.verify_ca_cert(self._ca(dns), doms), [])
        self.assertTrue(make_ca.verify_ca_cert(self._ca(None), doms))                     # unlimited
        self.assertTrue(make_ca.verify_ca_cert(self._ca(dns, critical=False), doms))      # not critical
        self.assertTrue(make_ca.verify_ca_cert(self._ca(dns + [X.DNSName("bank.com")]), doms))
        self.assertTrue(make_ca.verify_ca_cert(self._ca(dns[:1]), doms))
        self.assertTrue(make_ca.verify_ca_cert(self._ca(dns, pathlen=None), doms))
        self.assertTrue(make_ca.verify_ca_cert(self._ca(dns) * 2, doms))                  # two certs
        self.assertTrue(make_ca.verify_ca_cert(b"garbage", doms))

    def test_existing_ca_with_a_foreign_key_is_replaced(self):
        self.dom.write_text("anthropic.com\n")
        make_ca.ensure_ca(self.dom, self.state, None)
        cert = (self.state / make_ca.CERT_FILE).read_bytes()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        (self.state / make_ca.KEY_FILE).write_bytes(other + cert)
        _, created, _ = make_ca.ensure_ca(self.dom, self.state, None)
        self.assertTrue(created)

    def test_shipped_domain_list_is_valid(self):
        text = (ROOT / "domains.txt").read_text()
        domains = dlp.parse_domains(text, warn=lambda e: self.fail(f"invalid entry: {e}"))
        self.assertIn("anthropic.com", domains)
        self.assertIn("chatgpt.com", domains)
        self.assertNotIn("githubcopilot.com", domains)  # coding assistants are off by default


class AddSecretsToolTests(unittest.TestCase):
    def test_merges_values_and_never_follows_a_planted_temp_link(self):
        sys.path.insert(0, str(ROOT))
        import aidlp_tool
        dest = TMP / "list" / "secrets.txt"
        dest.parent.mkdir(exist_ok=True)
        dest.write_text("existingValue1\n")
        env = TMP / "add.env"
        env.write_text("A=newSecretValue2\nB=abc\n")
        if os.name == "posix":
            victim = TMP / "victim2.txt"
            victim.write_text("keep")
            (dest.parent / "secrets.txt.tmp").symlink_to(victim)
        import io, contextlib
        old_stdin = sys.stdin
        sys.stdin = type("TTY", (io.StringIO,), {"isatty": lambda self: True})()
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                aidlp_tool.cmd_add_secrets([str(dest), str(env)])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(dest.read_text().splitlines(), ["existingValue1", "newSecretValue2"])
        if os.name == "posix":
            self.assertEqual(victim.read_text(), "keep")
            self.assertEqual(dest.stat().st_mode & 0o777, 0o600)


def _pdf_with_lines(*lines):
    content = "BT /F1 28 Tf 72 700 Td " + " ".join(f"({l}) Tj 0 -40 Td" for l in lines) + " ET"
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
            f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n".encode()
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode() + b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    return out + f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()


def _png_of(pdf: bytes) -> bytes:
    import shutil, subprocess
    d = Path(tempfile.mkdtemp(dir=TMP))
    (d / "p.pdf").write_bytes(pdf)
    subprocess.run([shutil.which("pdftoppm"), "-r", "200", "-png", "-singlefile", str(d / "p.pdf"), str(d / "p")], check=True)
    return (d / "p.png").read_bytes()


@unittest.skipUnless(all(__import__("shutil").which(t) for t in ("tesseract", "pdftotext", "pdftoppm")),
                     "OCR tools (tesseract, poppler) not installed")
class OCRTests(unittest.TestCase):
    def setUp(self):
        SECRETS.write_text("")
        self.gl, self.ocr = dlp.Gitleaks(), dlp.OCR()

    def block(self, kind, media, raw):
        import base64 as b64
        return json.dumps({"messages": [{"role": "user", "content": [{"type": kind, "source": {
            "type": "base64", "media_type": media, "data": b64.b64encode(raw).decode()}}]}]}).encode()

    def test_secret_in_an_image_is_caught_by_ocr(self):
        png = _png_of(_pdf_with_lines("password=Kangaroo42", "nothing else here"))
        with self.assertRaises(dlp.ScanError) as e:
            run(dlp.redact(self.block("image", "image/png", png), [], self.gl, "application/json", self.ocr))
        self.assertIn("image or PDF", str(e.exception))

    def test_secret_in_a_pdf_text_layer_is_caught(self):
        pdf = _pdf_with_lines("config", "password=Kangaroo42")
        with self.assertRaises(dlp.ScanError):
            run(dlp.redact(self.block("document", "application/pdf", pdf), [], self.gl, "application/json", self.ocr))

    def test_listed_secret_in_an_image_is_caught(self):
        png = _png_of(_pdf_with_lines("my pin is Zebra7731"))
        with self.assertRaises(dlp.ScanError):
            run(dlp.redact(self.block("image", "image/png", png), ["Zebra7731"], self.gl, "application/json", self.ocr))

    def test_screenshot_inside_a_text_pdf_is_ocrd(self):
        listing = ("page   num  type   width height color comp bpc  enc interp  object ID x-ppi y-ppi size ratio\n"
                   "--------------------------------------------------------------------------------------------\n"
                   "   2     0 image     800   600  rgb     3   8  image  no         9  0   144   144 30.1K 2.1%\n"
                   "   5     1 image     400   300  rgb     3   8  jpeg   no        12  0    96    96 12.0K 3.4%\n")
        self.assertEqual(dlp.pages_with_images(listing), {2, 5})
        self.assertEqual(dlp.pages_with_images(listing.splitlines()[0] + "\n---\n"), set())

    def test_oversized_image_is_refused_before_ocr(self):
        huge_png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + (50000).to_bytes(4, "big") + \
            (50000).to_bytes(4, "big") + b"\x08\x02\x00\x00\x00" + os.urandom(64)
        self.assertEqual(dlp.image_size(huge_png), (50000, 50000))
        with self.assertRaises(dlp.ScanError) as e:
            run(self.ocr._image(huge_png))
        self.assertIn("too large", str(e.exception))

    def test_image_sizes_are_read_from_headers(self):
        png = _png_of(_pdf_with_lines("x"))
        w, h = dlp.image_size(png)
        self.assertGreater(w, 100)
        self.assertGreater(h, 100)
        self.assertEqual(dlp.image_size(b"GIF89a" + (320).to_bytes(2, "little") + (200).to_bytes(2, "little")), (320, 200))

    def test_too_many_new_images_in_one_request_is_blocked(self):
        import base64 as b64
        blocks = [{"type": "image", "source": {"type": "base64", "media_type": "image/png",
                   "data": b64.b64encode(b"\x89PNG\r\n\x1a\n" + os.urandom(40)).decode()}} for _ in range(dlp.OCR_MAX_ITEMS + 1)]
        body = json.dumps({"messages": [{"role": "user", "content": blocks}]}).encode()
        with self.assertRaises(dlp.ScanError) as e:
            run(dlp.redact(body, [], self.gl, "application/json", self.ocr))
        self.assertIn("at most", str(e.exception))

    def test_page_sizes_use_the_larger_box_and_rotation(self):
        out = ("Pages: 2\n"
               "Page    1 size:  612 x 792 pts (letter)\nPage    1 rot:   0\n"
               "Page    1 MediaBox:      0.00     0.00   612.00   792.00\n"
               "Page    1 CropBox:       0.00     0.00   300.00   400.00\n"
               "Page    2 rot:   90\n"
               "Page    2 MediaBox:      0.00     0.00   200.00   100.00\n"
               "Page    2 CropBox:       0.00     0.00  9000.00    50.00\n")
        self.assertEqual(dlp.page_sizes(out), {1: (612.0, 792.0), 2: (100.0, 9000.0)})

    def test_too_many_or_too_large_embedded_images_are_refused_before_extraction(self):
        rows = "".join(f"   1  {i:4d} image   800   600  rgb  3  8  image  no  {9+i}  0  72  72  1K  1%\n" for i in range(3))
        head = "page num type width height color comp bpc enc interp object ID x-ppi y-ppi size ratio\n----\n"
        self.assertEqual(dlp.image_listing(head + rows), [(1, 800, 600)] * 3)
        big = head + "   3     0 image  20000 20000  rgb  3  8  image  no  9  0  72  72  1K  1%\n"
        self.assertEqual(dlp.image_listing(big), [(3, 20000, 20000)])

    def test_giant_page_is_refused_not_shrunk(self):
        pdf = _pdf_with_lines("password=Kangaroo42").replace(b"/MediaBox [0 0 612 792]", b"/MediaBox [0 0 9000 9000]")
        with self.assertRaises(dlp.ScanError) as e:  # its text layer already catches it; force the OCR path:
            run(self.ocr._pdf(pdf.replace(b"(password=Kangaroo42) Tj", b"")))
        self.assertIn("too large", str(e.exception))

    def test_clean_image_passes_and_is_ocrd_once(self):
        png = _png_of(_pdf_with_lines("quarterly report", "nothing secret here"))
        body = self.block("image", "image/png", png)
        out, counts = run(dlp.redact(body, [], self.gl, "application/json", self.ocr))
        self.assertEqual(out, body)
        calls = []
        original = self.ocr._image

        async def counting(raw):
            calls.append(1)
            return await original(raw)
        self.ocr._image = counting
        run(dlp.redact(body, [], self.gl, "application/json", self.ocr))
        self.assertEqual(calls, [])  # second time served from the OCR cache


class HiddenNameTests(unittest.TestCase):
    def setUp(self):
        DOMAINS.write_text("anthropic.com\n")
        EVENTS.unlink(missing_ok=True)
        self.addon = dlp.AiDLP()
        self.t = DomainTests()

    def decide(self, sni, ip, ech=False):
        data = self.t.hello(sni, ip, ech)
        self.addon.tls_clienthello(data)
        return "passthrough" if data.ignore_connection else "intercept"

    def test_addresses_are_learned_from_listed_connections(self):
        self.assertEqual(self.decide("api.anthropic.com", "160.79.104.10"), "intercept")
        self.assertIn("160.79.104.10", self.addon.ai_addresses)

    def test_nameless_or_ech_connections_to_ai_addresses_are_forced_through_inspection(self):
        self.addon.ai_addresses.add("160.79.104.10")
        self.assertEqual(self.decide(None, "160.79.104.10"), "intercept")
        self.assertEqual(self.decide("public.ech-frontend.example", "160.79.104.10", ech=True), "intercept")
        self.assertIn("forced through inspection", EVENTS.read_text())

    def test_other_connections_still_pass_through(self):
        self.addon.ai_addresses.add("160.79.104.10")
        self.assertEqual(self.decide(None, "93.184.216.34"), "passthrough")            # nameless, other host
        self.assertEqual(self.decide("www.example.com", "93.184.216.34", ech=True), "passthrough")
        self.assertEqual(self.decide("www.example.com", "160.79.104.10"), "passthrough")  # named, not ECH

    def test_nameless_flow_to_ai_address_is_scanned(self):
        self.addon.ai_addresses.add("160.79.104.10")
        flow = type("F", (), {})()
        flow.client_conn = type("C", (), {"sni": None})()
        flow.server_conn = type("S", (), {"address": ("160.79.104.10", 443)})()
        flow.request = type("R", (), {"pretty_host": "160.79.104.10"})()
        self.assertTrue(self.addon._inspected(flow))


class RequestStoreTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.dir = TMP / "requests"
        shutil.rmtree(self.dir, ignore_errors=True)
        self.saved = (dlp.REQUESTS_DIR, dlp.KEEP_REQUESTS, dlp.REQUESTS_UID, dlp.client_uid)
        dlp.REQUESTS_DIR, dlp.KEEP_REQUESTS, dlp.REQUESTS_UID = self.dir, 3, 1000
        dlp.client_uid = lambda flow: 1000  # the request comes from the allowed account
        SECRETS.write_text("")
        EVENTS.unlink(missing_ok=True)

    def tearDown(self):
        dlp.REQUESTS_DIR, dlp.KEEP_REQUESTS, dlp.REQUESTS_UID, dlp.client_uid = self.saved

    def test_login_headers_are_hidden_and_listed_secrets_redacted(self):
        fields = [(b"Host", b"api.anthropic.com"), (b"x-api-key", b"sk-real"), (b"Authorization", b"Bearer abc"),
                  (b"Cookie", b"sessionKey=xyz"), (b"anthropic-version", b"2023-06-01"),
                  (b"x-innocent-name", b"actually a secret"), (b"User-Agent", b"tool Zebra7731")]
        out = dict(dlp.safe_headers(fields, ["Zebra7731"]))
        self.assertEqual(out["x-api-key"], "[hidden]")
        self.assertEqual(out["Authorization"], "[hidden]")
        self.assertEqual(out["Cookie"], "[hidden]")
        self.assertEqual(out["x-innocent-name"], "[hidden]")  # not on the allowlist
        self.assertEqual(out["anthropic-version"], "2023-06-01")
        self.assertEqual(out["User-Agent"], "tool [REDACTED:known-secret]")

    def test_body_is_pretty_printed_with_images_summarised(self):
        import base64 as b64
        img = b64.b64encode(os.urandom(3000)).decode()
        text, truncated = dlp.displayable_body(json.dumps({"a": "hi", "img": img}).encode())
        self.assertFalse(truncated)
        self.assertIn('"a": "hi"', text)
        self.assertIn("[base64 data, 2 KB]", text)
        self.assertNotIn(img, text)
        self.assertTrue(dlp.displayable_body(b"\x00\xff\xfe" + os.urandom(10), "audio/webm")[0].startswith("[binary body"))

    def test_only_the_newest_requests_are_kept(self):
        ids = [dlp.store_request("POST", "api.anthropic.com", f"/v1/m?key=SECRETQUERY{i}", [], "{}") for i in range(5)]
        kept = sorted(f.stem for f in self.dir.glob("*.json"))
        self.assertEqual(kept, sorted(ids[-3:]))
        rec = json.loads((self.dir / f"{ids[-1]}.json").read_text())
        self.assertEqual(rec["path"], "/v1/m")  # query (which can carry API keys) is dropped
        if os.name == "posix":
            self.assertEqual((self.dir / f"{ids[-1]}.json").stat().st_mode & 0o777, 0o640)

    def test_flow_stores_the_redacted_body_and_links_the_event(self):
        addon = dlp.AiDLP()
        addon.ocr.tesseract = None
        dlp.http = type("http", (), {"Response": AddonHookTests.FakeResponse})
        aws = "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")
        req = AddonHookTests.Req("api.anthropic.com", body_of(f"key {aws}"), {"x-api-key": "sk-ant-real"})
        req.headers.fields = [(b"x-api-key", b"sk-ant-real"), (b"content-type", b"application/json")]
        run(addon.request(AddonHookTests.Flow(req)))
        ev = json.loads(EVENTS.read_text().splitlines()[-1])
        rec = json.loads((self.dir / f"{ev['id']}.json").read_text())
        self.assertNotIn(aws, rec["body"])
        self.assertIn("[REDACTED:aws-access-token]", rec["body"])
        self.assertEqual(dict(rec["headers"])["x-api-key"], "[hidden]")

    def test_blocked_request_is_stored_without_its_body(self):
        addon = dlp.AiDLP()
        dlp.http = type("http", (), {"Response": AddonHookTests.FakeResponse})
        req = AddonHookTests.Req("api.anthropic.com", body_of("FORCE_GITLEAKS_ERROR secret stuff"))
        req.headers.fields = [(b"content-type", b"application/json")]
        run(addon.request(AddonHookTests.Flow(req)))
        ev = json.loads(EVENTS.read_text().splitlines()[-1])
        self.assertEqual(ev["action"], "blocked")
        rec = json.loads((self.dir / f"{ev['id']}.json").read_text())
        self.assertIsNone(rec["body"])

    def test_other_users_requests_are_not_stored(self):
        dlp.client_uid = lambda flow: 1001
        addon = dlp.AiDLP()
        addon.ocr.tesseract = None
        dlp.http = type("http", (), {"Response": AddonHookTests.FakeResponse})
        req = AddonHookTests.Req("api.anthropic.com", body_of("hello there"))
        req.headers.fields = [(b"content-type", b"application/json")]
        run(addon.request(AddonHookTests.Flow(req)))
        ev = json.loads(EVENTS.read_text().splitlines()[-1])
        self.assertNotIn("id", ev)
        self.assertFalse(self.dir.exists() and any(self.dir.iterdir()))

    def test_socket_owner_is_read_from_proc(self):
        head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        row = "   {n}: {l} {r} {st} 00000000:00000000 00:00000000 00000000  {uid}        0 {n}\n"
        mine = row.format(n=1, l="8920A8C0:D431", r="0A684FA0:01BB", st="01", uid=1000)  # 192.168.32.137:54321 -> 160.79.104.10:443
        listening = row.format(n=0, l="0100007F:4762", r="00000000:0000", st="0A", uid=977)
        table = head + listening + mine
        self.assertEqual(dlp.uid_from_proc(table, "192.168.32.137", 0xD431, "160.79.104.10", 443), 1000)
        self.assertIsNone(dlp.uid_from_proc(table, "192.168.32.137", 0xD431, "1.2.3.4", 443))   # other destination
        self.assertIsNone(dlp.uid_from_proc(table, "127.0.0.1", 0x4762, "0.0.0.0", 0))         # listening socket
        same_local_other_dest = row.format(n=2, l="8920A8C0:D431", r="04030201:01BB", st="01", uid=1001)
        self.assertEqual(dlp.uid_from_proc(table + same_local_other_dest, "192.168.32.137", 0xD431, "160.79.104.10", 443), 1000)
        clash = row.format(n=3, l="8920A8C0:D431", r="0A684FA0:01BB", st="01", uid=1001)
        self.assertIsNone(dlp.uid_from_proc(table + clash, "192.168.32.137", 0xD431, "160.79.104.10", 443))  # ambiguous

    def test_nothing_is_stored_when_capture_is_off(self):
        dlp.KEEP_REQUESTS = 0
        self.assertIsNone(dlp.store_request("POST", "h", "/", [], "{}"))
        self.assertFalse(self.dir.exists())


class SecretsCliTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_loader("cli", loader=None)
        self.cli = importlib.util.module_from_spec(spec)
        exec((LINUX / "ai-dlp-secrets").read_text(), self.cli.__dict__)

    def test_env_file_parsing(self):
        f = TMP / "x.env"
        f.write_text('# c\nexport A="quoted value 1"\nB=\'single\'\nC=plain=with=equals\n\nnoequals\n')
        self.assertEqual(list(self.cli.env_values(f)), ["quoted value 1", "single", "plain=with=equals"])

    def test_pgpass_parsing(self):
        f = TMP / "pgpass"
        f.write_text("db:5432:app:user:pa\\:ss:word\n#comment\nh:*:*:u:simplepass\n")
        self.assertEqual(list(self.cli.pgpass_values(f)), ["pa:ss:word", "simplepass"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
