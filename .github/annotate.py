"""Turn the useful end of a log into a GitHub error annotation.

usage: python .github/annotate.py TITLE LOGFILE [LINES]

Annotations are visible to everyone through the checks API, unlike job logs
(which need a signed-in user), so a failure's cause can be read without access
to the run. For unittest output, the failure details are used; otherwise the
last LINES lines. The message is kept under GitHub's annotation size limit.
"""
import sys
from pathlib import Path

LIMIT = 3800  # characters, safely under the annotation message limit

title, path = sys.argv[1], Path(sys.argv[2])
lines = int(sys.argv[3]) if len(sys.argv) > 3 else 60
text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else "(no log written)"
marker = text.find("\n======")
if marker != -1:  # unittest: from the first failure section to the end
    text = text[marker + 1:]
else:
    text = "\n".join(text.splitlines()[-lines:])
if len(text) > LIMIT:
    text = "...\n" + text[-LIMIT:]
esc = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
print(f"::error title={title}::{esc}")
