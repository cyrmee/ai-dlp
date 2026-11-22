"""Turn the end of a log into a GitHub error annotation.

usage: python .github/annotate.py TITLE LOGFILE [LINES]

Annotations are visible to everyone through the checks API, unlike job logs
(which need a signed-in user), so a failure's cause can be read without access
to the run.
"""
import sys
from pathlib import Path

title, path = sys.argv[1], Path(sys.argv[2])
lines = int(sys.argv[3]) if len(sys.argv) > 3 else 60
text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else "(no log written)"
tail = "\n".join(text.splitlines()[-lines:])
esc = tail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
print(f"::error title={title}::{esc}")
