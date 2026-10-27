"""Text hygiene shared by the CLI, provider bridge and workflow.

Local models occasionally emit NUL or other control characters.  Those bytes
are valid in JSON strings but cannot be passed through ``argv`` to a Go engine
(``embedded null byte``) and can corrupt terminal output and reports.  Every
boundary that accepts or returns model text runs through these helpers.
"""

from __future__ import annotations

import re
from typing import Any

# Keep tab (0x09), newline (0x0a) and carriage return (0x0d); drop the rest of
# the C0/C1 control ranges, including NUL (0x00).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def strip_control(value: Any) -> str:
    """Return *value* as text with unsafe control characters removed."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return _CONTROL_RE.sub("", value)


def clean_model_text(value: Any) -> str:
    """Normalise line endings, strip controls and trim model output."""
    text = strip_control(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()
