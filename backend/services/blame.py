"""Owner attribution via ``git blame``.

For each finding ``(file, line)``, ask git who last changed that line.
We store ``owner_email``, ``owner_name``, and ``last_modified`` on the
finding so the UI can group by owner and show MTTR per person.

This intentionally uses the email as the identity key — no Auth/SSO/Slack
mapping required.
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# `git blame --porcelain` emits header lines we care about.
_AUTHOR_RE = re.compile(r"^author (?P<name>.+)$", re.MULTILINE)
_EMAIL_RE = re.compile(r"^author-mail <(?P<email>[^>]+)>$", re.MULTILINE)
_TIME_RE = re.compile(r"^author-time (?P<ts>\d+)$", re.MULTILINE)


def attribute(repo_path: str, file_path: str, line: int) -> dict | None:
    """Return ``{owner_name, owner_email, last_modified_unix}`` or None."""
    if not (repo_path and file_path and line):
        return None
    full = Path(repo_path) / file_path.lstrip("/")
    if not full.is_file():
        return None
    try:
        out = subprocess.check_output(
            [
                "git", "-C", repo_path, "blame",
                "--porcelain", "-L", f"{line},{line}", "--", file_path.lstrip("/"),
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None

    name = (_AUTHOR_RE.search(out) or _no_match()).groupdict().get("name")
    email = (_EMAIL_RE.search(out) or _no_match()).groupdict().get("email")
    ts = (_TIME_RE.search(out) or _no_match()).groupdict().get("ts")
    if not (name or email):
        return None
    return {
        "owner_name": name or "",
        "owner_email": email or "",
        "last_modified_unix": int(ts) if ts else None,
    }


def attribute_findings(findings: list[dict], repo_path: str) -> list[dict]:
    """Attach owner info to each finding in place. Returns the list."""
    for f in findings:
        info = attribute(
            repo_path,
            f.get("file_path") or "",
            int(f.get("line_start") or f.get("line") or 0),
        )
        if info:
            f["owner_name"] = info["owner_name"]
            f["owner_email"] = info["owner_email"]
            f["last_modified_unix"] = info["last_modified_unix"]
    return findings


class _NullMatch:
    def groupdict(self):
        return {}


def _no_match():
    return _NullMatch()
