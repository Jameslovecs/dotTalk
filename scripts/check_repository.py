"""Reject obvious credentials, personal email addresses, and runtime files in Git's index."""

import re
import subprocess
import sys
from pathlib import PurePosixPath

FORBIDDEN_PARTS = {".state", ".venv", "local", "__pycache__"}
FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".pem", ".key", ".log"}
TOKEN = re.compile(
    rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{32,})"
)
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def main():
    names = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
    violations = []
    for name in filter(None, names):
        path = PurePosixPath(name)
        if (
            FORBIDDEN_PARTS.intersection(path.parts)
            or path.suffix in FORBIDDEN_SUFFIXES
            or path.name.startswith((".env", "credentials"))
        ):
            violations.append(f"{name}: runtime/sensitive path")
        # Read the index, not the working tree: this is what the next commit publishes.
        content = subprocess.check_output(["git", "show", f":{name}"])
        if TOKEN.search(content) or PRIVATE_KEY.search(content):
            violations.append(f"{name}: credential pattern")
        for match in EMAIL.finditer(content):
            if match.group(1).lower() not in {b"example.invalid", b"example.com", b"example.test"}:
                violations.append(f"{name}: non-synthetic email address")
    if violations:
        print("Repository guard failed (values redacted):\n" + "\n".join(violations))
        return 1
    print("Repository guard passed: no prohibited tracked paths or obvious secret/PII patterns.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
