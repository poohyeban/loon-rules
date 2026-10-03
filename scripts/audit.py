"""Check policy-free rules, provenance and public files without printing secrets."""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
from pathlib import Path

from scripts.rules import parse_rule

ROOT = Path(__file__).resolve().parents[1]
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
EMAIL = re.compile(rb"[A-Za-z0-9_.+\[\]-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CHECKS = {
    "home-directory": rb"/(?:Users|home)/[A-Za-z0-9_.-]+/|[A-Z]:\\Users\\",
    "private-key": rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----",
    "github-token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
    "api-secret": rb"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}",
    "subscription-secret": rb"[?&](?:token|access_token|api_key|password)=[A-Za-z0-9_%+-]{8,}",
}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def private_markers():
    markers = {Path.home().name, socket.gethostname()}
    for key in ("user.name", "user.email"):
        result = subprocess.run(["git", "config", "--global", "--get", key], capture_output=True, text=True)
        if result.returncode == 0:
            markers.add(result.stdout.strip())
    return {s.encode().lower() for s in markers if len(s) >= 5 and s not in
            {"runner", "poohyeban", BOT_NAME, BOT_EMAIL}}


def scan(data: bytes, label: str, markers=()) -> list[str]:
    # Report only the category and public relative filename, never the value.
    errors = [f"{label}: {name}" for name, pattern in CHECKS.items() if re.search(pattern, data)]
    for value in EMAIL.findall(data):
        if value.decode() != BOT_EMAIL:
            errors.append(f"{label}: non-bot-email")
            break
    if any(marker in data.lower() for marker in markers):
        errors.append(f"{label}: local-identity")
    return errors


def audit():
    markers, errors = private_markers(), []
    paths = sorted(set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""})
    for raw in paths:
        relative = raw.decode()
        path = ROOT / relative
        if path.is_symlink():
            errors.append(f"{relative}: symlink")
            continue
        if not path.is_file():
            errors.append(f"{relative}: missing tracked file")
            continue
        if path.suffix in {".p12", ".key", ".pem", ".env", ".conf", ".lcf"}:
            errors.append(f"{relative}: unexpected configuration or credential file")
        data = path.read_bytes()
        errors.extend(scan(data, relative, markers))
        if relative.startswith("rules/"):
            for n, line in enumerate(data.decode("utf-8").splitlines(), 1):
                try:
                    parse_rule(line)
                except ValueError:
                    errors.append(f"{relative}:{n}: invalid, logical or policy-bearing rule")
                    break
    has_head = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, capture_output=True).returncode == 0
    if has_head:
        log = git("log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B%x00")
        errors.extend(scan(log, "commit-metadata", markers))
        identities = git("log", "--all", "--format=%an|%ae|%cn|%ce").decode().splitlines()
        expected = "|".join((BOT_NAME, BOT_EMAIL, BOT_NAME, BOT_EMAIL))
        if any(line != expected for line in identities):
            errors.append("commit-metadata: unexpected author or committer")
        # Scan every unique historical blob as well as the current working tree.
        for line in git("rev-list", "--objects", "--all").splitlines():
            oid = line.split(b" ", 1)[0].decode()
            if git("cat-file", "-t", oid).strip() == b"blob":
                errors.extend(scan(git("cat-file", "blob", oid), "history-blob", markers))
    manifest_path = ROOT / "reports/manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        actual = {str(p.relative_to(ROOT / "rules")) for p in (ROOT / "rules").rglob("*.list")}
        if actual != set(manifest["outputs"]):
            errors.append("manifest: output inventory mismatch")
        for name, info in manifest["outputs"].items():
            path = ROOT / "rules" / name
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != info["sha256"]:
                errors.append("manifest: output digest mismatch")
    if errors:
        for error in sorted(set(errors)):
            print(error)
        raise SystemExit("Audit failed; keep repository private.")
    print(f"Audit passed: {len(paths)} public files; rules, identities, history and provenance checked.")


if __name__ == "__main__":
    audit()
