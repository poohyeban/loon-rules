"""Validate published Loon datasets independently of machine/privacy checks."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from scripts.rules import compact, parse_rule
from scripts.social import SERVICES

AGGREGATES = {
    "China/China.list": ("China/Sources/China-v2fly-Domain.list", "China/Sources/China-GeoIP.list"),
    "OpenAI/OpenAI.list": ("OpenAI/Sources/OpenAI-v2fly.list", "OpenAI/Sources/OpenAI-Official-Domain.list",
                           "OpenAI/Sources/OpenAI-ASN-IP.list", "OpenAI/Sources/OpenAI-Voice-IP.list"),
    "Claude/Claude.list": ("Claude/Sources/Claude-v2fly.list", "Claude/Sources/Claude-ASN-IP.list"),
    **{f"{s}/{s}.list": (f"{s}/Sources/{s}-v2fly.list",) for s in SERVICES},
}
REVIEWED = {"data/OpenAI/official-domains.txt", "data/OpenAI/official-domains-excluded.txt",
            "data/Meta/sukka-review.json"}


def no_resolve_path(path: str) -> str:
    return path.removesuffix(".list") + "-NoResolve.list"


def audit_publication(root: Path, reviewed_root: Path | None = None) -> dict:
    from scripts.build import SOURCES

    reviewed_root = reviewed_root or root
    manifest = json.loads((root / "reports/manifest.json").read_text(encoding="utf-8"))
    if set(manifest) != {"upstreams", "reviewed_files", "outputs"}:
        raise ValueError("manifest schema mismatch")
    upstreams = manifest["upstreams"]
    if set(upstreams) != set(SOURCES):
        raise ValueError("manifest source inventory mismatch")
    revisions = {}
    for name, url in SOURCES.items():
        info = upstreams[name]
        if info.get("url") != url or not re.fullmatch(r"[0-9a-f]{64}", info.get("sha256", "")):
            raise ValueError(f"manifest source URL or digest mismatch: {name}")
        if type(info.get("bytes")) is not int or info["bytes"] <= 0:
            raise ValueError(f"manifest source byte count mismatch: {name}")
        pinned = re.fullmatch(r"https://raw\.githubusercontent\.com/(v2fly/domain-list-community|SukkaW/Surge)/(master|release)/(.+)", url)
        if pinned:
            repo, branch, path = pinned.groups()
            commit = info.get("commit", "")
            if not re.fullmatch(r"[0-9a-f]{40}", commit) or info.get("resolved_url") != (
                    f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"):
                raise ValueError(f"manifest pinned revision mismatch: {name}")
            key = (repo, branch)
            if key in revisions and revisions[key] != commit:
                raise ValueError("manifest mixes revisions of one upstream branch")
            revisions[key] = commit
    for name, expected in (("ASN.mmdb", "GeoLite2-ASN"), ("Country.mmdb", "GeoLite2-Country")):
        metadata = upstreams[name].get("database", {})
        if (metadata.get("type") != expected or metadata.get("ip_version") != 6 or
                type(metadata.get("build_epoch")) is not int or metadata["build_epoch"] <= 0):
            raise ValueError(f"manifest database metadata mismatch: {name}")
    if set(manifest["reviewed_files"]) != REVIEWED:
        raise ValueError("manifest reviewed inventory mismatch")
    for name, expected in manifest["reviewed_files"].items():
        if hashlib.sha256((reviewed_root / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"manifest reviewed digest mismatch: {name}")

    required = {"AdGuard/Ad-Domain.list"} | set(AGGREGATES)
    required.update(p for sources in AGGREGATES.values() for p in sources)
    for path in list(required):
        if path.endswith(("-GeoIP.list", "-ASN-IP.list", "-Voice-IP.list")) or path in {
                "China/China.list", "OpenAI/OpenAI.list", "Claude/Claude.list"}:
            required.add(no_resolve_path(path))
    optional = {f"{s}/Sources/{s}-Sukka.list" for s in SERVICES}
    actual = {str(p.relative_to(root / "rules")) for p in (root / "rules").rglob("*") if p.is_file()}
    if not required <= actual or not actual <= required | optional or actual != set(manifest["outputs"]):
        raise ValueError("manifest output inventory mismatch")
    parsed = {}
    for path in sorted(actual):
        data = (root / "rules" / path).read_bytes()
        if not data or not data.endswith(b"\n") or b"\r" in data or data.startswith(b"\xef\xbb\xbf"):
            raise ValueError(f"non-canonical ruleset encoding: {path}")
        lines = data.decode("utf-8").splitlines()
        if lines != sorted(set(lines)) or any(not line for line in lines):
            raise ValueError(f"empty, duplicate or unordered rule: {path}")
        parsed[path] = {parse_rule(line) for line in lines}
        info = manifest["outputs"][path]
        if info.get("sha256") != hashlib.sha256(data).hexdigest() or info.get("rules") != len(lines):
            raise ValueError(f"manifest output digest or count mismatch: {path}")
    pairs = 0
    for path, rules in parsed.items():
        nr = path.endswith("-NoResolve.list")
        if any(rule.no_resolve != nr for rule in rules if rule.kind.startswith("IP-")):
            raise ValueError(f"incorrect no-resolve modifier: {path}")
        if nr:
            base = path.replace("-NoResolve.list", ".list")
            if base not in parsed or {(r.kind, r.value) for r in rules} != {
                    (r.kind, r.value) for r in parsed[base]}:
                raise ValueError(f"regular and NoResolve sets differ: {path}")
            pairs += 1
    for path, sources in AGGREGATES.items():
        inputs = set().union(*(parsed[p] for p in sources))
        service = path.split("/", 1)[0]
        supplement = f"{service}/Sources/{service}-Sukka.list"
        if supplement in parsed:
            inputs |= parsed[supplement]
        if parsed[path] != compact(inputs):
            raise ValueError(f"aggregate does not match its sources: {path}")
    if parsed["AdGuard/Ad-Domain.list"] != compact(parsed["AdGuard/Ad-Domain.list"]):
        raise ValueError("AdGuard output is not compacted")
    return {"files": len(actual), "pairs": pairs, "aggregates": len(AGGREGATES),
            "rules": sum(map(len, parsed.values())), "sources": len(upstreams)}
