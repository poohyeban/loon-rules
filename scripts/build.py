"""Download original upstreams, build in staging, validate, then publish locally."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from scripts.rules import Rule, adguard, compact, parse_rule, reviewed_domains, v2fly
from scripts.social import SERVICES, aggregate, sukka_supplement

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "cn.txt": "https://raw.githubusercontent.com/v2fly/domain-list-community/release/cn.txt",
    "openai.txt": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai",
    "Country.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "ASN.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
    "voice.json": "https://openai.com/chatgpt-voice.json",
    "adguard.txt": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    **{f"{service.lower()}.txt": f"https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/{service.lower()}"
       for service in SERVICES},
    "sukka-global.txt": "https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/global.conf",
}
PINNED_REPOS = {"v2fly/domain-list-community", "SukkaW/Surge"}
TARGET_ASNS = {401518, 401864}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(inputs: Path) -> dict:
    manifest = {}
    commits = {}
    for repo in sorted(PINNED_REPOS):
        response = subprocess.check_output(
            ["git", "ls-remote", "https://github.com/" + repo + ".git", "refs/heads/master"],
            text=True, timeout=60).split()
        if len(response) != 2 or not re.fullmatch(r"[0-9a-f]{40}", response[0]):
            raise ValueError("cannot resolve upstream revision: " + repo)
        commits[repo] = response[0]
    for name, url in SOURCES.items():
        resolved_url, revision = url, {}
        for repo, commit in commits.items():
            prefix = f"https://raw.githubusercontent.com/{repo}/master/"
            if url.startswith(prefix):
                resolved_url = url.replace(prefix, f"https://raw.githubusercontent.com/{repo}/{commit}/", 1)
                revision = {"commit": commit, "resolved_url": resolved_url}
        target = inputs / name
        temp = inputs / (name + ".part")
        subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
                        "--retry", "3", "--retry-delay", "3", "--connect-timeout", "20",
                        "--max-time", "180", "--output", str(temp), resolved_url], check=True)
        if not temp.stat().st_size:
            raise ValueError(f"empty upstream: {name}")
        temp.replace(target)
        manifest[name] = {"url": url, "sha256": digest(target), "bytes": target.stat().st_size, **revision}
        print(f"Downloaded {name}: {target.stat().st_size} bytes")
    return manifest


def networks_rules(networks, no_resolve=False) -> set[Rule]:
    return {Rule("IP-CIDR" if n.version == 4 else "IP-CIDR6", str(n), no_resolve=no_resolve) for n in networks}


def country_networks(path: Path):
    import maxminddb
    groups = {4: [], 6: []}
    with maxminddb.open_database(path) as database:
        for network, record in database:
            if record and (record.get("country") or {}).get("iso_code") == "CN":
                groups[network.version].append(network)
    if not all(groups.values()):
        raise ValueError("Country database lacks CN IPv4 or IPv6 records")
    return [n for version in (4, 6) for n in ipaddress.collapse_addresses(groups[version])]


def asn_networks(path: Path):
    import maxminddb
    groups = {asn: set() for asn in TARGET_ASNS}
    with maxminddb.open_database(path) as database:
        for network, record in database:
            if record and type(record.get("autonomous_system_number")) is int:
                asn = record["autonomous_system_number"]
                if asn in groups:
                    groups[asn].add(network)
    networks = set().union(*groups.values())
    if not networks:
        raise ValueError("ASN database lacks all explicitly tracked ASNs")
    coverage = {"networks_by_asn": {str(asn): len(groups[asn]) for asn in sorted(groups)},
                "missing_asns": sorted(asn for asn, nets in groups.items() if not nets)}
    return networks, coverage


def voice_networks(payload):
    if not isinstance(payload, dict):
        raise ValueError("Voice JSON must be an object")
    stamp = payload.get("creationTime")
    if not isinstance(stamp, str) or datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("invalid Voice timestamp")
    prefixes = payload.get("prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        raise ValueError("missing Voice prefixes")
    output = set()
    for item in prefixes:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError("invalid Voice prefix record")
        key, value = next(iter(item.items()))
        if key not in {"ipv4Prefix", "ipv6Prefix"} or not isinstance(value, str) or "/" not in value:
            raise ValueError("unknown Voice prefix schema")
        network = ipaddress.ip_network(value, strict=True)
        if network.version != (4 if key == "ipv4Prefix" else 6):
            raise ValueError("mismatched Voice prefix version")
        output.add(network)
    return output


def write_list(root: Path, relative: str, rules: set[Rule]) -> None:
    if not rules:
        raise ValueError(f"refusing empty ruleset: {relative}")
    lines = sorted(r.render() for r in rules)
    for line in lines:
        parse_rule(line)
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def json_write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def validate_pair(regular: set[Rule], no_resolve: set[Rule]):
    def partition(rules, expected):
        domains, ips = set(), set()
        for rule in rules:
            if rule.kind in {"IP-CIDR", "IP-CIDR6"}:
                if rule.no_resolve != expected:
                    raise ValueError("incorrect no-resolve modifier")
                ips.add((rule.kind, rule.value))
            else:
                domains.add(rule)
        return domains, ips
    if partition(regular, False) != partition(no_resolve, True):
        raise ValueError("regular and NoResolve sets differ")


def build(root: Path = ROOT, offline: bool = False):
    workspace = root / "build"
    inputs = workspace / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    if offline:
        manifest = json.loads((inputs / "manifest.json").read_text())
        if set(manifest) != set(SOURCES):
            raise ValueError("offline source inventory mismatch")
        for name, data in manifest.items():
            if data["url"] != SOURCES[name] or digest(inputs / name) != data["sha256"]:
                raise ValueError(f"offline source hash or URL mismatch: {name}")
    else:
        manifest = download(inputs)
        json_write(inputs / "manifest.json", manifest)

    stage = workspace / "staging"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    output = stage / "rules"
    reports = {}
    cn, report = v2fly((inputs / "cn.txt").read_text(encoding="utf-8-sig"))
    reports["China-v2fly"] = report.json()
    ai, report = v2fly((inputs / "openai.txt").read_text(encoding="utf-8-sig"))
    reports["OpenAI-v2fly"] = report.json()
    official_path = root / "data/OpenAI/official-domains.txt"
    excluded_path = root / "data/OpenAI/official-domains-excluded.txt"
    official, report = reviewed_domains(official_path.read_text(), excluded_path.read_text())
    reports["OpenAI-reviewed"] = report.json()
    ads, report = adguard((inputs / "adguard.txt").read_text(encoding="utf-8-sig"))
    reports["AdGuard"] = report.json()
    china_nets = country_networks(inputs / "Country.mmdb")
    asn_nets, reports["OpenAI-ASN"] = asn_networks(inputs / "ASN.mmdb")
    voice_nets = voice_networks(json.loads((inputs / "voice.json").read_text()))

    social = {}
    for service in SERVICES:
        social[service], report = v2fly((inputs / f"{service.lower()}.txt").read_text(encoding="utf-8-sig"))
        reports[service + "-v2fly"] = report.json()
    social_review_path = root / "data/Meta/sukka-review.json"
    supplements, report = sukka_supplement(
        (inputs / "sukka-global.txt").read_text(encoding="utf-8-sig"), social,
        json.loads(social_review_path.read_text()))
    reports["Meta-Sukka-selection"] = report.json()
    for service in SERVICES:
        combined, reports[service + "-aggregate"] = aggregate(social[service], supplements[service])
        write_list(output, f"{service}/Sources/{service}-v2fly.list", social[service])
        # An upstream may legitimately remove all auxiliary entries for a service.
        if supplements[service]:
            write_list(output, f"{service}/Sources/{service}-Sukka.list", supplements[service])
        write_list(output, f"{service}/{service}.list", combined)

    for relative, rules in {
        "China/Sources/China-v2fly-Domain.list": cn,
        "OpenAI/Sources/OpenAI-v2fly.list": ai,
        "OpenAI/Sources/OpenAI-Official-Domain.list": official,
        "AdGuard/Ad-Domain.list": compact(ads),
    }.items():
        write_list(output, relative, rules)

    for label, nets in {"China/Sources/China-GeoIP": china_nets,
                        "OpenAI/Sources/OpenAI-ASN-IP": asn_nets,
                        "OpenAI/Sources/OpenAI-Voice-IP": voice_nets}.items():
        for no_resolve in (False, True):
            suffix = "-NoResolve" if no_resolve else ""
            write_list(output, label + suffix + ".list", networks_rules(nets, no_resolve))
    for name, domains, nets in (("China", cn, china_nets), ("OpenAI", ai | official, asn_nets | voice_nets)):
        reduced = compact(domains)
        regular = reduced | networks_rules(nets)
        nr = reduced | networks_rules(nets, True)
        validate_pair(regular, nr)
        write_list(output, f"{name}/{name}.list", regular)
        write_list(output, f"{name}/{name}-NoResolve.list", nr)
        reports[name + "-aggregate"] = {"domains_before_compaction": len(domains), "domains": len(reduced),
                                      "ip_rules": len(regular) - len(reduced), "total": len(regular)}

    # Only stable, public provenance is committed. No clock, machine path or identity.
    provenance = {"upstreams": manifest, "reviewed_files": {
        str(p.relative_to(root)): digest(p) for p in (official_path, excluded_path, social_review_path)},
        "outputs": {str(p.relative_to(output)): {"sha256": digest(p), "rules": len(p.read_text().splitlines())}
                    for p in sorted(output.rglob("*.list"))}}
    json_write(stage / "reports/conversion.json", reports)
    json_write(stage / "reports/manifest.json", provenance)
    # All source parsing, validation and pair checks completed before publication.
    # CI never commits a failed build. Backup permits restoration on local I/O errors.
    backup = workspace / "previous"
    if backup.exists():
        shutil.rmtree(backup)
    backup.mkdir()
    installed = []
    try:
        for name in ("rules", "reports"):
            target = root / name
            if target.exists():
                target.rename(backup / name)
            installed.append(name)
            (stage / name).rename(target)
    except Exception:
        for name in reversed(installed):
            if (root / name).exists():
                shutil.rmtree(root / name)
            if (backup / name).exists():
                (backup / name).rename(root / name)
        raise
    for name, data in reports.items():
        print(name + ": " + json.dumps(data.get("counts", data), sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="rebuild from hash-verified local inputs")
    args = parser.parse_args()
    build(offline=args.offline)
