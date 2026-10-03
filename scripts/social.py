"""Separate service classifications with a bounded, reviewed Sukka supplement."""
from __future__ import annotations

from scripts.rules import Report, Rule, compact, covers, parse_rule, shape

SERVICES = ("WhatsApp", "Instagram", "Facebook")


def sukka_supplement(text: str, primary: dict[str, set[Rule]], review: dict):
    """Read the original section; never infer service ownership from a keyword."""
    if set(primary) != set(SERVICES) or set(review) != {"additions", "excluded"}:
        raise ValueError("invalid social source inventory")
    additions, excluded = review["additions"], review["excluded"]
    if set(additions) & set(excluded):
        raise ValueError("conflicting Sukka review entries")
    for line, service in additions.items():
        if service not in SERVICES or parse_rule(line).kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            raise ValueError("invalid reviewed Sukka addition")
    for line, reason in excluded.items():
        parse_rule(line)
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("missing Sukka exclusion reason")

    selected = {service: set() for service in SERVICES}
    report = Report()
    active, sections = False, 0
    seen = set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("# >> "):
            active = line == "# >> Facebook"
            sections += int(active)
        if not active or not line or line.startswith("#"):
            continue
        report.counts["input"] += 1
        rule = parse_rule(line)  # Unknown syntax/policies fail instead of widening a rule.
        seen.add(line)
        if line in excluded:
            report.skip(number, line, excluded[line])
            continue
        if rule.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            report.skip(number, line, "not a service-specific exact domain or suffix")
            continue
        owners = set()
        for service, rules in primary.items():
            for candidate in rules:
                try:
                    shape(candidate)
                except ValueError:
                    continue
                if covers(candidate, rule):
                    owners.add(service)
        if line in additions:
            owners.add(additions[line])
        if len(owners) > 1:
            raise ValueError(f"ambiguous Sukka service classification at line {number}")
        if not owners:
            report.skip(number, line, "unclassified domain; requires service-boundary review")
            continue
        service = owners.pop()
        selected[service].add(rule)
        report.counts[service] += 1
    if sections != 1 or not report.counts["input"]:
        raise ValueError("missing, duplicated or empty Sukka Facebook section")
    # A reviewed entry is a selector, not a permanent locally injected rule.
    report.counts["review_entries_absent_upstream"] = len((set(additions) | set(excluded)) - seen)
    report.counts["output"] = sum(map(len, selected.values()))
    return selected, report


def aggregate(primary: set[Rule], supplement: set[Rule]):
    if not primary:
        raise ValueError("empty primary service rules")
    merged = primary | supplement
    result = compact(merged)
    base = compact(primary)
    return result, {
        "primary": len(primary), "supplement": len(supplement),
        "exact_duplicates": len(primary & supplement),
        "covered_rules_removed": len(merged) - len(result),
        "supplement_added": sorted(r.render() for r in result - base),
        "total": len(result),
    }
