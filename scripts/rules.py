"""Policy-free Loon rules and deliberately bounded upstream conversions.

Regex parsing uses CPython's parser, but only a small, explicit RE2-compatible
subset is interpreted. Nothing from upstream is evaluated as Python code.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from re import _constants as rx, _parser


class Unsupported(ValueError):
    pass


def hostname(value: str) -> str:
    value = value.lower()
    if not value or len(value) > 253 or not value.isascii():
        raise Unsupported("invalid hostname")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s)
           for s in value.split(".")):
        raise Unsupported("invalid hostname label")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise Unsupported("IP literal is not a hostname rule")


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str = ""
    children: tuple[Rule, ...] = ()
    no_resolve: bool = False

    def render(self) -> str:
        if self.children:
            return self.kind + ",(" + ",".join("(" + c.render() + ")" for c in self.children) + ")"
        return f"{self.kind},{self.value}" + (",no-resolve" if self.no_resolve else "")


def domain(kind: str, value: str) -> Rule:
    if kind == "DOMAIN-KEYWORD":
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", value):
            raise Unsupported("invalid keyword")
        return Rule(kind, value)
    return Rule(kind, hostname(value))


def logic(kind: str, *children: Rule) -> Rule:
    if kind not in {"AND", "OR", "NOT"} or not children or (kind == "NOT" and len(children) != 1):
        raise Unsupported("invalid logical arity")
    return Rule(kind, children=tuple(children))


def subdomains(value: str) -> Rule:
    return logic("AND", domain("DOMAIN-SUFFIX", value), logic("NOT", domain("DOMAIN", value)))


def split_outer(value: str) -> list[str]:
    depth, start, result = 0, 0, []
    for i, char in enumerate(value):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise Unsupported("unbalanced parentheses")
        elif char == "," and depth == 0:
            result.append(value[start:i])
            start = i + 1
    if depth:
        raise Unsupported("unbalanced parentheses")
    result.append(value[start:])
    return result


def parse_rule(line: str, depth: int = 0) -> Rule:
    """Validate publishable rules; internal exception logic is never exported."""
    if depth > 12 or line.strip() != line or any(c.isspace() for c in line):
        raise Unsupported("non-canonical rule or excessive nesting")
    parts = split_outer(line)
    kind = parts[0]
    if kind in {"AND", "OR", "NOT"}:
        raise Unsupported("logical rules are disabled for Loon compatibility")
    elif kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"} and len(parts) == 2:
        result = domain(kind, parts[1])
    elif kind in {"IP-CIDR", "IP-CIDR6"} and len(parts) in {2, 3}:
        if len(parts) == 3 and parts[2] != "no-resolve":
            raise Unsupported("policy or unsupported IP modifier")
        net = ipaddress.ip_network(parts[1], strict=True)
        if "/" not in parts[1] or net.version != (4 if kind == "IP-CIDR" else 6):
            raise Unsupported("wrong IP version or absent prefix length")
        result = Rule(kind, str(net), no_resolve=len(parts) == 3)
    else:
        raise Unsupported("unsupported type, policy or field count")
    if result.render() != line:
        raise Unsupported("non-canonical rule")
    return result


def strict_suffix(rule: Rule) -> str | None:
    if rule.kind == "AND" and len(rule.children) == 2:
        first = rule.children[0]
        if first.kind == "DOMAIN-SUFFIX" and rule == subdomains(first.value):
            return first.value
    return None


def matches(rule: Rule, host: str) -> bool:
    """Hostname set model used for conversion checks, not a Loon emulator."""
    if rule.kind == "DOMAIN":
        return host == rule.value
    if rule.kind == "DOMAIN-SUFFIX":
        return host == rule.value or host.endswith("." + rule.value)
    if rule.kind == "DOMAIN-KEYWORD":
        return rule.value in host
    values = [matches(c, host) for c in rule.children]
    if rule.kind == "AND":
        return all(values)
    if rule.kind == "OR":
        return any(values)
    if rule.kind == "NOT":
        return not values[0]
    raise Unsupported("not a hostname expression")


def shape(rule: Rule) -> tuple[str, str]:
    suffix = strict_suffix(rule)
    if suffix:
        return "subdomains", suffix
    if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return ("exact" if rule.kind == "DOMAIN" else "suffix"), rule.value
    raise Unsupported("unsupported exception shape")


def covers(outer: Rule, inner: Rule) -> bool:
    a, x = shape(outer)
    b, y = shape(inner)
    if b == "exact":
        return matches(outer, y)
    if a == "exact":
        return False
    if y.endswith("." + x):
        return True
    return x == y and (a == "suffix" or b == "subdomains")


def intersects(a: Rule, b: Rule) -> bool:
    ak, av = shape(a)
    bk, bv = shape(b)
    if ak == "exact":
        return matches(b, av)
    if bk == "exact":
        return matches(a, bv)
    return av == bv or av.endswith("." + bv) or bv.endswith("." + av)


def compact(rules: set[Rule]) -> set[Rule]:
    """Only remove rules covered by an unconditional suffix in this same set."""
    suffixes = {r.value for r in rules if r.kind == "DOMAIN-SUFFIX"}
    result = set()
    for rule in rules:
        value = strict_suffix(rule)
        if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            value = rule.value
        if value:
            labels = value.split(".")
            start = 1 if rule.kind == "DOMAIN-SUFFIX" else 0
            if any(".".join(labels[i:]) in suffixes for i in range(start, len(labels))):
                continue
        result.add(rule)
    return result


def _expand(tokens, limit: int) -> set[str]:
    output = {""}
    for op, value in tokens:
        if op == rx.LITERAL:
            atom = {chr(value)}
        elif op == rx.SUBPATTERN:
            _, add_flags, del_flags, children = value
            if add_flags or del_flags:
                raise Unsupported("regex flags")
            atom = _expand(children, limit)
        elif op == rx.BRANCH:
            atom = set().union(*(_expand(branch, limit) for branch in value[1]))
        elif op == rx.IN:
            atom = set()
            for mode, arg in value:
                if mode == rx.LITERAL:
                    atom.add(chr(arg))
                elif mode == rx.RANGE and arg[1] - arg[0] < 128:
                    atom.update(chr(i) for i in range(arg[0], arg[1] + 1))
                elif mode == rx.CATEGORY and arg == rx.CATEGORY_DIGIT:
                    atom.update("0123456789")  # RE2's ASCII \d
                else:
                    raise Unsupported("non-finite or unsupported character class")
        elif op == rx.MAX_REPEAT:
            low, high, children = value
            if high == rx.MAXREPEAT or high > 253:
                raise Unsupported("unbounded or excessive regex repetition")
            unit = _expand(children, limit)
            atom, current = set(), {""}
            for count in range(high + 1):
                if count >= low:
                    atom.update(current)
                    if len(atom) > limit:
                        raise Unsupported("regex expansion limit")
                if count < high:
                    current = _product(current, unit, limit)
        else:
            raise Unsupported(f"unsupported regex operation: {op}")
        output = _product(output, atom, limit)
    return output


def _product(left: set[str], right: set[str], limit: int) -> set[str]:
    if len(left) * len(right) > limit:
        raise Unsupported("regex expansion limit")
    result = {a + b for a in left for b in right}
    if any(len(s) > 253 for s in result):
        raise Unsupported("regex hostname too long")
    return result


def regex_rules(pattern: str, limit: int = 1000) -> set[Rule]:
    # Do not let Python-only features acquire accidental upstream semantics.
    if re.search(r"\(\?(?!:)|\\(?![.d-])", pattern):
        raise Unsupported("unsupported regex extension or escape")
    try:
        parsed = _parser.parse(pattern, 0)
    except re.error as error:
        raise Unsupported("invalid regex") from error
    tokens = list(parsed)
    if parsed.state.flags != re.UNICODE or not tokens or tokens[-1] != (rx.AT, rx.AT_END):
        raise Unsupported("regex must have an absolute end anchor")
    tokens.pop()
    anchored = bool(tokens and tokens[0] == (rx.AT, rx.AT_BEGINNING))
    if anchored:
        tokens.pop(0)
    if not anchored:
        raise Unsupported("finite regex needs a start anchor")
    values = _expand(tokens, limit)
    for value in values:
        if hostname(value) != value:
            raise Unsupported("regex normalization would change its language")
    return {domain("DOMAIN", v) for v in values}


@dataclass
class Report:
    counts: Counter = field(default_factory=Counter)
    skipped: list[dict] = field(default_factory=list)

    def skip(self, number: int, line: str, reason: str) -> None:
        self.skipped.append({"line": number, "source_rule": line, "reason": reason})
        self.counts["skipped"] += 1

    def json(self) -> dict:
        return {"counts": dict(sorted(self.counts.items())), "skipped": self.skipped}


def v2fly(text: str) -> tuple[set[Rule], Report]:
    output, report = set(), Report()
    mapping = {"domain": "DOMAIN-SUFFIX", "full": "DOMAIN", "keyword": "DOMAIN-KEYWORD"}
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        report.counts["input"] += 1
        line = re.split(r":@|\s+[@&]|#", raw.strip(), maxsplit=1)[0].strip()
        kind, sep, value = line.partition(":")
        if not sep:
            kind, value = "domain", kind
        kind = kind.lower()
        if kind == "include":
            raise ValueError(f"unresolved v2fly include at line {number}")
        try:
            if kind == "regexp":
                converted = regex_rules(value)
                report.counts["regex_converted"] += 1
                report.counts["regex_output"] += len(converted)
            elif kind in mapping:
                converted = {domain(mapping[kind], value)}
            else:
                raise ValueError(f"unknown v2fly type at line {number}: {kind}")
            output.update(converted)
        except Unsupported as error:
            if kind != "regexp":
                raise ValueError(f"malformed v2fly {kind} at line {number}") from error
            report.skip(number, raw, str(error))
    report.counts["output"] = len(output)
    return output, report


def reviewed_domains(text: str, excluded_text: str) -> tuple[set[Rule], Report]:
    def entries(value):
        return {s.split("#", 1)[0].strip().lower() for s in value.splitlines()
                if s.split("#", 1)[0].strip()}
    source, exclusions = entries(text), entries(excluded_text)
    if not source or not exclusions <= source or not source - exclusions:
        raise ValueError("invalid reviewed domain snapshot or exclusions")
    # Validate excluded entries as well, so a malformed snapshot never hides.
    for s in source:
        hostname(s[2:] if s.startswith("*.") else s)
    report = Report(Counter(input=len(source), excluded=len(exclusions)))
    output = set()
    for number, raw in enumerate(text.splitlines(), 1):
        s = raw.split("#", 1)[0].strip().lower()
        if not s or s in exclusions:
            continue
        if s.startswith("*."):
            report.skip(number, s, "strict subdomains require disabled logical rules")
        else:
            output.add(domain("DOMAIN", s))
    report.counts["output"] = len(output)
    return output, report


def _ad_parts(line: str) -> tuple[bool, str, list[str]]:
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    if body.startswith("/"):
        end = body.rfind("/")
        if end <= 0:
            raise Unsupported("unclosed regex")
        pattern, rest = body[:end + 1], body[end + 1:]
        if rest and not rest.startswith("$"):
            raise Unsupported("invalid regex suffix")
        return exception, pattern, rest[1:].split(",") if rest else []
    pattern, sep, rest = body.partition("$")
    return exception, pattern, rest.split(",") if sep else []


def _ad_basic(pattern: str) -> set[Rule]:
    m = re.fullmatch(r"\|\|([^*?^|]+)\^\|?", pattern)
    if m:
        return {domain("DOMAIN-SUFFIX", m[1])}
    m = re.fullmatch(r"\.([^*?^|]+)\^\|?", pattern)
    if m:
        return {subdomains(m[1])}
    m = re.fullmatch(r"\|([^*?^|]+?)\^?\|", pattern)
    if m:
        return {domain("DOMAIN", m[1])}
    if pattern.startswith("/") and pattern.endswith("/"):
        return regex_rules(pattern[1:-1])
    fields = pattern.split("#", 1)[0].split()
    if len(fields) >= 2:
        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError as error:
            raise Unsupported("unsupported hostname pattern") from error
        if not (address.is_loopback or address.is_unspecified):
            raise Unsupported("non-blocking hosts address")
        return {domain("DOMAIN", value) for value in fields[1:]}
    return {domain("DOMAIN", pattern)}


def _exception_envelope(pattern: str) -> Rule:
    if not re.search(r"(?:\^\|?|\|)$", pattern):
        raise Unsupported("cannot safely bound exception")
    tail = re.split(r"[*?]", pattern)[-1].rstrip("^|")
    # Discard a partial/unanchored label. foo*bar.com is NOT bounded
    # by bar.com; only the complete label com is a conservative envelope.
    if "." not in tail:
        raise Unsupported("exception has no complete fixed suffix")
    suffix = tail.split(".", 1)[1]
    return domain("DOMAIN-SUFFIX", suffix)


def _impossible_hostname_regex(pattern: str) -> bool:
    if not pattern.startswith("/") or not pattern.endswith("/"):
        return False
    try:
        parsed = _parser.parse(pattern[1:-1], 0)
    except re.error:
        return False
    # A mandatory top-level literal # cannot occur in a DNS hostname.
    return any(op == rx.LITERAL and value == ord("#") for op, value in parsed)


def adguard(text: str) -> tuple[set[Rule], Report]:
    report, parsed, disabled = Report(), [], set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        body = line[2:] if line.startswith("@@") else line
        if not body.startswith("/") and any(
                marker in line for marker in ("##", "#@#", "#$#", "#%#", "#?#", "#$?#")):
            report.counts["cosmetic_ignored"] += 1
            continue
        report.counts["input"] += 1
        try:
            exception, pattern, modifiers = _ad_parts(line)
        except Unsupported as error:
            if line.startswith("@@"):
                raise ValueError(f"unsafe AdGuard exception at line {number}") from error
            report.skip(number, line, str(error))
            continue
        if "badfilter" in modifiers:
            if modifiers.count("badfilter") != 1:
                raise ValueError("ambiguous badfilter")
            remaining = [m for m in modifiers if m != "badfilter"]
            disabled.add(("@@" if exception else "") + pattern + ("$" + ",".join(remaining) if remaining else ""))
            report.counts["badfilter"] += 1
        else:
            parsed.append((number, line, exception, pattern, modifiers))
    blocks, exceptions, block_sources = set(), set(), {}
    for number, line, exception, pattern, modifiers in parsed:
        if line in disabled:
            report.counts["disabled"] += 1
            continue
        try:
            if modifiers:
                raise Unsupported("modifier requires unsupported semantics")
            converted = _ad_basic(pattern)
        except Unsupported as error:
            if not exception:
                report.skip(number, line, str(error))
                continue
            if modifiers:
                raise ValueError(f"unsafe modified exception at line {number}") from error
            if _impossible_hostname_regex(pattern):
                report.counts["non_hostname_exception"] += 1
                continue
            try:
                converted = {_exception_envelope(pattern)}
                report.counts["conservative_exceptions"] += 1
                report.skip(number, line, "exception conservatively bounded; may under-block")
            except Unsupported:
                raise ValueError(f"unrepresentable AdGuard exception at line {number}") from error
        if exception:
            # Strict-subdomain conditions can remain in the build-time model.
            # Removing an intersecting block preserves the exception without
            # sending AND/NOT expressions to Loon.
            exceptions.update(converted)
        else:
            for rule in converted:
                if rule.children:
                    report.skip(number, line, "strict subdomains require disabled logical rules")
                    continue
                blocks.add(rule)
                block_sources.setdefault(rule, []).append((number, line))
    output = set()
    for block in sorted(blocks, key=Rule.render):
        conflicts = sorted((e for e in exceptions if intersects(block, e)), key=Rule.render)
        if conflicts:
            report.counts["blocks_removed"] += 1
            for number, line in block_sources[block]:
                report.skip(number, line, "block removed to preserve exception: " + block.render())
        else:
            output.add(block)
    report.counts["exceptions"] = len(exceptions)
    report.counts["output"] = len(output)
    return output, report
