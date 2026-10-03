import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.rules import (Rule, Unsupported, adguard, compact, covers, domain,
                          intersects, logic, matches, parse_rule, regex_rules,
                          reviewed_domains, subdomains, v2fly)
from scripts.build import SOURCES, asn_networks, build, digest, validate_pair, voice_networks, write_list
from scripts.audit import scan, BOT_EMAIL


class RuleTests(unittest.TestCase):
    def test_internal_exception_logic_cannot_be_published(self):
        rule = logic("AND", domain("DOMAIN-SUFFIX", "example.com"),
                     logic("NOT", logic("OR", domain("DOMAIN", "a.example.com"),
                                        subdomains("b.example.com"))))
        for candidate in (rule, logic("OR", domain("DOMAIN", "a.example")),
                          logic("NOT", domain("DOMAIN", "a.example"))):
            with self.subTest(kind=candidate.kind), self.assertRaises(Unsupported):
                parse_rule(candidate.render())
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "Existing.list"
                path.write_text("DOMAIN,keep.example\n")
                with self.assertRaises(Unsupported):
                    write_list(Path(directory), path.name, {candidate})
                self.assertEqual(path.read_text(), "DOMAIN,keep.example\n")
        for host, expected in [("example.com", True), ("a.example.com", False),
                               ("b.example.com", True), ("a.b.example.com", False),
                               ("notexample.com", False)]:
            self.assertEqual(matches(rule, host), expected)

    def test_invalid_or_policy_bearing_rules(self):
        invalid = ["DOMAIN,example.com,DIRECT", "DOMAIN-SUFFIX,example.com,REJECT",
                   "IP-CIDR,192.0.2.0/24,PROXY", "DOMAIN-WILDCARD,*.example.com",
                   "DOMAIN-REGEX,.*", "DOMAIN,EXAMPLE.COM", "DOMAIN,bad_.com",
                   "DOMAIN,example.com ", "IP-CIDR6,192.0.2.0/24",
                   "IP-CIDR,192.0.2.1/24", "AND,()", "NOT,((DOMAIN,a),(DOMAIN,b))",
                   "AND,((DOMAIN,a)),DIRECT", "AND,((DOMAIN,a)",
                   "NOT,((IP-CIDR,192.0.2.0/24))", "FINAL,DIRECT"]
        for line in invalid:
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_rule(line)

    def test_subdomain_root_and_boundary(self):
        rule = subdomains("example.com")
        self.assertFalse(matches(rule, "example.com"))
        self.assertFalse(matches(rule, "notexample.com"))
        self.assertTrue(matches(rule, "a.b.example.com"))

    def test_finite_regex_and_limit(self):
        rules = regex_rules(r"^(foo|bar)[0-2]\.example\.com$")
        self.assertEqual(len(rules), 6)
        for p in [r"^a\d+\.com$", r"^a[0-9]{4}\.com$", r"foo\.com$",
                  r"^foo\.com$|bar", r"^.+-mihayo\.akamaized\.net$",
                  r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$",
                  r"^(?i:foo)\.com$", r"^192\.0\.2\.1$", r"^FOO\.com$"]:
            with self.subTest(pattern=p), self.assertRaises(Unsupported):
                regex_rules(p)

    def test_unbounded_subdomains_are_reported_without_suffix_approximation(self):
        cases = [r".+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$",
                 r".+\.awsdns-cn-[0-9][a-e0-9]\.cn$", r"^.+\.example\.com$"]
        text = "full:keep.example\n" + "\n".join("regexp:" + p for p in cases)
        rules, report = v2fly(text)
        self.assertEqual(rules, {domain("DOMAIN", "keep.example")})
        self.assertEqual([x["source_rule"] for x in report.skipped],
                         ["regexp:" + p for p in cases])

    def test_compaction_preserves_membership(self):
        rules = {domain("DOMAIN-SUFFIX", "example.com"), domain("DOMAIN", "a.example.com"),
                 subdomains("example.com"), domain("DOMAIN-SUFFIX", "child.example.com"),
                 domain("DOMAIN", "other.example")}
        reduced = compact(rules)
        self.assertEqual(len(reduced), 2)
        for host in ["example.com", "a.example.com", "z.child.example.com", "other.example", "notexample.com"]:
            self.assertEqual(any(matches(r, host) for r in rules), any(matches(r, host) for r in reduced))

    def test_cover_and_intersection_model(self):
        rules = [domain(k, h) for k in ("DOMAIN", "DOMAIN-SUFFIX")
                 for h in ("example.com", "a.example.com", "other.com")]
        rules += [subdomains(h) for h in ("example.com", "a.example.com", "other.com")]
        samples = [prefix + h for h in ("example.com", "a.example.com", "other.com")
                   for prefix in ("", "x.", "x.y.")]
        for a in rules:
            for b in rules:
                self.assertEqual(intersects(a, b), any(matches(a, h) and matches(b, h) for h in samples))
                self.assertEqual(covers(a, b), all(not matches(b, h) or matches(a, h) for h in samples))

    def test_v2fly_metadata_and_full_diagnostics(self):
        rules, report = v2fly("domain:example.com:@cn\nfull:a.example.com @x\nkeyword:example\n" +
                              "regexp:^x.+$\n" * 40)
        self.assertEqual(len(rules), 3)
        self.assertEqual(len(report.skipped), 40)
        for line in ["Include:foo", "INCLUDE:foo", "include:foo #bar", "unknown:foo"]:
            with self.assertRaises(ValueError):
                v2fly(line)

    def test_reviewed_wildcards_and_exclusions(self):
        result, report = reviewed_domains("*.example.com\na.example.com\nshared.example\n", "shared.example\n")
        self.assertEqual(result, {domain("DOMAIN", "a.example.com")})
        self.assertEqual(report.skipped[0]["source_rule"], "*.example.com")
        self.assertEqual(report.counts["output"], 1)
        self.assertFalse(any(matches(r, "example.com") for r in result))
        for source, excluded in [("", ""), ("a.example", "b.example"), ("a.example", "a.example")]:
            with self.assertRaises(ValueError):
                reviewed_domains(source, excluded)

    def test_adguard_exact_exception_removes_overlapping_suffix(self):
        rules, report = adguard("||example.com^\n@@|example.com|\n")
        self.assertFalse(any(matches(r, "example.com") for r in rules))
        self.assertEqual(rules, set())
        self.assertEqual(report.counts["blocks_removed"], 1)
        self.assertIn("preserve exception", report.skipped[0]["reason"])

    def test_adguard_exceptions_apply_to_every_overlapping_block(self):
        source = "||example.com^\n||safe.example.com^\n.safe.example.com^\n@@||safe.example.com^\n"
        rules, _ = adguard(source)
        for host in ("safe.example.com", "x.safe.example.com"):
            self.assertFalse(any(matches(r, host) for r in rules))
        self.assertEqual(rules, set())

    def test_adguard_two_exceptions(self):
        rules, _ = adguard("||example.com^\n@@|a.example.com|\n@@||b.example.com^\n")
        for rule in rules:
            self.assertEqual(parse_rule(rule.render()), rule)
        self.assertFalse(any(matches(r, "a.example.com") for r in rules))
        self.assertFalse(any(matches(r, "x.b.example.com") for r in rules))
        self.assertEqual(rules, set())

    def test_adguard_keeps_disjoint_blocks_and_exact_apex(self):
        rules, _ = adguard("|example.com|\n||example.com^\n||ads.other.com^\n@@.example.com^\n")
        self.assertEqual(rules, {domain("DOMAIN", "example.com"),
                                 domain("DOMAIN-SUFFIX", "ads.other.com")})
        self.assertFalse(any(matches(r, "child.example.com") for r in rules))

    def test_adguard_partial_label_envelope_does_not_overblock(self):
        rules, report = adguard("||foobar.com^\n@@||foo*bar.com^\n||example.org^\n")
        self.assertFalse(any(matches(r, "foobar.com") for r in rules))
        self.assertTrue(any(matches(r, "example.org") for r in rules))
        self.assertEqual(report.counts["conservative_exceptions"], 1)

    def test_adguard_subdomain_patterns(self):
        rules, report = adguard(".example.com^\n")
        self.assertEqual(rules, set())
        self.assertEqual(report.skipped[0]["source_rule"], ".example.com^")

    def test_finite_adguard_regex_and_exact_exception(self):
        rules, report = adguard(r"/^(ads|safe)\.example\.com$/" + "\n@@|safe.example.com|\n")
        self.assertEqual(rules, {domain("DOMAIN", "ads.example.com")})
        self.assertEqual(report.counts["blocks_removed"], 1)

    def test_failed_build_leaves_previous_publication_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("rules", "reports"):
                (root / name).mkdir()
                (root / name / "existing").write_text("last good publication")
            inputs = root / "build/inputs"
            inputs.mkdir(parents=True)
            manifest = {}
            for name, url in SOURCES.items():
                path = inputs / name
                path.write_text("||ads.example^\n@@/foo.*/" if name == "adguard.txt" else "example.com")
                manifest[name] = {"url": url, "sha256": digest(path)}
            (inputs / "manifest.json").write_text(json.dumps(manifest))
            reviewed = root / "data/OpenAI"
            reviewed.mkdir(parents=True)
            (reviewed / "official-domains.txt").write_text("keep.example\nshared.example\n")
            (reviewed / "official-domains-excluded.txt").write_text("shared.example\n")
            with self.assertRaisesRegex(ValueError, "unrepresentable AdGuard exception"):
                build(root, offline=True)
            for name in ("rules", "reports"):
                self.assertEqual([p.name for p in (root / name).iterdir()], ["existing"])
                self.assertEqual((root / name / "existing").read_text(), "last good publication")

    def test_adguard_partial_suffix_exception_is_conservative(self):
        rules, report = adguard("||metric.gstatic.com^\n@@-ds.metric.gstatic.com^|\n")
        self.assertEqual(rules, set())
        self.assertEqual(report.counts["conservative_exceptions"], 1)

    def test_adguard_badfilter_and_hosts(self):
        rules, _ = adguard("||example.com^\n||example.com^$badfilter\n0.0.0.0 a.example b.example\n")
        self.assertEqual(rules, {domain("DOMAIN", "a.example"), domain("DOMAIN", "b.example")})

    def test_adguard_unsafe_exceptions_abort(self):
        for extra in ["@@/foo.*/", "@@||example.com^$important", "@@||*^", "@@/unclosed"]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                adguard("||example.com^\n" + extra)

    def test_adguard_safe_skips(self):
        rules, report = adguard("||example.com^$important\n||ads*.com^\n||192.0.2.1^\n"
                                "||safe.example^\n@@/foo#bar/\n")
        self.assertEqual(rules, {domain("DOMAIN-SUFFIX", "safe.example")})
        self.assertEqual(len(report.skipped), 3)

    def test_pair_content_and_modifier_checks(self):
        domains = {subdomains("example.com")}
        base = Rule("IP-CIDR", "192.0.2.0/24")
        nr = Rule("IP-CIDR", "192.0.2.0/24", no_resolve=True)
        validate_pair(domains | {base}, domains | {nr})
        for left, right in [(domains | {base}, {nr}), ({nr}, {nr}), ({base}, {base})]:
            with self.assertRaises(ValueError):
                validate_pair(left, right)

    def test_voice_schema_and_ip_versions(self):
        payload = {"creationTime": "2026-01-01T00:00:00Z", "prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}
        self.assertEqual(voice_networks(payload), {ipaddress.ip_network("192.0.2.0/24")})
        for records in [[], [{"ipv6Prefix": "192.0.2.0/24"}], [{"unknown": "192.0.2.0/24"}],
                        [{"ipv4Prefix": "192.0.2.1/24"}]]:
            with self.assertRaises(ValueError):
                voice_networks(dict(payload, prefixes=records))

    def test_asn_partial_coverage_is_reported_and_empty_aborts(self):
        db = MagicMock()
        network = ipaddress.ip_network("192.0.2.0/24")
        with patch("maxminddb.open_database", return_value=db):
            db.__enter__.return_value = [(network, {"autonomous_system_number": 401518})]
            networks, report = asn_networks("fixture")
            self.assertEqual(networks, {network})
            self.assertEqual(report["missing_asns"], [401864])
            self.assertEqual(report["networks_by_asn"]["401864"], 0)
            db.__enter__.return_value = []
            with self.assertRaises(ValueError):
                asn_networks("fixture")

    def test_privacy_detection_does_not_return_values(self):
        secret = ("ghp_" + "a" * 32).encode()
        findings = scan(secret, "fixture")
        self.assertEqual(findings, ["fixture: github-token"])
        self.assertNotIn(secret.decode(), str(findings))
        self.assertEqual(scan(BOT_EMAIL.encode(), "fixture"), [])
        email = ("private" + "@" + "example.com").encode()
        self.assertEqual(scan(email, "fixture"), ["fixture: non-bot-email"])


if __name__ == "__main__":
    unittest.main()
