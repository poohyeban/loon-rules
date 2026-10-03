import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.build import download
from scripts.rules import domain, matches, subdomains, v2fly
from scripts.social import SERVICES, aggregate, sukka_supplement


class SocialTests(unittest.TestCase):
    def setUp(self):
        self.primary = {
            service: {domain("DOMAIN-SUFFIX", service.lower() + ".example")}
            for service in SERVICES
        }
        self.review = {"additions": {"DOMAIN-SUFFIX,ig.example": "Instagram"}, "excluded": {}}

    def test_section_isolation_service_assignment_and_unknowns(self):
        text = """# >> Other
DOMAIN-SUFFIX,other.example
# >> Facebook
DOMAIN-SUFFIX,facebook.example
DOMAIN-SUFFIX,cdn.instagram.example
DOMAIN-SUFFIX,ig.example
# WhatsApp
DOMAIN-SUFFIX,whatsapp.example
DOMAIN-KEYWORD,facebook
DOMAIN-SUFFIX,unreviewed.example
# >> Twitter
DOMAIN-SUFFIX,twitter.example
"""
        selected, report = sukka_supplement(text, self.primary, self.review)
        self.assertEqual(selected["Facebook"], self.primary["Facebook"])
        self.assertEqual(selected["WhatsApp"], self.primary["WhatsApp"])
        self.assertEqual(selected["Instagram"], {domain("DOMAIN-SUFFIX", v) for v in
                                               ("cdn.instagram.example", "ig.example")})
        self.assertEqual(len(report.skipped), 2)
        self.assertEqual(report.counts["input"], 6)

    def test_missing_reviewed_entry_is_not_injected(self):
        result, report = sukka_supplement("# >> Facebook\nDOMAIN-SUFFIX,facebook.example\n",
                                         self.primary, self.review)
        self.assertFalse(result["Instagram"])
        self.assertEqual(report.counts["review_entries_absent_upstream"], 1)

    def test_explicit_exclusion_wins_over_primary_classification(self):
        self.review["excluded"]["DOMAIN-SUFFIX,facebook.example"] = "outside selected scope"
        result, report = sukka_supplement("# >> Facebook\nDOMAIN-SUFFIX,facebook.example\n",
                                         self.primary, self.review)
        self.assertFalse(result["Facebook"])
        self.assertEqual(report.skipped[0]["reason"], "outside selected scope")

    def test_section_drift_and_policy_bearing_input_abort(self):
        for text in ("# >> Renamed\nDOMAIN,facebook.example", "# >> Facebook\n",
                     "# >> Facebook\nDOMAIN,facebook.example\n# >> Facebook\nDOMAIN,ig.example",
                     "# >> Facebook\nDOMAIN,facebook.example,PROXY",
                     "# >> Facebook\nDOMAIN-WILDCARD,*.facebook.example"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                sukka_supplement(text, self.primary, self.review)

    def test_ambiguous_service_boundary_aborts(self):
        self.primary["Instagram"] |= self.primary["Facebook"]
        with self.assertRaises(ValueError):
            sukka_supplement("# >> Facebook\nDOMAIN-SUFFIX,facebook.example\n",
                             self.primary, self.review)

    def test_source_keyword_cannot_claim_an_unrelated_supplement(self):
        self.primary["Facebook"].add(domain("DOMAIN-KEYWORD", "facebook"))
        selected, report = sukka_supplement("# >> Facebook\nDOMAIN-SUFFIX,notfacebook.example\n",
                                            self.primary, self.review)
        self.assertFalse(selected["Facebook"])
        self.assertIn("requires service-boundary review", report.skipped[0]["reason"])

    def test_merge_preserves_exact_domains_without_restoring_skipped_regex(self):
        primary, _ = v2fly("full:api.example\nregexp:^.+\\.media\\.example$\nroot.example\n")
        supplemental = {domain("DOMAIN", "api.example"), domain("DOMAIN", "cdn.root.example")}
        result, report = aggregate(primary, supplemental)
        self.assertEqual(result, primary)
        self.assertEqual(report["exact_duplicates"], 1)
        self.assertEqual(report["covered_rules_removed"], 1)
        self.assertEqual(report["supplement_added"], [])
        for host, expected in (("api.example", True), ("x.api.example", False),
                               ("media.example", False), ("x.media.example", False),
                               ("root.example", True), ("cdn.root.example", True)):
            self.assertEqual(any(matches(r, host) for r in result), expected)
        with self.assertRaises(ValueError):
            aggregate(set(), supplemental)

    def test_reviewed_supplement_is_reported_after_compaction(self):
        result, report = aggregate(self.primary["Instagram"], {domain("DOMAIN-SUFFIX", "ig.example")})
        self.assertEqual(len(result), 2)
        self.assertEqual(report["supplement_added"], ["DOMAIN-SUFFIX,ig.example"])

    def test_shared_upstream_revision_is_resolved_once(self):
        revision = "a" * 40
        sources = {name + ".txt": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/" + name
                   for name in ("whatsapp", "instagram", "facebook")}
        urls = []

        def curl(args, **kwargs):
            urls.append(args[-1])
            Path(args[args.index("--output") + 1]).write_text("example.com\n")

        with tempfile.TemporaryDirectory() as directory, \
             patch("scripts.build.SOURCES", sources), \
             patch("scripts.build.PINNED_REPOS", {"v2fly/domain-list-community"}), \
             patch("scripts.build.subprocess.check_output", return_value=revision + "\trefs/heads/master\n") as resolve, \
             patch("scripts.build.subprocess.run", side_effect=curl):
            manifest = download(Path(directory))
        self.assertEqual(resolve.call_count, 1)
        self.assertTrue(all("/" + revision + "/data/" in url for url in urls))
        self.assertTrue(all(item["commit"] == revision for item in manifest.values()))


if __name__ == "__main__":
    unittest.main()
