import contextlib
import io
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts.build import SOURCES, build, digest, json_write
from scripts.validation import audit_publication


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        inputs = self.root / "build/inputs"
        inputs.mkdir(parents=True)
        content = {name: "fixture" for name in SOURCES}
        content.update({"cn.txt": "cn.example\n", "openai.txt": "full:api.openai.example\n",
                        "anthropic.txt": "anthropic.example\nfull:service.b-cdn.example\n",
                        "adguard.txt": "||ads.example^\n",
                        "sukka-global.txt": "# >> Facebook\nDOMAIN-SUFFIX,facebook.example\n",
                        "voice.json": json.dumps({"creationTime": "2026-01-01T00:00:00Z",
                                                  "prefixes": [{"ipv4Prefix": "198.51.100.0/24"}]})})
        for service in ("whatsapp", "instagram", "facebook"):
            content[service + ".txt"] = service + ".example\n"
        manifest = {}
        for name, url in SOURCES.items():
            path = inputs / name
            path.write_text(content[name])
            info = {"url": url, "sha256": digest(path), "bytes": path.stat().st_size}
            for branch in ("master", "release"):
                if f"/{branch}/" in url:
                    info.update(commit="a" * 40, resolved_url=url.replace(f"/{branch}/", "/" + "a" * 40 + "/"))
            manifest[name] = info
        json_write(inputs / "manifest.json", manifest)
        reviewed = self.root / "data/OpenAI"
        reviewed.mkdir(parents=True)
        (reviewed / "official-domains.txt").write_text("api.openai.example\nshared.example\n")
        (reviewed / "official-domains-excluded.txt").write_text("shared.example\n")
        json_write(self.root / "data/Meta/sukka-review.json", {"additions": {}, "excluded": {}})
        self.asns = [
            (ipaddress.ip_network("203.0.113.0/24"), {"autonomous_system_number": 399358,
                                                    "autonomous_system_organization": "Anthropic, PBC"}),
            (ipaddress.ip_network("2001:db8:2::/48"), {"autonomous_system_number": 399358}),
            (ipaddress.ip_network("198.18.0.0/24"), {"autonomous_system_number": 401518}),
            (ipaddress.ip_network("198.19.0.0/24"), {"autonomous_system_number": 999}),
        ]
        self.rebuild()

    def database(self, path):
        db = MagicMock()
        reader = db.__enter__.return_value
        country = Path(path).name == "Country.mmdb"
        reader.__iter__.return_value = (
            [(ipaddress.ip_network(n), {"country": {"iso_code": "CN"}})
             for n in ("192.0.2.0/24", "2001:db8:1::/48")] if country else self.asns)
        reader.metadata.return_value = SimpleNamespace(
            database_type="GeoLite2-Country" if country else "GeoLite2-ASN",
            ip_version=6, build_epoch=1767225600)
        return db

    def rebuild(self):
        with patch("maxminddb.open_database", side_effect=self.database), contextlib.redirect_stdout(io.StringIO()):
            build(self.root, offline=True)

    def refresh_manifest(self, relative):
        path = self.root / "rules" / relative
        manifest_path = self.root / "reports/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["outputs"][relative] = {"sha256": digest(path), "rules": len(path.read_text().splitlines())}
        json_write(manifest_path, manifest)

    def snapshot(self):
        return {str(p.relative_to(self.root)): digest(p) for folder in ("rules", "reports")
                for p in (self.root / folder).rglob("*") if p.is_file()}

    def test_claude_separates_own_asn_from_openai_and_shared_clouds(self):
        rules = (self.root / "rules/Claude/Claude.list").read_text()
        self.assertIn("IP-CIDR,203.0.113.0/24\n", rules)
        self.assertIn("IP-CIDR6,2001:db8:2::/48\n", rules)
        self.assertIn("DOMAIN,service.b-cdn.example\n", rules)
        self.assertNotIn("198.18.", rules)
        self.assertNotIn("198.19.", rules)
        self.assertNotIn("DOMAIN-SUFFIX,b-cdn.example", rules)
        self.assertEqual(audit_publication(self.root)["pairs"], 7)
        self.assertEqual(audit_publication(self.root)["sources"], 11)

    def test_offline_rebuild_is_identical(self):
        before = self.snapshot()
        self.rebuild()
        self.assertEqual(before, self.snapshot())

    def test_missing_claude_asn_aborts_before_replacing_previous_outputs(self):
        before = self.snapshot()
        self.asns = [record for record in self.asns if record[1]["autonomous_system_number"] != 399358]
        with self.assertRaisesRegex(ValueError, "lacks all"):
            self.rebuild()
        self.assertEqual(before, self.snapshot())

    def test_audit_rejects_pair_content_drift_even_with_updated_hash(self):
        path = "Claude/Claude-NoResolve.list"
        output = self.root / "rules" / path
        output.write_text(output.read_text().replace("DOMAIN-SUFFIX,anthropic.example\n", ""))
        self.refresh_manifest(path)
        with self.assertRaisesRegex(ValueError, "sets differ"):
            audit_publication(self.root)

    def test_audit_rejects_wrong_aggregate_even_when_both_variants_agree(self):
        for path in ("Claude/Claude.list", "Claude/Claude-NoResolve.list"):
            output = self.root / "rules" / path
            output.write_text(output.read_text().replace("DOMAIN-SUFFIX,anthropic.example\n", ""))
            self.refresh_manifest(path)
        with self.assertRaisesRegex(ValueError, "aggregate does not match"):
            audit_publication(self.root)

    def test_audit_rejects_duplicate_lines_and_noncanonical_encoding(self):
        path = "Claude/Sources/Claude-v2fly.list"
        output = self.root / "rules" / path
        original = output.read_bytes()
        for data in (original + original, original.replace(b"\n", b"\r\n"), b"\xef\xbb\xbf" + original):
            output.write_bytes(data)
            self.refresh_manifest(path)
            with self.assertRaises(ValueError):
                audit_publication(self.root)

    def test_audit_rejects_changed_reviewed_snapshot(self):
        (self.root / "data/OpenAI/official-domains.txt").write_text("changed.example\n")
        with self.assertRaisesRegex(ValueError, "reviewed digest mismatch"):
            audit_publication(self.root)

    def test_audit_rejects_missing_required_file_even_with_manifest_updated(self):
        path = "Claude/Claude.list"
        (self.root / "rules" / path).unlink()
        manifest_path = self.root / "reports/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        del manifest["outputs"][path]
        json_write(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "output inventory"):
            audit_publication(self.root)

    def test_audit_rejects_mixed_v2fly_revisions(self):
        manifest_path = self.root / "reports/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        entry = manifest["upstreams"]["anthropic.txt"]
        entry["commit"] = "b" * 40
        entry["resolved_url"] = entry["url"].replace("/master/", "/" + "b" * 40 + "/")
        json_write(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "mixes revisions"):
            audit_publication(self.root)


if __name__ == "__main__":
    unittest.main()
