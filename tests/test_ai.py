import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_ai", ROOT / "scripts/build_ai.py")
ai = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ai)


def fixtures():
    # A complete offline regression fixture, not downloaded during CI tests.
    core = ["chatgpt.com", "openai.com", "oaistatic.com", "claude.ai", "claude.com",
            "anthropic.com", "gemini.google.com", "perplexity.ai", "poe.com",
            "grok.com", "x.ai", "groq.com", "sora.com", "dify.ai", "jasper.ai",
            "openart.ai", "cursor.sh", "notebooklm.google", "aistudio.google.com",
            "deepmind.google"]
    providers = [
        ["oaiusercontent.com", "oaistatsig.com", "chatgpt.livekit.cloud", "host.livekit.cloud", "turn.livekit.cloud"],
        ["claude.app", "claudeusercontent.com", "claudemcpcontent.com", "claudemcpclient.com", "claude.ai"],
        ["gemini.gstatic.com", "generativelanguage.googleapis.com", "geminiweb-pa.clients6.google.com", "aisandbox-pa.googleapis.com", "gemini.google.com"],
    ]
    data = {"sukka_domains": "\n".join("DOMAIN-SUFFIX," + x for x in core),
            "sukka_voice": "\n".join("IP-CIDR,4.150.48." + str(i) + "/32,no-resolve" for i in range(1, 22))}
    for name, domains in zip(("openai", "anthropic", "google-gemini"), providers):
        rule = {"domain_suffix": domains}
        if name == "openai":
            rule["domain_regex"] = ai.AZURE_REGEX  # actual upstream uses a scalar
        data[name] = json.dumps({"version": 2, "rules": [rule]})
    return data


class AITests(unittest.TestCase):
    def test_combined_coverage_and_shared_service_boundaries(self):
        files, manifest = ai.assemble(fixtures())
        self.assertIn("oaiusercontent.com", files["AI-Supplement.list"])
        self.assertIn("claudemcpcontent.com", files["AI-Supplement.list"])
        self.assertIn("DOMAIN-WILDCARD,chatgpt-async", files["AI-Supplement.list"])
        self.assertNotIn("DOMAIN-SUFFIX,chatgpt.com\n", files["AI-Supplement.list"])
        self.assertEqual(manifest["counts"]["voice_ip"], 21)

    def test_failed_source_does_not_replace_published_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            ai.publish(fixtures(), tmp)
            before = {p.name: p.read_bytes() for p in Path(tmp).iterdir()}
            bad = fixtures()
            bad["sukka_voice"] = "<html>upstream failure</html>"
            with self.assertRaises(ValueError):
                ai.publish(bad, tmp)
            self.assertEqual(before, {p.name: p.read_bytes() for p in Path(tmp).iterdir()})

    def test_future_regex_requires_review_instead_of_silent_omission(self):
        data = fixtures()
        doc = json.loads(data["openai"])
        doc["rules"][0]["domain_regex"] = [ai.AZURE_REGEX, "^unknown.*$"]
        data["openai"] = json.dumps(doc)
        with self.assertRaisesRegex(ValueError, "Unreviewed provider regex"):
            ai.assemble(data)

    def test_shared_root_is_rejected(self):
        data = fixtures()
        doc = json.loads(data["anthropic"])
        doc["rules"][0]["domain_suffix"].append("auth0.com")
        data["anthropic"] = json.dumps(doc)
        with self.assertRaisesRegex(ValueError, "Shared provider root"):
            ai.assemble(data)

    def test_voice_asn_fallback_is_not_applied_to_all_traffic(self):
        data = fixtures()
        data["sukka_voice"] += "\nIP-ASN,399358\n"
        files, manifest = ai.assemble(data)
        self.assertNotIn("IP-ASN", files["AI-Voice-IP.list"])
        self.assertEqual(manifest["excluded_voice_rules"], ["IP-ASN,399358"])

    def test_voice_subscription_keeps_update_interval_at_top_level(self):
        snippet = (ROOT / "examples/AI-Rules.snippet").read_text()
        voice_lines = [line for line in snippet.splitlines() if "AI-Voice-IP.list" in line]
        self.assertEqual(len(voice_lines), 1)
        self.assertTrue(voice_lines[0].startswith("RULE-SET,"))
        self.assertIn("update-interval=21600", voice_lines[0])
        self.assertNotIn("DEST-PORT", voice_lines[0])  # TCP fallback must also follow SG

    def test_unchanged_inputs_do_not_rewrite_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            ai.publish(fixtures(), tmp)
            before = {p.name: p.stat().st_mtime_ns for p in Path(tmp).iterdir()}
            ai.publish(fixtures(), tmp)
            self.assertEqual(before, {p.name: p.stat().st_mtime_ns for p in Path(tmp).iterdir()})

    def test_new_upstream_domain_is_checked_without_editing_sample_list(self):
        data = fixtures()
        doc = json.loads(data["anthropic"])
        doc["rules"][0]["domain_suffix"].append("new-provider-cdn.example")
        data["anthropic"] = json.dumps(doc)
        original = ai.supplement_only
        def broken_conversion(providers, base):
            return {(kind, value) for kind, value in original(providers, base)
                    if value != "new-provider-cdn.example"}
        with mock.patch.object(ai, "supplement_only", side_effect=broken_conversion):
            with self.assertRaisesRegex(ValueError, "Upstream provider domain lost"):
                ai.assemble(data)

    def test_invalid_url_regex_and_extra_options_are_not_published(self):
        for extra in ["URL-REGEX,(", "DOMAIN-KEYWORD,openai,unreviewed-option"]:
            data = fixtures()
            data["sukka_domains"] += "\n" + extra
            with self.assertRaises(ValueError):
                ai.assemble(data)

    def test_fetch_failure_has_bounded_retries(self):
        with mock.patch.object(ai.urllib.request, "urlopen", side_effect=urllib.error.URLError("unavailable")) as fetch:
            with mock.patch.object(ai.time, "sleep") as sleep:
                with self.assertRaises(urllib.error.URLError):
                    ai.fetch(("openai", ai.SOURCES["openai"]))
                self.assertEqual(fetch.call_count, 3)
                self.assertEqual(sleep.call_count, 2)

    def test_network_failure_does_not_publish_partial_source_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            ai.publish(fixtures(), tmp)
            before = {p.name: p.read_bytes() for p in Path(tmp).iterdir()}
            def fetch(item):
                name, _ = item
                if name == "openai":
                    raise urllib.error.URLError("simulated network failure")
                return name, fixtures()[name]
            with mock.patch.object(ai, "fetch", side_effect=fetch):
                with mock.patch("sys.argv", ["build_ai.py", "--output", tmp]):
                    with self.assertRaises(urllib.error.URLError):
                        ai.main()
            self.assertEqual(before, {p.name: p.read_bytes() for p in Path(tmp).iterdir()})

    def test_large_reduction_preserves_last_valid_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            more = fixtures()
            more["sukka_domains"] += "\n" + "\n".join("DOMAIN,extra-" + str(i) + ".example" for i in range(40))
            ai.publish(more, tmp)
            before = {p.name: p.read_bytes() for p in Path(tmp).iterdir()}
            with self.assertRaisesRegex(ValueError, "Large rule-count reduction"):
                ai.publish(fixtures(), tmp)
            self.assertEqual(before, {p.name: p.read_bytes() for p in Path(tmp).iterdir()})


if __name__ == "__main__":
    unittest.main()
