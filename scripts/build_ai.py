#!/usr/bin/env python3
"""Build credential-free Surge AI rules; publish only after every source validates.

SPDX-License-Identifier: AGPL-3.0-or-later
"""
from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "sukka_domains": "https://ruleset.skk.moe/List/non_ip/ai.conf",
    "sukka_voice": "https://ruleset.skk.moe/List/ip/ai.conf",
    **{name: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/" + name + ".json"
       for name in ("openai", "anthropic", "google-gemini")},
}
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "URL-REGEX"}
SHARED_ROOTS = {
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "github.com", "cloudflare.com", "auth0.com", "livekit.cloud", "apple.com",
    "icloud.com", "amazonaws.com", "azure.com", "stripe.com", "sentry.io",
}
POSITIVE = [
    "chatgpt.com", "api.openai.com", "files.oaiusercontent.com", "oaistatsig.com",
    "chatgpt.livekit.cloud", "host.livekit.cloud", "turn.livekit.cloud",
    "claude.ai", "claude.com", "claude.app", "bridge.claudeusercontent.com",
    "sample.claudemcpcontent.com", "claudemcpclient.com", "gemini.google.com",
    "gemini.gstatic.com", "generativelanguage.googleapis.com",
    "geminiweb-pa.clients6.google.com", "aisandbox-pa.googleapis.com",
    "chatgpt-async-webps-prod-centralus-42.webpubsub.azure.com",
]
NEGATIVE = [
    "www.youtube.com", "rr1.googlevideo.com", "api.stripe.com", "www.paypal.com",
    "other.auth0.com", "other.livekit.cloud", "api.cloudflare.com",
    "storage.googleapis.com", "guzzoni.apple.com", "gspe1-ssl.ls.apple.com",
    "apps.mzstatic.com", "www.apple.com", "claude-fan.example", "example.com",
]
AZURE_REGEX = r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$"
AZURE_RULE = ("DOMAIN-WILDCARD", "chatgpt-async-webps-prod-*.webpubsub.azure.com")


def values(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def hostname(value):
    if not isinstance(value, str):
        raise ValueError("Non-string domain")
    value = value.lower().lstrip(".").rstrip(".")
    if not (0 < len(value) < 254 and "." in value and re.fullmatch(r"[a-z0-9_.-]+", value)):
        raise ValueError("Invalid domain: " + value)
    return value


def matches(host, rules):
    for kind, value in rules:
        if kind == "DOMAIN" and host == value:
            return True
        if kind == "DOMAIN-SUFFIX" and (host == value or host.endswith("." + value)):
            return True
        if kind == "DOMAIN-KEYWORD" and value in host:
            return True
        if kind == "DOMAIN-WILDCARD" and fnmatch.fnmatchcase(host, value):
            return True
    return False


def parse_sukka(text):
    rules = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kind, separator, value = line.partition(",")
        value = value.strip()
        if not separator or kind not in DOMAIN_TYPES or not value or "\n" in value or "," in value:
            raise ValueError("Unexpected Sukka domain rule: " + line[:160])
        if kind == "DOMAIN" and value.startswith("7h15."):
            continue  # upstream identification marker, not an AI dependency
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            value = hostname(value)
            if kind == "DOMAIN-SUFFIX" and value in SHARED_ROOTS:
                raise ValueError("Shared root added upstream: " + value)
        elif kind == "DOMAIN-KEYWORD":
            value = value.lower()
            if not re.fullmatch(r"[a-z0-9_.-]{5,253}", value):
                raise ValueError("Invalid or overly broad domain keyword")
        elif kind == "DOMAIN-WILDCARD":
            value = value.lower()
            if not re.fullmatch(r"[a-z0-9_.?*-]{3,253}", value) or "." not in value:
                raise ValueError("Invalid domain wildcard")
            if value.lstrip("*?.") in SHARED_ROOTS:
                raise ValueError("Shared wildcard root added upstream")
        elif kind == "URL-REGEX":
            try:
                re.compile(value)
            except re.error as error:
                raise ValueError("Invalid URL regex") from error
        rules.add((kind, value))
    if not 20 <= len(rules) <= 10000:
        raise ValueError("Unexpected Sukka domain count")
    return rules


def parse_provider(text):
    doc = json.loads(text)
    if doc.get("version") not in (1, 2, 3, 4) or not isinstance(doc.get("rules"), list):
        raise ValueError("Invalid provider document")
    result = set()
    for rule in doc["rules"]:
        if set(rule) - {"domain", "domain_suffix", "domain_regex"}:
            raise ValueError("New provider rule fields require review")
        for field, kind in [("domain", "DOMAIN"), ("domain_suffix", "DOMAIN-SUFFIX")]:
            for value in values(rule.get(field)):
                value = hostname(value)
                if value in SHARED_ROOTS:
                    raise ValueError("Shared provider root: " + value)
                result.add((kind, value))
        for pattern in values(rule.get("domain_regex")):
            if pattern != AZURE_REGEX:
                raise ValueError("Unreviewed provider regex: " + str(pattern))
            # Surge has no DOMAIN-REGEX. Bound this conversion to the dedicated
            # ChatGPT Azure prefix; it is slightly wider than the numeric regex.
            result.add(AZURE_RULE)
    if not 5 <= len(result) <= 20000:
        raise ValueError("Unexpected provider rule count")
    return result


def supplement_only(providers, base):
    result = set()
    for kind, value in providers:
        covered = (kind, value) in base
        if kind == "DOMAIN":
            covered = covered or matches(value, base)
        elif kind == "DOMAIN-SUFFIX":
            covered = covered or any(
                (k == "DOMAIN-SUFFIX" and (value == v or value.endswith("." + v)))
                or (k == "DOMAIN-KEYWORD" and v in value) for k, v in base
            )
        if not covered:
            result.add((kind, value))
    # Exact hosts and child suffixes need not duplicate a broader provider suffix.
    suffixes = {v for k, v in result if k == "DOMAIN-SUFFIX"}
    return {(k, v) for k, v in result if k not in {"DOMAIN", "DOMAIN-SUFFIX"}
            or not any(v.endswith("." + parent) or (k == "DOMAIN" and v == parent)
                       for parent in suffixes if parent != v or k == "DOMAIN")}


def parse_voice(text):
    networks = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("DOMAIN,7h15."):
            continue
        parts = [v.strip() for v in line.split(",")]
        if parts[0] == "IP-ASN" and len(parts) in (2, 3) and parts[1].isdigit():
            if len(parts) == 3 and parts[2] != "no-resolve":
                raise ValueError("Unexpected ASN option")
            continue  # the AI IP upstream also has ASN fallbacks; voice uses CIDRs only
        if len(parts) not in (2, 3) or parts[0] not in {"IP-CIDR", "IP-CIDR6"}:
            raise ValueError("Unexpected voice rule: " + line[:160])
        if len(parts) == 3 and parts[2] != "no-resolve":
            raise ValueError("Unexpected voice rule option")
        network = ipaddress.ip_network(parts[1], strict=True)
        if (network.version == 6) != (parts[0] == "IP-CIDR6"):
            raise ValueError("Voice address-family mismatch")
        if not network.is_global or network.prefixlen < (16 if network.version == 4 else 32):
            raise ValueError("Non-public or overly broad voice prefix")
        networks.add(network)
    if not 20 <= len(networks) <= 100000:
        raise ValueError("Unexpected voice IP count")
    return sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def render(title, rules, note=""):
    header = ["# " + title, "# Generated by scripts/build_ai.py; do not edit.",
              "# Sources, licenses and input SHA-256: AI-Sources.json"]
    if note:
        header.append("# " + note)
    return "\n".join(header + [k + "," + v for k, v in sorted(rules)]) + "\n"


def provider_samples(rules):
    samples = set()
    for kind, value in rules:
        if kind == "DOMAIN":
            samples.add(value)
        elif kind == "DOMAIN-SUFFIX":
            samples.update((value, "probe." + value))
        elif kind == "DOMAIN-WILDCARD":
            samples.add(value.replace("*", "sample-42").replace("?", "a"))
        else:
            raise ValueError("Unexpected converted provider rule: " + kind)
    return samples


def assemble(inputs):
    if set(inputs) != set(SOURCES):
        raise ValueError("A source is missing; retain previous published rules")
    base = parse_sukka(inputs["sukka_domains"])
    providers = set().union(*(parse_provider(inputs[name])
                            for name in ("openai", "anthropic", "google-gemini")))
    supplement = supplement_only(providers, base)
    combined = base | supplement
    all_provider_samples = provider_samples(providers)
    if any(not matches(host, combined) for host in all_provider_samples):
        raise ValueError("Upstream provider domain lost during conversion or deduplication")
    if any(not matches(host, combined) for host in POSITIVE):
        raise ValueError("Critical AI domain coverage regression")
    if any(matches(host, combined) for host in NEGATIVE):
        raise ValueError("Shared or unrelated domain routing regression")
    voice = parse_voice(inputs["sukka_voice"])
    files = {
        "AI-Sukka.list": render("Sukka AI domain rules", base,
                                "URL-REGEX requires existing HTTPS visibility; no MITM configuration is installed."),
        "AI-Supplement.list": render("OpenAI / Anthropic / Gemini supplements", supplement,
                                     "Azure WebPubSub regex becomes a dedicated-prefix wildcard (slightly wider)."),
        "AI-Voice-IP.list": render("ChatGPT Voice IPs", {
            ("IP-CIDR6" if n.version == 6 else "IP-CIDR", str(n) + ",no-resolve") for n in voice
        }, "Dedicated voice IPs; route UDP 3478 and TCP 443 fallback through the same exit."),
    }
    manifest = {
        "sources": {k: {"url": url, "sha256": hashlib.sha256(inputs[k].encode()).hexdigest()}
                    for k, url in SOURCES.items()},
        "counts": {"sukka": len(base), "supplement": len(supplement), "voice_ip": len(voice)},
        "checks": {"positive_domain_samples": len(POSITIVE), "negative_domain_samples": len(NEGATIVE),
                   "all_provider_domain_samples": len(all_provider_samples)},
        "conversion": {"azure_webpubsub": "Dedicated-prefix wildcard; broader than numeric regex"},
        "excluded_voice_rules": [line.strip() for line in inputs["sukka_voice"].splitlines()
                                 if line.strip().startswith("IP-ASN,")],
        "licenses": {"SukkaW/Surge": "AGPL-3.0", "MetaCubeX/meta-rules-dat": "GPL-3.0"},
        "files": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()},
    }
    files["AI-Sources.json"] = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return files, manifest


def publish(inputs, output):
    files, manifest = assemble(inputs)  # all validation precedes any file change
    output = Path(output)
    previous = output / "AI-Sources.json"
    if previous.exists():
        counts = json.loads(previous.read_text())["counts"]
        for key, count in manifest["counts"].items():
            if count < counts[key] * 0.7:
                raise ValueError("Large rule-count reduction requires review: " + key)
    output.mkdir(parents=True, exist_ok=True)
    staged = []
    try:
        for name, content in files.items():
            dest = output / name
            if dest.exists() and dest.read_text() == content:
                continue
            fd, tmp = tempfile.mkstemp(prefix=".ai-stage-", dir=output)
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.chmod(tmp, 0o644)
            staged.append((Path(tmp), dest))
        for tmp, dest in staged:
            os.replace(tmp, dest)
    finally:
        for tmp, _ in staged:
            tmp.unlink(missing_ok=True)
    # GitHub publishes the complete generated set in one commit, never on failure.
    return manifest


def fetch(item):
    name, url = item
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RuleSet-AI-Updater/1"})
            with urllib.request.urlopen(req, timeout=25) as response:
                data = response.read(2_000_001)
            if not 0 < len(data) <= 2_000_000:
                raise ValueError("Source size out of bounds: " + name)
            return name, data.decode("utf-8")
        except Exception:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("Unreachable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "Rules")
    args = parser.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
        inputs = dict(pool.map(fetch, SOURCES.items()))
    result = publish(inputs, args.output)
    print(json.dumps({"counts": result["counts"], "checks": result["checks"]}))


if __name__ == "__main__":
    main()
