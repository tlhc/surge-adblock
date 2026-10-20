#!/usr/bin/env python3
"""
Surge DOMAIN-SET merge.

Merge domain sources, preserve exact matches, exclude protected services,
then suffix-fold -> out/block.list.

Also writes out/dns-block-ruleset.list (encrypted DNS and HTTPDNS endpoints).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
SOURCES = ROOT / "sources"
OUT = ROOT / "out"
SGT = dt.timezone(dt.timedelta(hours=8), name="SGT")

# ---------------------------------------------------------------------------
# Upstream catalog
# ---------------------------------------------------------------------------
SOURCES_META = {
    "anti_ad": {
        "url": "https://anti-ad.net/surge2.txt",
        "file": "anti_ad_surge2.txt",
        "kind": "domainset",
        "label": "anti-AD surge2",
    },
    "advertising_lite": {
        "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/AdvertisingLite/AdvertisingLite_Domain.list",
        "file": "bm7_advertising_lite_domain.list",
        "kind": "domainset",
        "label": "BM7 AdvertisingLite_Domain",
    },
    "hagezi_normal": {
        # try primary then fallbacks
        "urls": [
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/wildcard/multi-onlydomains.txt",
        ],
        "file": "hagezi_normal_onlydomains.txt",
        "kind": "plain_hosts",  # bare host, no leading dot; NO *.wildcard
        "label": "HaGeZi Normal onlydomains",
    },
    "hagezi_popupads": {
        "urls": [
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/wildcard/popupads-onlydomains.txt",
        ],
        "file": "hagezi_popupads_onlydomains.txt",
        "kind": "plain_hosts",
        "label": "HaGeZi Pop-Up Ads",
    },
    "tracking_protection": {
        "url": "https://cdn.jsdelivr.net/gh/geekdada/surge-list/domain-set/tracking-protection-filter.txt",
        "file": "geekdada_tracking_protection_filter.txt",
        "kind": "domainset",
        "label": "geekdada Tracking Protection",
    },
    "onehosts_lite": {
        "url": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
        "file": "onehosts_lite_adblock.txt",
        "kind": "adblock",
        "label": "1Hosts Lite",
    },
    "doh_domains": {
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-onlydomains.txt",
        "file": "hagezi_doh_domains.txt",
        "kind": "plain_hosts",
        "label": "HaGeZi encrypted DNS domains",
    },
    "doh_ipv4": {
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/ips/doh.txt",
        "file": "hagezi_doh_ipv4.txt",
        "kind": "ipv4",
        "label": "HaGeZi DoH IPv4",
    },
    "httpdns": {
        "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BlockHttpDNS/BlockHttpDNS.list",
        "file": "bm7_httpdns.list",
        "kind": "httpdns",
        "label": "BM7 BlockHttpDNS",
    },
}

UA = "surge-adblock-merge/1.0 (+https://local; merge+dedupe)"

def _ssl_ctx() -> ssl.SSLContext:
    return ssl.create_default_context()


def download(url: str, dest: Path, timeout: int = 90) -> Tuple[bool, int, str]:
    """Download URL → dest. Returns (ok, http_code_or_0, note). HTTP 200 only kept."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            raw = resp.read()
            if code != 200:
                return False, int(code), f"HTTP {code}"
            dest.write_bytes(raw)
            return True, 200, f"{len(raw)} bytes"
    except urllib.error.HTTPError as e:
        return False, int(e.code), f"HTTPError {e.code}"
    except Exception as e:  # noqa: BLE001
        return False, 0, f"{type(e).__name__}: {e}"


def SourceIsValid(path: Path, kind: str) -> bool:
    try:
        if kind in ("ipv4", "httpdns"):
            return bool(ParseDnsRules(path, kind))
        return bool(parse_hosts(path, kind))
    except (OSError, ValueError):
        return False


def fetch_all() -> Dict[str, dict]:
    SOURCES.mkdir(parents=True, exist_ok=True)
    status: Dict[str, dict] = {}
    for key, meta in SOURCES_META.items():
        dest = SOURCES / meta["file"]
        urls = meta.get("urls") or [meta["url"]]
        ok = False
        last_note = ""
        last_code = 0
        used = ""
        for u in urls:
            with tempfile.TemporaryDirectory(prefix=".fetch-", dir=SOURCES) as directory:
                candidatePath = Path(directory) / meta["file"]
                ok, last_code, last_note = download(u, candidatePath)
                if ok and not SourceIsValid(candidatePath, meta["kind"]):
                    ok, last_note = False, "no valid rules"
                if ok:
                    try:
                        candidatePath.replace(dest)
                    except OSError as error:
                        ok, last_note = False, str(error)
            used = u
            print(f"  [{'OK' if ok else 'SKIP'}] {key}: HTTP {last_code} — {last_note} ← {u}")
            if ok:
                break
        if not ok and SourceIsValid(dest, meta["kind"]):
            ok = True
            last_note = f"using previous source after update failure: {last_note}"
            print(f"  [CACHED] {key}: {last_note}")
        status[key] = {
            "ok": ok,
            "code": last_code,
            "note": last_note,
            "url": used,
            "path": dest if ok else None,
            "label": meta["label"],
            "kind": meta["kind"],
        }
    return status


# ---------------------------------------------------------------------------
# Normalization: lowercase, leading dot for suffix rules
# ---------------------------------------------------------------------------
COMMENT_RE = re.compile(r"^\s*(#|!|//)")
# DOMAIN-SUFFIX,host  / DOMAIN,host  / DOMAIN-KEYWORD,... / URL-REGEX,... / IP-CIDR,...
RULE_RE = re.compile(
    r"^(?P<typ>DOMAIN(?:-SUFFIX|-KEYWORD|-SET)?|URL-REGEX|IP-CIDR6?|USER-AGENT|PROCESS-NAME)"
    r"\s*,\s*(?P<body>[^,;#\s]+)",
    re.IGNORECASE,
)
# AdGuard / ABP style: ||host^  (optionally with $modifiers — we only take host)
ADG_RE = re.compile(r"^\|\|([a-z0-9._-]+)\^", re.IGNORECASE)
# bare host or .host or *.host
HOST_RE = re.compile(r"^(?:\*\.)?\.?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\.?$", re.IGNORECASE)

SKIP_TYPES = {
    "DOMAIN-KEYWORD",
    "URL-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "USER-AGENT",
    "PROCESS-NAME",
}


def is_valid_host(h: str) -> bool:
    if not h or len(h) > 253:
        return False
    if "." not in h:  # require at least one dot (TLD-looking); drop bare keywords
        return False
    if h.startswith(".") or h.endswith("."):
        return False
    if "*" in h or "/" in h or " " in h:
        return False
    # reject IPv4-ish
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h):
        return False
    labels = h.split(".")
    if any(not lab or len(lab) > 63 for lab in labels):
        return False
    return True


def line_to_host(line: str, kind: str) -> Optional[str]:
    """Extract a DOMAIN-SET entry while preserving its matching scope."""
    s = line.strip()
    if not s or COMMENT_RE.match(s):
        return None
    # strip inline comments for some lists
    if "#" in s and not s.startswith("||"):
        # keep DOMAIN-*,host #comment
        if not re.match(r"^(DOMAIN|IP-|URL-|USER-|PROCESS)", s, re.I):
            s = s.split("#", 1)[0].strip()
            if not s:
                return None

    # AdGuard ||host^
    m = ADG_RE.match(s)
    if m:
        h = m.group(1).lower().rstrip(".")
        return f".{h}" if is_valid_host(h) else None

    # Surge/Clash typed rule
    m = RULE_RE.match(s)
    if m:
        typ = m.group("typ").upper()
        body = m.group("body").strip()
        if typ in SKIP_TYPES or typ == "DOMAIN-SET":
            return None
        if typ in ("DOMAIN-SUFFIX", "DOMAIN"):
            h = body.lower().rstrip(".")
            if h.startswith("*."):
                h = h[2:]
            h = h.lstrip(".")
            prefix = "." if typ == "DOMAIN-SUFFIX" else ""
            return prefix + h if is_valid_host(h) else None
        return None

    # HaGeZi onlydomains: reject wildcard *.host explicitly
    if kind == "plain_hosts":
        if s.startswith("*.") or s.startswith("*"):
            return None
        h = s.lower().lstrip(".").rstrip(".")
        return f".{h}" if is_valid_host(h) else None

    hm = HOST_RE.match(s)
    if hm:
        h = hm.group(1).lower().rstrip(".")
        prefix = "." if s.startswith((".", "*.")) else ""
        return prefix + h if is_valid_host(h) else None
    return None


def parse_hosts(path: Path, kind: str) -> Set[str]:
    hosts: Set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            h = line_to_host(line, kind)
            if h:
                hosts.add(h)
    return hosts


def ParseDnsRules(path: Path, kind: str) -> List[str]:
    rules = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or COMMENT_RE.match(line):
            continue
        if kind == "ipv4":
            rules.add(f"IP-CIDR,{ipaddress.IPv4Address(line)}/32,no-resolve")
            continue
        fields = line.split(",")
        if len(fields) < 2:
            raise ValueError(f"Invalid DNS rule: {line}")
        ruleType, value = fields[:2]
        if ruleType in ("DOMAIN", "DOMAIN-SUFFIX") and len(fields) == 2:
            if not HOST_RE.fullmatch(value) or not is_valid_host(value):
                raise ValueError(f"Invalid DNS domain: {value}")
            rules.add(f"{ruleType},{value.lower()}")
        elif ruleType in ("IP-CIDR", "IP-CIDR6") and fields[2:] in ([], ["no-resolve"]):
            network = ipaddress.ip_network(value)
            if network.version != (4 if ruleType == "IP-CIDR" else 6):
                raise ValueError(f"Invalid IP family: {line}")
            rules.add(f"{ruleType},{network},no-resolve")
        else:
            raise ValueError(f"Unsupported DNS rule: {line}")
    return sorted(rules)


# ---------------------------------------------------------------------------
# Suffix folding: if example.com present, drop ads.example.com
# ---------------------------------------------------------------------------
def fold_suffixes(hosts: Iterable[str]) -> Set[str]:
    """Remove entries covered by a suffix rule; exact parents cover no children."""
    entries = set(hosts)
    kept_set: Set[str] = set()
    for h in entries:
        parts = h.lstrip(".").split(".")
        for i in range(len(parts) - 1):
            parent = "." + ".".join(parts[i:])
            if parent != h and parent in entries:
                break
        else:
            kept_set.add(h)
    return kept_set


# Bare 2-label names whose only label is a generic ad/tracker word.
# A leading-dot DOMAIN-SET line would block every subdomain of that name.
# Exact members only — do not drop longer hosts that merely contain these words.
# Applied after suffix fold, so folded children of a dropped root are not re-added.
SHORT_ROOT_DENY = frozenset(
    {
        "ad.com",
        "ad.global",
        "ad.gt",
        "ad.guru",
        "ad.net",
        "ad.page",
        "ad.plus",
        "ad.style",
        "ad.vu",
        "ads.bid",
        "ads.cc",
        "ads.com",
        "analytics.blue",
        "analytics.com",
        "analytics.vg",
        "metrics.io",
        "metrics.li",
        "stat.media",
        "stat.ovh",
        "stat.pl",
        "stat.re",
        "stat.social",
        "stats.de",
        "stats.fr",
        "stats.lt",
        "stats.rip",
        "stats.st",
    }
)


def drop_short_roots(hosts: Set[str]) -> Tuple[Set[str], Set[str]]:
    """Return (kept, removed) for hosts listed in SHORT_ROOT_DENY."""
    removed = {h for h in hosts if h.lstrip(".") in SHORT_ROOT_DENY}
    return hosts - removed, removed


def to_domainset_lines(hosts: Set[str]) -> List[str]:
    return sorted(hosts)


PROTECTED_HOSTS = frozenset({"safebrowsing.googleapis.com", "safebrowsing.urlsec.qq.com"})


def write_list(path: Path, lines: List[str], header: List[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for h in header:
            f.write(h + "\n")
        for line in lines:
            f.write(line + "\n")
    return len(lines)


# ---------------------------------------------------------------------------
# Block set: exclude protected services, suffix-fold, then write out/block.list.
# ---------------------------------------------------------------------------
BLOCK_SOURCES = (
    "anti_ad",
    "advertising_lite",
    "hagezi_normal",
    "hagezi_popupads",
    "tracking_protection",
    "onehosts_lite",
)


def main() -> int:
    print("== fetch sources ==")
    status = fetch_all()

    loaded: Dict[str, Set[str]] = {}
    raw_counts: Dict[str, int] = {}
    for key, st in status.items():
        if not st["ok"] or st["kind"] in ("ipv4", "httpdns"):
            continue
        assert st["path"] is not None
        hosts = parse_hosts(st["path"], st["kind"])
        loaded[key] = hosts
        raw_counts[key] = len(hosts)
        print(f"  parsed {key}: {len(hosts)} hosts")

    failed_fatal = [
        key for key in SOURCES_META if not status.get(key, {}).get("ok")
    ]
    if failed_fatal:
        for key in failed_fatal:
            st = status.get(key, {})
            print(
                f"FATAL: source '{key}' has no valid download or cached file "
                f"(HTTP {st.get('code', 0)} — {st.get('note', 'missing status')})",
                file=sys.stderr,
            )
        return 1

    rec: Set[str] = set()
    for key in BLOCK_SOURCES:
        rec |= loaded[key]
    rec = {
        h for h in rec
        if not any(
            h.lstrip(".") == protected
            or h.lstrip(".").endswith("." + protected)
            or (h.startswith(".") and protected.endswith(h))
            for protected in PROTECTED_HOSTS
        )
    }
    rec_folded = fold_suffixes(rec)
    rec_folded, short_roots_removed = drop_short_roots(rec_folded)

    now = dt.datetime.now(SGT)
    ts = now.strftime("%Y-%m-%d %H:%M:%S UTC+8")

    OUT.mkdir(parents=True, exist_ok=True)

    header_common = [
        "# Surge DOMAIN-SET",
        f"# Generated: {ts}",
        "# Bare host: exact match; leading dot: host and subdomains",
    ]

    rec_lines = to_domainset_lines(rec_folded)

    n_rec = write_list(
        OUT / "block.list",
        rec_lines,
        header_common
        + [
            f"# Hosts: {len(rec_lines)}",
            "# Contents: " + " + ".join(SOURCES_META[key]["label"] for key in BLOCK_SOURCES),
            "# Excludes Google/Tencent Safe Browsing service domains",
        ],
    )
    for stale in (
        "lite.list",
        "aggressive.list",
        "merged-lite.list",
        "merged-aggressive.list",
        "recommended.list",
        "allowlist-surge.list",
        "patch-ruleset.list",
    ):
        sp = OUT / stale
        if sp.exists():
            sp.unlink()

    dnsRules = {f"DOMAIN-SUFFIX,{host.lstrip('.')}" for host in loaded["doh_domains"]}
    for key in ("doh_ipv4", "httpdns"):
        rules = ParseDnsRules(status[key]["path"], status[key]["kind"])
        raw_counts[key] = len(rules)
        dnsRules.update(rules)
    # DOMAIN-SUFFIX,host already covers DOMAIN,host
    dnsRules = {rule for rule in dnsRules
                if not (rule.startswith("DOMAIN,") and f"DOMAIN-SUFFIX,{rule[7:]}" in dnsRules)}
    dnsCount = write_list(OUT / "dns-block-ruleset.list", sorted(dnsRules), [
        "# Surge RULE-SET: encrypted DNS and HTTPDNS endpoints",
        f"# Generated: {ts}",
        "# Sources: HaGeZi encrypted DNS domains + DoH IPv4 + BM7 BlockHttpDNS",
        "# Use without pre-matching; route Surge-generated DNS before this rule",
    ])

    stats_rows = [(SOURCES_META[key]["label"], raw_counts.get(key, 0)) for key in BLOCK_SOURCES]
    stats = "# Merge result\n\n| Source | Parsed hosts |\n|--------|-------------:|\n"
    for name, count in stats_rows:
        stats += f"| {name} | {count} |\n"
    stats += f"\n`out/block.list`: {n_rec}\n"
    stats += "\n| DNS source | Parsed rules |\n|------------|-------------:|\n"
    for key in ("doh_domains", "doh_ipv4", "httpdns"):
        stats += f"| {SOURCES_META[key]['label']} | {raw_counts[key]} |\n"
    stats += f"\n`out/dns-block-ruleset.list`: {dnsCount} (deduplicated)\n"
    (OUT / "STATS.md").write_text(stats, encoding="utf-8")

    print("\n== outputs ==")
    print(f"  block: {n_rec}")
    print(f"  short-root filter removed: {len(short_roots_removed)}")
    if short_roots_removed:
        print("  " + ", ".join(sorted(short_roots_removed)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
