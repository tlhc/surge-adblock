#!/usr/bin/env python3
"""
Surge DOMAIN-SET merge.

Merge domain sources, preserve exact matches, exclude protected services,
then suffix-fold -> out/block.list.

Also writes out/patch-ruleset.list (BanAD DOMAIN-SUFFIX only).
"""

from __future__ import annotations

import datetime as dt
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
    "oisd_small": {
        "url": "https://raw.githubusercontent.com/pikipig/surge-5-anti-ad/main/antiAD-set-small.txt",
        "file": "oisd_small.txt",
        "kind": "domainset",
        "label": "OISD small (pikipig)",
    },
    "anti_ad": {
        "url": "https://anti-ad.net/surge2.txt",
        "file": "anti_ad_surge2.txt",
        "kind": "domainset",
        "label": "anti-AD surge2",
    },
    "awavenue": {
        "url": "https://cdn.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Surge.list",
        "file": "awavenue_surge.list",
        "kind": "domainset",
        "label": "AWAvenue Ads Rule",
    },
    "privacy": {
        "url": "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Privacy/Privacy_Domain.list",
        "file": "bm7_privacy_domain.list",
        "kind": "domainset",
        "label": "BM7 Privacy_Domain",
    },
    "hagezi_light": {
        # try primary then fallbacks
        "urls": [
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/wildcard/light-onlydomains.txt",
        ],
        "file": "hagezi_light_onlydomains.txt",
        "kind": "plain_hosts",  # bare host, no leading dot; NO *.wildcard
        "label": "HaGeZi light onlydomains",
    },
    "dns_filter": {
        "url": "https://cdn.jsdelivr.net/gh/geekdada/surge-list/domain-set/dns-filter.txt",
        "file": "geekdada_dns_filter.txt",
        "kind": "domainset",
        "label": "geekdada DNS filter",
    },
    "tracking_protection": {
        "url": "https://cdn.jsdelivr.net/gh/geekdada/surge-list/domain-set/tracking-protection-filter.txt",
        "file": "geekdada_tracking_protection_filter.txt",
        "kind": "domainset",
        "label": "geekdada Tracking Protection",
    },
    # companion RULE-SET only — never into the DOMAIN-SET
    "banad": {
        "url": "https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/BanAD.list",
        "file": "acl4ssr_banad.list",
        "kind": "ruleset",
        "label": "ACL4SSR BanAD",
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
        if kind == "ruleset":
            return bool(parse_ruleset_domain_suffix(path))
        return bool(parse_hosts(path, kind))
    except OSError:
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


def parse_ruleset_domain_suffix(path: Path) -> List[str]:
    """Extract DOMAIN-SUFFIX lines only (curated companion patch)."""
    out: List[str] = []
    seen: Set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or COMMENT_RE.match(s):
                continue
            m = RULE_RE.match(s)
            if not m:
                continue
            typ = m.group("typ").upper()
            if typ != "DOMAIN-SUFFIX":
                continue
            body = m.group("body").strip().lower().lstrip(".")
            if not is_valid_host(body) or body in seen:
                continue
            seen.add(body)
            out.append(f"DOMAIN-SUFFIX,{body}")
    return out


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
def unique_adds(candidate: Set[str], existing: Set[str]) -> Set[str]:
    return candidate - existing


def main() -> int:
    print("== fetch sources ==")
    status = fetch_all()

    loaded: Dict[str, Set[str]] = {}
    raw_counts: Dict[str, int] = {}
    for key, st in status.items():
        if not st["ok"] or st["kind"] == "ruleset":
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

    oisd = set(loaded["oisd_small"])
    anti = set(loaded.get("anti_ad", set()))
    awa = set(loaded.get("awavenue", set()))
    priv = set(loaded.get("privacy", set()))
    hage = set(loaded.get("hagezi_light", set()))

    rec: Set[str] = set(oisd)
    rec |= unique_adds(anti, rec)
    rec |= awa
    rec |= unique_adds(priv, rec)
    rec |= unique_adds(unique_adds(hage, oisd), rec)
    rec |= loaded["dns_filter"]
    rec |= loaded["tracking_protection"]
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
            "# Contents: OISD + anti-AD + AWAvenue + BM7 Privacy + HaGeZi light + geekdada DNS filter + geekdada Tracking Protection",
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
    ):
        sp = OUT / stale
        if sp.exists():
            sp.unlink()

    # ---- companion RULE-SET patch: curated DOMAIN-SUFFIX only from BanAD ----
    # locked: NO wide KEYWORD/advert, NO URL-REGEX — DOMAIN-SUFFIX only (or empty + note)
    patch_path = OUT / "patch-ruleset.list"
    patch_lines: List[str] = []
    banad_path = status.get("banad", {}).get("path")
    if banad_path and Path(banad_path).is_file():
        patch_lines = parse_ruleset_domain_suffix(Path(banad_path))
    with patch_path.open("w", encoding="utf-8") as f:
        f.write("# RULE-SET, DOMAIN-SUFFIX only\n")
        f.write(f"# Generated: {ts}\n")
        f.write("# Source: ACL4SSR BanAD\n")
        f.write("# Subscribe separately from the DOMAIN-SET\n")
        if not patch_lines:
            f.write("# Empty\n")
        for line in patch_lines:
            f.write(line + "\n")

    stats_rows = [
        ("OISD small", raw_counts.get("oisd_small", 0)),
        ("anti-AD", raw_counts.get("anti_ad", 0)),
        ("AWAvenue", raw_counts.get("awavenue", 0)),
        ("BM7 Privacy", raw_counts.get("privacy", 0)),
        ("HaGeZi light", raw_counts.get("hagezi_light", 0)),
        ("geekdada DNS filter", raw_counts.get("dns_filter", 0)),
        ("geekdada Tracking Protection", raw_counts.get("tracking_protection", 0)),
    ]
    stats = "# Merge result\n\n| Source | Parsed hosts |\n|--------|-------------:|\n"
    for name, count in stats_rows:
        stats += f"| {name} | {count} |\n"
    stats += f"\n`out/block.list`: {n_rec}\n"
    (OUT / "STATS.md").write_text(stats, encoding="utf-8")

    print("\n== outputs ==")
    print(f"  block: {n_rec}")
    print(f"  short-root filter removed: {len(short_roots_removed)}")
    if short_roots_removed:
        print("  " + ", ".join(sorted(short_roots_removed)))
    print(f"  patch DOMAIN-SUFFIX: {len(patch_lines)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
