#!/usr/bin/env python3
"""
Surge DOMAIN-SET merge+dedupe pipeline (Pareto: low-FP + coverage).

Tiers (locked room consensus):
  recommended = OISD ∪ (anti-AD − OISD) ∪ AWAvenue ∪ (Privacy − cur) ∪ (HaGeZi − OISD)
  lite        = OISD ∪ AWAvenue ∪ (anti-AD − OISD)   # anti-AD optional-but-included if size ok
  aggressive  = recommended ∪ (BM7 Advertising_Domain − recommended)

Outputs leading-dot DOMAIN-SET (.host), with parent-suffix folding.
"""

from __future__ import annotations

import datetime as dt
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
SOURCES = ROOT / "sources"
OUT = ROOT / "out"
ALLOWLIST_FILE = ROOT / "allowlist.txt"
ALLOWLIST_OPTIONAL_FILE = ROOT / "allowlist-optional.txt"
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
    "bm7_adv_domain": {
        "url": "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Advertising/Advertising_Domain.list",
        "file": "bm7_advertising_domain.list",
        "kind": "domainset",
        "label": "BM7 Advertising_Domain",
    },
    # companion / stats only — never into DOMAIN-SET merge
    "banad": {
        "url": "https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/BanAD.list",
        "file": "acl4ssr_banad.list",
        "kind": "ruleset",
        "label": "ACL4SSR BanAD (stats/companion)",
    },
    "bm7_advlite_rules": {
        "url": "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/AdvertisingLite/AdvertisingLite.list",
        "file": "bm7_advertisinglite.list",
        "kind": "ruleset",
        "label": "BM7 AdvertisingLite RULE-SET (companion ref)",
    },
}

UA = "surge-adblock-merge/1.0 (+https://local; merge+dedupe)"

# These feeds are required for a valid default block list. Only the feeds in
# SOFT_SKIP_SOURCES may be unavailable without failing the merge.
REQUIRED_FETCH_SOURCES = ("oisd_small", "anti_ad", "hagezi_light")
SOFT_SKIP_SOURCES = ("awavenue", "privacy", "banad")
FATAL_FETCH_SOURCES = tuple(
    key for key in SOURCES_META if key not in SOFT_SKIP_SOURCES
)


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
            ok, last_code, last_note = download(u, dest)
            used = u
            print(f"  [{'OK' if ok else 'SKIP'}] {key}: HTTP {last_code} — {last_note} ← {u}")
            if ok:
                break
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
# Normalization → host keys (lowercase, no leading . or *.)
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
    """Extract a single host key from a source line, or None to skip."""
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
        return h if is_valid_host(h) else None

    # Surge/Clash typed rule
    m = RULE_RE.match(s)
    if m:
        typ = m.group("typ").upper()
        body = m.group("body").strip()
        if typ in SKIP_TYPES:
            return None
        if typ in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-SET"):
            h = body.lower().lstrip(".").lstrip("*.").rstrip(".")
            return h if is_valid_host(h) else None
        return None

    # HaGeZi onlydomains: reject wildcard *.host explicitly
    if kind == "plain_hosts":
        if s.startswith("*.") or s.startswith("*"):
            return None
        h = s.lower().lstrip(".").rstrip(".")
        return h if is_valid_host(h) else None

    # DOMAIN-SET style: .host or bare host
    if s.startswith("*.") or (s.startswith("*") and not s.startswith("*.") is False and "*" in s[:2]):
        # *.host → host (treat as suffix); still valid for domain-set sources
        if s.startswith("*."):
            h = s[2:].lower().rstrip(".")
            return h if is_valid_host(h) else None
        return None

    hm = HOST_RE.match(s)
    if hm:
        h = hm.group(1).lower()
        return h if is_valid_host(h) else None
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
    """Keep only hosts that are not a strict subdomain of another host in the set."""
    sorted_hosts = sorted(set(hosts), key=lambda h: (h.count("."), len(h), h))
    kept: List[str] = []
    # index by reversed labels for parent checks — use simple endswith for clarity/correctness
    kept_set: Set[str] = set()
    for h in sorted_hosts:
        # check if any already-kept parent is a suffix of h
        parts = h.split(".")
        is_child = False
        # potential parents: h's suffixes of length >= 2 labels
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in kept_set:
                is_child = True
                break
        if not is_child:
            kept.append(h)
            kept_set.add(h)
    return kept_set


def to_domainset_lines(hosts: Set[str]) -> List[str]:
    return [f".{h}" for h in sorted(hosts)]


def write_list(path: Path, lines: List[str], header: List[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for h in header:
            f.write(h + "\n")
        for line in lines:
            f.write(line + "\n")
    return len(lines)


# ---------------------------------------------------------------------------
# Allowlist (false-positive avoidance) — LOCKED design
# ---------------------------------------------------------------------------
# allowlist.txt          → FORCED subtract from all DOMAIN-SET tiers
# allowlist-optional.txt → documented only; NOT subtracted by default
# Semantics:
#   bare host  → exact match only
#   .host      → suffix allow: host itself + any subdomain
# Exports out/allowlist-surge.list (leading-dot) for DIRECT-before-REJECT.


def _parse_allowlist_line(line: str) -> tuple[Optional[str], bool]:
    """Return (host_key, is_suffix) or (None, False) to skip."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None, False
    # strip inline comments (# …) but keep host
    if "#" in s:
        s = s.split("#", 1)[0].strip()
        if not s:
            return None, False
    s = s.lower().rstrip(".")
    if not s:
        return None, False
    if s.startswith("."):
        root = s.lstrip(".")
        if is_valid_host(root):
            return root, True
        return None, False
    if is_valid_host(s):
        return s, False
    return None, False


def load_allowlist_forced() -> Tuple[Set[str], Set[str], int]:
    """Load allowlist.txt. Returns (exact, suffixes, raw_entry_count)."""
    exact: Set[str] = set()
    suffixes: Set[str] = set()
    raw_n = 0
    if not ALLOWLIST_FILE.is_file():
        return exact, suffixes, 0
    with ALLOWLIST_FILE.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            host, is_suf = _parse_allowlist_line(line)
            if host is None:
                continue
            raw_n += 1
            if is_suf:
                suffixes.add(host)
            else:
                exact.add(host)
    return exact, suffixes, raw_n


def load_allowlist_optional_hosts() -> List[str]:
    """Parse optional file for docs/stats listing only (not applied)."""
    out: List[str] = []
    if not ALLOWLIST_OPTIONAL_FILE.is_file():
        return out
    with ALLOWLIST_OPTIONAL_FILE.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            host, is_suf = _parse_allowlist_line(line)
            if host is None:
                continue
            out.append(("." if is_suf else "") + host)
    return out


def is_allowlisted(host: str, exact: Set[str], suffixes: Set[str]) -> bool:
    if host in exact:
        return True
    for suf in suffixes:
        if host == suf or host.endswith("." + suf):
            return True
    return False


def apply_allowlist(
    hosts: Set[str], exact: Set[str], suffixes: Set[str]
) -> Tuple[Set[str], Set[str]]:
    kept: Set[str] = set()
    removed: Set[str] = set()
    for h in hosts:
        if is_allowlisted(h, exact, suffixes):
            removed.add(h)
        else:
            kept.add(h)
    return kept, removed


def allowlist_to_domainset_lines(exact: Set[str], suffixes: Set[str]) -> List[str]:
    """Export only true suffix entries for the DIRECT companion DOMAIN-SET.

    Exact allowlist hosts are intentionally omitted: a leading dot would widen
    an exact host into a suffix match. Exact hosts are still removed during the
    merge itself; use an explicit exact Surge DOMAIN rule if DIRECT is needed.
    """
    del exact  # exact-only entries are merge-time subtraction, not DOMAIN-SET lines
    return [f".{h}" for h in sorted(suffixes)]


# ---------------------------------------------------------------------------
# Tier assembly
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
        key for key in FATAL_FETCH_SOURCES if not status.get(key, {}).get("ok")
    ]
    if failed_fatal:
        for key in failed_fatal:
            st = status.get(key, {})
            kind = "required source" if key in REQUIRED_FETCH_SOURCES else "non-optional source"
            print(
                f"FATAL: {kind} '{key}' failed fetch "
                f"(HTTP {st.get('code', 0)} — {st.get('note', 'missing status')})",
                file=sys.stderr,
            )
        return 1

    for key in SOFT_SKIP_SOURCES:
        st = status.get(key, {})
        if not st.get("ok"):
            print(
                f"WARNING: optional source '{key}' unavailable; continuing "
                f"without it (HTTP {st.get('code', 0)} — {st.get('note', 'missing status')})",
                file=sys.stderr,
            )

    print("== allowlist (forced) ==")
    al_exact, al_suffixes, al_raw_n = load_allowlist_forced()
    al_optional = load_allowlist_optional_hosts()
    if al_raw_n == 0:
        print("  (none — allowlist.txt missing or empty)")
    else:
        print(f"  allowlist.txt entries={al_raw_n} exact={len(al_exact)} suffix={len(al_suffixes)}")
    print(f"  allowlist-optional.txt listed={len(al_optional)} (NOT subtracted)")

    oisd = set(loaded["oisd_small"])
    anti = set(loaded.get("anti_ad", set()))
    awa = set(loaded.get("awavenue", set()))
    priv = set(loaded.get("privacy", set()))
    hage = set(loaded.get("hagezi_light", set()))
    adv = set(loaded.get("bm7_adv_domain", set()))

    # ---- contribution tracking (order matters for "unique vs current") ----
    contrib: Dict[str, dict] = {}

    # recommended build order
    rec: Set[str] = set(oisd)
    contrib["oisd_small"] = {
        "raw": len(oisd),
        "added_to_recommended": len(oisd),
        "note": "base",
    }

    anti_diff = unique_adds(anti, rec)
    contrib["anti_ad"] = {
        "raw": len(anti),
        "overlap_with_prior": len(anti & rec),
        "added_to_recommended": len(anti_diff),
        "note": "anti-AD − OISD(+prior)",
    }
    rec |= anti_diff

    awa_diff = unique_adds(awa, rec)
    # locked: ∪ AWAvenue (all) — but after dedupe against current, unique adds matter for stats
    contrib["awavenue"] = {
        "raw": len(awa),
        "overlap_with_prior": len(awa & (rec - awa_diff)),
        "added_to_recommended": len(awa_diff),
        "note": "AWAvenue all (unique vs current)",
    }
    rec |= awa  # all of AWAvenue (union); equivalent to |= awa_diff

    priv_diff = unique_adds(priv, rec)
    contrib["privacy"] = {
        "raw": len(priv),
        "overlap_with_prior": len(priv & rec),
        "added_to_recommended": len(priv_diff),
        "note": "Privacy_Domain − current",
    }
    rec |= priv_diff

    # HaGeZi: unique vs OISD specifically per locked spec "(HaGeZi − OISD)"
    # then also skip anything already in rec from other sources
    hage_vs_oisd = unique_adds(hage, oisd)
    hage_diff = unique_adds(hage_vs_oisd, rec)
    contrib["hagezi_light"] = {
        "raw": len(hage),
        "minus_oisd": len(hage_vs_oisd),
        "overlap_with_prior_rec": len(hage & rec),
        "added_to_recommended": len(hage_diff),
        "note": "HaGeZi light onlydomains − OISD (− already in rec)",
        "fetched": "hagezi_light" in loaded,
    }
    rec |= hage_diff

    # fold recommended
    rec_before_fold = len(rec)
    rec_folded = fold_suffixes(rec)
    rec_after_fold_n = len(rec_folded)
    rec_folded, rec_al_removed = apply_allowlist(rec_folded, al_exact, al_suffixes)
    rec_folded_n = len(rec_folded)

    # ---- lite: OISD ∪ AWAvenue ∪ (anti-AD − OISD) ----
    lite: Set[str] = set(oisd) | awa | unique_adds(anti, oisd)
    lite_before_fold = len(lite)
    lite_folded = fold_suffixes(lite)
    lite_folded, lite_al_removed = apply_allowlist(lite_folded, al_exact, al_suffixes)
    contrib_lite = {
        "oisd_small": len(oisd),
        "awavenue_unique_vs_oisd": len(unique_adds(awa, oisd)),
        "anti_ad_unique_vs_oisd": len(unique_adds(anti, oisd)),
        "before_fold": lite_before_fold,
        "after_fold": len(lite_folded),
    }

    # ---- aggressive: recommended ∪ (AdvDomain − recommended) ----
    # use pre-fold recommended set for unique-diff semantics, then fold final
    adv_diff = unique_adds(adv, rec)
    agg: Set[str] = set(rec) | adv_diff
    agg_before_fold = len(agg)
    agg_folded = fold_suffixes(agg)
    agg_folded, agg_al_removed = apply_allowlist(agg_folded, al_exact, al_suffixes)
    contrib["bm7_adv_domain"] = {
        "raw": len(adv),
        "overlap_with_recommended": len(adv & rec),
        "added_to_aggressive": len(adv_diff),
        "note": "Advertising_Domain − recommended (aggressive only; higher FP)",
    }

    # naive union for STATS (OISD + anti-AD, no fold)
    naive_union = len(oisd | anti)
    naive_sum = len(oisd) + len(anti)

    now = dt.datetime.now(SGT)
    ts = now.strftime("%Y-%m-%d %H:%M:%S SGT")

    OUT.mkdir(parents=True, exist_ok=True)

    header_common = [
        f"# Surge DOMAIN-SET — generated by merge.py",
        f"# Generated: {ts}",
        f"# Format: leading-dot host (.example.com) — DOMAIN-SET compatible",
        f"# NO DOMAIN-KEYWORD / URL-REGEX / IP-CIDR in this file",
    ]

    rec_lines = to_domainset_lines(rec_folded)
    lite_lines = to_domainset_lines(lite_folded)
    agg_lines = to_domainset_lines(agg_folded)

    n_rec = write_list(
        OUT / "block.list",
        rec_lines,
        header_common
        + [
            f"# Tier: block (default) — low FP, high efficiency, CN+global coverage",
            f"# Recipe: OISD ∪ (anti-AD−OISD) ∪ AWAvenue ∪ (Privacy−cur) ∪ (HaGeZi−OISD)",
            f"# Hosts: {len(rec_lines)} (before fold {rec_before_fold}, after fold {rec_after_fold_n}, allowlist −{len(rec_al_removed)})",
        ],
    )
    # User wants a single deliverable: out/block.list only (lite/aggressive not shipped)
    n_lite = len(lite_lines)
    n_agg = len(agg_lines)
    for stale in ("lite.list", "aggressive.list", "merged-lite.list", "merged-aggressive.list", "recommended.list"):
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
        f.write("# Companion RULE-SET patch (optional) — DOMAIN-SUFFIX only\n")
        f.write(f"# Generated: {ts}\n")
        f.write("# Source: ACL4SSR BanAD DOMAIN-SUFFIX lines (KEYWORD intentionally excluded)\n")
        f.write("# Do NOT mix into DOMAIN-SET. Use as separate RULE-SET if desired.\n")
        f.write("# Wide DOMAIN-KEYWORD (ad/ads/advert) omitted by design to limit FP.\n")
        if not patch_lines:
            f.write("# (empty — no DOMAIN-SUFFIX extracted, or BanAD fetch failed)\n")
        for line in patch_lines:
            f.write(line + "\n")

    # ---- companion allowlist DOMAIN-SET (DIRECT before REJECT) ----
    al_surge_lines = allowlist_to_domainset_lines(al_exact, al_suffixes)
    al_surge_path = OUT / "allowlist-surge.list"
    write_list(
        al_surge_path,
        al_surge_lines,
        [
            f"# Surge DOMAIN-SET allowlist (FP avoidance) — use DIRECT *before* REJECT DOMAIN-SET",
            f"# Generated: {ts}",
            f"# Source: allowlist.txt (forced). Optional file is NOT included.",
            f"# Only suffix entries (.host) are exported; exact hosts are merge-time subtraction only.",
            f"# Place this suffix DOMAIN-SET above the adblock DOMAIN-SET in rules.",
            f"# Hosts: {len(al_surge_lines)}",
        ],
    )

    # BanAD keyword count for stats only
    banad_kw = 0
    banad_suf = len(patch_lines)
    if banad_path and Path(banad_path).is_file():
        text = Path(banad_path).read_text(encoding="utf-8", errors="replace")
        banad_kw = sum(1 for ln in text.splitlines() if re.match(r"^\s*DOMAIN-KEYWORD\s*,", ln, re.I))

    # ---- STATS.md (Chinese) ----
    # top contributors by unique adds to recommended
    top = sorted(
        (
            (k, contrib[k].get("added_to_recommended", contrib[k].get("added_to_aggressive", 0)))
            for k in ("oisd_small", "anti_ad", "awavenue", "privacy", "hagezi_light")
        ),
        key=lambda x: -x[1],
    )

    def src_status_line(key: str) -> str:
        st = status.get(key, {})
        if st.get("ok"):
            return f"OK HTTP {st.get('code')} — {st.get('note')}"
        return f"SKIP HTTP {st.get('code')} — {st.get('note')}"


    def _al_sample(removed: Set[str], n: int = 12) -> str:
        if not removed:
            return "_（本档无命中）_"
        items = sorted(removed)[:n]
        more = len(removed) - len(items)
        body = ", ".join(f"`{h}`" for h in items)
        if more > 0:
            body += f" … (+{more})"
        return body

    stats = f"""# Surge 广告 DOMAIN-SET 合并统计

> 生成时间：**{ts}**
> 脚本：`merge.py`（可重复运行）  
> **默认交付：block** — 效率 + 少误报 + 覆盖（Pareto）

## 三档产物

| 档位 | 文件 | 主机数（折叠后） | 说明 |
|------|------|----------------:|------|
| **block（默认）** | `out/block.list` | **{n_rec}** | OISD 底 + anti-AD 差集 + AWAvenue + Privacy 差集 + HaGeZi 差集 |
| lite | `out/lite.list` | **{n_lite}** | OISD ∪ AWAvenue ∪ (anti-AD−OISD)，更小 |
| aggressive | `out/aggressive.list` | **{n_agg}** | recommended ∪ (BM7 Advertising_Domain 差集)，**误报更高** |

别名（兼容）：`out/merged-lite.list` → lite，`out/merged-aggressive.list` → aggressive。

配套（勿混入 DOMAIN-SET）：`out/patch-ruleset.list` — 仅 BanAD 的 **DOMAIN-SUFFIX**（{banad_suf} 条）；宽 KEYWORD 已排除。

## 上游拉取

| 源 | 状态 | 解析主机数 |
|----|------|----------:|
| OISD small | {src_status_line("oisd_small")} | {raw_counts.get("oisd_small", 0)} |
| anti-AD surge2 | {src_status_line("anti_ad")} | {raw_counts.get("anti_ad", 0)} |
| AWAvenue | {src_status_line("awavenue")} | {raw_counts.get("awavenue", 0)} |
| BM7 Privacy_Domain | {src_status_line("privacy")} | {raw_counts.get("privacy", 0)} |
| HaGeZi light onlydomains | {src_status_line("hagezi_light")} | {raw_counts.get("hagezi_light", 0)} |
| BM7 Advertising_Domain | {src_status_line("bm7_adv_domain")} | {raw_counts.get("bm7_adv_domain", 0)} |
| BanAD (companion) | {src_status_line("banad")} | KEYWORD={banad_kw}, SUFFIX={banad_suf} |

## recommended 各源「独特贡献」（按并入顺序）

| 源 | 原始主机 | 相对先前集合重叠 | **新加入 recommended** | 备注 |
|----|--------:|----------------:|----------------------:|------|
| OISD small | {contrib['oisd_small']['raw']} | — | **{contrib['oisd_small']['added_to_recommended']}** | 国际低误报底座 |
| anti-AD | {contrib['anti_ad']['raw']} | {contrib['anti_ad']['overlap_with_prior']} | **{contrib['anti_ad']['added_to_recommended']}** | CN 向差集 |
| AWAvenue | {contrib['awavenue']['raw']} | {contrib['awavenue']['overlap_with_prior']} | **{contrib['awavenue']['added_to_recommended']}** | 国产 App |
| Privacy_Domain | {contrib['privacy']['raw']} | {contrib['privacy']['overlap_with_prior']} | **{contrib['privacy']['added_to_recommended']}** | 追踪器差集 |
| HaGeZi light | {contrib['hagezi_light']['raw']} | {contrib['hagezi_light']['overlap_with_prior_rec']} | **{contrib['hagezi_light']['added_to_recommended']}** | −OISD 后再 −rec |
| BM7 AdvDomain | {contrib['bm7_adv_domain']['raw']} | overlap→rec {contrib['bm7_adv_domain']['overlap_with_recommended']} | aggressive +**{contrib['bm7_adv_domain']['added_to_aggressive']}** | 不进 recommended |

### 按独特增量排序（recommended）

"""
    for i, (k, n) in enumerate(top, 1):
        stats += f"{i}. **{SOURCES_META[k]['label']}** — +{n}\n"

    stats += f"""
## 去重 / 折叠

| 指标 | 数值 |
|------|-----:|
| OISD + anti-AD 朴素相加 | {naive_sum} |
| OISD ∪ anti-AD（集合并，未折叠） | {naive_union} |
| 相对朴素相加的去重率 | {(1 - naive_union / naive_sum) * 100:.2f}% |
| recommended 折叠前 | {rec_before_fold} |
| recommended 后缀折叠后 | {rec_after_fold_n} |
| 折叠去掉子域 | {rec_before_fold - rec_after_fold_n} |
| recommended allowlist 后再计 | {rec_folded_n} |
| recommended allowlist 移除 | {len(rec_al_removed)} |
| lite 折叠后 | {n_lite} |
| aggressive 折叠后 | {n_agg} |
| aggressive 相对 recommended 净增 | {n_agg - n_rec} |

后缀折叠规则：若集合中已有 `example.com`，则丢弃 `ads.example.com`（由父域 `.example.com` 覆盖）。

## Allowlist 误报剔除（forced）

| 档位 | 移除主机数 | 样例（最多 12） |
|------|----------:|----------------|
| recommended | **{len(rec_al_removed)}** | {_al_sample(rec_al_removed)} |
| lite | **{len(lite_al_removed)}** | {_al_sample(lite_al_removed)} |
| aggressive | **{len(agg_al_removed)}** | {_al_sample(agg_al_removed)} |

- 强制文件：`allowlist.txt` — 条目 {al_raw_n}（精确 {len(al_exact)} + 后缀根 {len(al_suffixes)}）
- 可选文件：`allowlist-optional.txt` — 列出 {len(al_optional)} 条，**默认不剔除**
- 伴生 DOMAIN-SET：`out/allowlist-surge.list`（{len(al_surge_lines)} 行，建议 DIRECT 置于 REJECT 之前）
- 语义：`host` = 精确；`.host` = 该域及子域。详见 `docs/FALSE_POSITIVES.md`。
- patch-ruleset **永不**含宽 DOMAIN-KEYWORD。

## 设计说明（为何不把 BM7 Advertising 塞进默认档）

- BM7 `Advertising_Domain` 体量大，与 anti-AD 重叠极高，剩余增量里误报/过杀风险更高。
- `AdvertisingLite` 的 RULE-SET 含大量 DOMAIN-KEYWORD / URL-REGEX，**不能**写入 DOMAIN-SET。
- BanAD 的 DOMAIN-KEYWORD（如 `ad`/`ads`）误伤面大，仅作统计；patch 只保留 DOMAIN-SUFFIX。

## Surge 用法

```ini
# 推荐（默认）
DOMAIN-SET,file:///path/to/recommended.list,REJECT-TINYGIF,86400
# 或托管后
DOMAIN-SET,https://example.com/recommended.list,REJECT-TINYGIF,86400

# 更小
DOMAIN-SET,file:///path/to/lite.list,REJECT-TINYGIF,86400

# 激进（自行承担误报）
DOMAIN-SET,file:///path/to/aggressive.list,REJECT-TINYGIF,86400

# 可选配套 RULE-SET（与 DOMAIN-SET 分开）
RULE-SET,file:///path/to/patch-ruleset.list,REJECT-TINYGIF,86400
```

重新生成：

```bash
cd /workspace/surge-adblock-merge && python3 merge.py
```
"""
    (OUT / "STATS.md").write_text(stats, encoding="utf-8")

    # summary print
    print("\n== outputs ==")
    print(f"  recommended: {n_rec}")
    print(f"  lite:        {n_lite}")
    print(f"  aggressive:  {n_agg}")
    print(f"  patch DOMAIN-SUFFIX: {banad_suf}")
    print(f"  allowlist removed: rec={len(rec_al_removed)} lite={len(lite_al_removed)} agg={len(agg_al_removed)}")
    print(f"  allowlist-surge.list: {len(al_surge_lines)}")
    print(f"  STATS.md written")
    print("\nTop unique contributors (recommended):")
    for k, n in top:
        print(f"  +{n:7d}  {SOURCES_META[k]['label']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
