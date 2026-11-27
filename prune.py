#!/usr/bin/env python3
"""
Prune step for out/block.list.

merge.py calls apply() after suffix folding. apply() only reads two cached files:

  data/dead.txt  names that did not resolve (NXDOMAIN on two DoH resolvers)
  data/junk.txt  foreign-ccTLD / IDN / random-looking ad entries

`python3 prune.py refresh` rewrites both files at most once every REFRESH_DAYS
days. A failed or incomplete refresh leaves the cached files untouched, so
network trouble never prunes more.

dead.txt rows are tab separated: name, first NXDOMAIN date, optional alive-since date.
  .zone.tld   registered domain is NXDOMAIN: every suffix or exact entry under it is dead
  host.tld    exact host is NXDOMAIN: dead for an exact entry only (an NXDOMAIN apex of a
              suffix entry can still have resolvable children)
A row is dropped only after the name has resolved on every check for DEAD_RETURN_DAYS.
"""

from __future__ import annotations

import base64
import concurrent.futures
import datetime as dt
import http.client
import math
import os
import re
import sys
import threading
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
REFRESH_DAYS = 7
DEAD_RETURN_DAYS = 30
STALE_WARN_DAYS = 21

RESOLVERS = (("cloudflare-dns.com", "/dns-query"), ("dns.alidns.com", "/dns-query"))
SENTINEL_ALIVE = ("www.baidu.com", "www.cloudflare.com", "www.qq.com", "dns.google")
WORKERS = 48
QUERY_TIMEOUT = 8
STAGE_DEADLINE = 2400  # seconds per resolver stage
MAX_ERROR_RATE = 0.03
MAX_DEAD_RATE = 0.30

EASYPRIVACY_URL = "https://easylist.to/easylist/easyprivacy.txt"
TIF_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt"
MIN_EASYPRIVACY = 10000
MIN_TIF = 500000

# Entries that are never pruned: local pins and the named ad hosts that must stay blocked.
KEEP_RE = re.compile(
    r"pangolin|pglstatp|ctobsnssdk|wxsnsad|bilivideo|biliapi\.net|ahdohpiechei|szbdyd|mountaintoys"
)
# Tracker-named hosts are privacy entries; never pruned as junk.
TRACKER_RE = re.compile(
    r"analytic|metric|telemetr|track|stat\b|stats|pixel|beacon|collect|insight|sgtm|gtm|tagging|matomo|"
    r"piwik|umami|plausible|segment|sst\b|smetrics|measure|\blogs?\b|metrika|heatmap|rum\b|events?\b"
)
# Mainland China brand names and TLDs: never pruned as junk.
CN_RE = re.compile(
    r"qq|baidu|alibaba|aliyun|alicdn|taobao|tmall|xiaomi|miui|huawei|hicloud|oppo|heytap|vivo|"
    r"bytedance|snssdk|toutiao|douyin|kuaishou|weibo|sina|sohu|163|126\.net|netease|jd\.com|360|"
    r"iqiyi|youku|bilibili|zhihu|xiaohongshu|pinduoduo|meituan|umeng|getui|jpush|mob\.com|gdt|"
    r"sogou|cnzz|tencent|wechat|weixin|alipay|amap|autonavi|ximalaya|kugou|kuwo|miaozhen|admaster|"
    r"myqcloud|dbankcloud|hispace|71\.am"
)
CN_TLDS = frozenset({"cn", "hk", "tw", "mo"})
# Two-letter TLDs a CN/SG/EN reader can meet, including TLDs used as generic ones.
KEEP_TLDS = CN_TLDS | frozenset(
    "sg my jp kr us uk au ca nz ie in ph za id th vn co io tv me cc ai fm ly to ws sh gg gl ac la "
    "pw vc ms so im is ag bz mn nu fo st tk ml ga cf gq".split()
)


# ---------------------------------------------------------------------------
# Public suffix list (single-label rules omitted; unknown TLD is a suffix by default)
# ---------------------------------------------------------------------------
class PublicSuffixes:
    def __init__(self, path: Path = DATA / "public_suffix_list.dat"):
        self.rules: Set[str] = set()
        self.wild: Set[str] = set()
        self.exceptions: Set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                self.exceptions.add(line[1:])
            elif line.startswith("*."):
                self.wild.add(line[2:])
            else:
                self.rules.add(line)

    def suffix_labels(self, labels: List[str]) -> int:
        """Number of labels in the public suffix of labels."""
        n = len(labels)
        best = 1
        for i in range(n):
            name = ".".join(labels[i:])
            if name in self.exceptions:
                return n - i - 1
            if name in self.rules:
                best = max(best, n - i)
            elif i + 1 < n and ".".join(labels[i + 1:]) in self.wild:
                best = max(best, n - i)
        return best

    def registered(self, host: str) -> Optional[str]:
        """eTLD+1 of host, or None when host is itself a public suffix."""
        labels = host.split(".")
        k = self.suffix_labels(labels)
        return None if len(labels) <= k else ".".join(labels[-(k + 1):])


# ---------------------------------------------------------------------------
# Cached files
# ---------------------------------------------------------------------------
Dead = Dict[str, Tuple[str, str]]  # name -> (first NXDOMAIN date, alive-since date or "")


def read_header_date(path: Path) -> Optional[dt.date]:
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("# refreshed:"):
                return dt.date.fromisoformat(line.split(":", 1)[1].strip())
            if not line.startswith("#"):
                break
    except (OSError, ValueError):
        pass
    return None


def load_dead(path: Path) -> Dead:
    rows: Dead = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return rows
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) >= 2 and fields[0]:
            rows[fields[0]] = (fields[1], fields[2] if len(fields) > 2 else "")
    return rows


def write_dead(path: Path, rows: Dead, today: dt.date) -> None:
    lines = [
        "# Names that returned NXDOMAIN on Cloudflare and AliDNS DoH (see prune.py)",
        f"# refreshed: {today.isoformat()}",
        "# name<TAB>first NXDOMAIN date[<TAB>alive-since date]",
    ]
    lines += [f"{n}\t{a}\t{b}" if b else f"{n}\t{a}" for n, (a, b) in sorted(rows.items())]
    atomic_write(path, "\n".join(lines) + "\n")


def load_junk(path: Path) -> Set[str]:
    try:
        return {l for l in path.read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")}
    except OSError:
        return set()


def write_junk(path: Path, entries: Iterable[str], today: dt.date) -> None:
    lines = [
        "# Foreign-ccTLD, IDN or random-looking ad entries (see prune.py)",
        f"# refreshed: {today.isoformat()}",
    ] + sorted(entries)
    atomic_write(path, "\n".join(lines) + "\n")


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Applying the cached lists
# ---------------------------------------------------------------------------
def ancestors(host: str) -> List[str]:
    """host and its parents with at least two labels."""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def is_kept(entry: str, local: Iterable[str] = ()) -> bool:
    return entry in local or bool(KEEP_RE.search(entry))


def is_dead(entry: str, dead: Dead) -> bool:
    host = entry.lstrip(".")
    if any("." + a in dead for a in ancestors(host)):
        return True
    return not entry.startswith(".") and host in dead


def apply(entries: Set[str], data_dir: Path, local: Iterable[str] = ()) -> Tuple[Set[str], Dict[str, int]]:
    """Drop cached dead and junk entries; returns (kept, counts)."""
    local = set(local)
    dead = load_dead(data_dir / "dead.txt")
    junk = load_junk(data_dir / "junk.txt")
    kept: Set[str] = set()
    counts = {"dead": 0, "junk": 0}
    for entry in entries:
        if is_kept(entry, local):
            kept.add(entry)
        elif dead and is_dead(entry, dead):
            counts["dead"] += 1
        elif entry in junk:
            counts["junk"] += 1
        else:
            kept.add(entry)
    return kept, counts


# ---------------------------------------------------------------------------
# Junk classification (used by refresh only)
# ---------------------------------------------------------------------------
def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(v / len(text) * math.log2(v / len(text)) for v in counts.values())


def random_looking(host: str) -> bool:
    for label in host.split(".")[:-1]:
        if len(label) >= 16:
            digits = sum(ch.isdigit() for ch in label) / len(label)
            if digits > 0.25 or (entropy(label) > 3.6 and label.count("-") < 2):
                return True
        if re.fullmatch(r"[0-9a-f]{12,}", label):
            return True
    return False


def foreign(host: str) -> bool:
    tld = host.rsplit(".", 1)[-1]
    if tld.startswith("xn--") or not host.isascii():
        return True
    return len(tld) == 2 and tld not in KEEP_TLDS


def covered(host: str, guard: Set[str]) -> bool:
    return any(a in guard for a in ancestors(host))


def junk_candidates(
    entries: Iterable[str],
    privacy: Set[str],
    malware: Set[str],
    local: Iterable[str] = (),
) -> Set[str]:
    """Ad or unclassified entries on foreign ccTLD / IDN / random-looking names.

    privacy: hosts from tracking-protection lists (suffix semantics); malware: threat-intel hosts.
    Entries covered by either, tracker-named entries, CN-related entries and kept entries are not junk.
    """
    local = set(local)
    out: Set[str] = set()
    for entry in entries:
        host = entry.lstrip(".")
        if is_kept(entry, local) or not (foreign(host) or random_looking(host)):
            continue
        if host.rsplit(".", 1)[-1] in CN_TLDS or CN_RE.search(host):
            continue
        if TRACKER_RE.search(host) or covered(host, privacy) or covered(host, malware):
            continue
        out.add(entry)
    return out


# ---------------------------------------------------------------------------
# DoH
# ---------------------------------------------------------------------------
def build_query(name: str) -> bytes:
    labels = name.split(".")
    if not name.isascii() or len(name) > 253 or any(not 0 < len(l) <= 63 for l in labels):
        raise ValueError(name)
    qname = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    return b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"


def parse_response(data: bytes) -> str:
    """NX (NXDOMAIN), OK (NOERROR, answers or not), FAIL (SERVFAIL etc.) or ERR (not a DNS reply)."""
    if len(data) < 12 or not data[2] & 0x80:
        return "ERR"
    rcode = data[3] & 0x0F
    return "NX" if rcode == 3 else "OK" if rcode == 0 else "FAIL"


class Doh:
    def __init__(self, host: str, path: str, timeout: float = QUERY_TIMEOUT):
        self.host, self.path, self.timeout = host, path, timeout
        self.local = threading.local()

    def query(self, name: str) -> str:
        try:
            wire = base64.urlsafe_b64encode(build_query(name)).rstrip(b"=").decode()
        except ValueError:
            return "ERR"
        for attempt in range(4):
            delay = 0.5 * (attempt + 1)
            try:
                conn = getattr(self.local, "conn", None)
                if conn is None:
                    conn = self.local.conn = http.client.HTTPSConnection(self.host, timeout=self.timeout)
                conn.request("GET", f"{self.path}?dns={wire}", headers={"accept": "application/dns-message"})
                resp = conn.getresponse()
                body = resp.read()
                if resp.status == 200:
                    return parse_response(body)
                if resp.status == 429:
                    retry_after = resp.getheader("Retry-After", "")
                    delay = min(float(retry_after), 30) if retry_after.isdigit() else 4.0 * 2 ** attempt
            except (OSError, http.client.HTTPException):
                pass
            self.local.conn = None
            time.sleep(delay)
        return "ERR"


class RefreshAborted(Exception):
    pass


def resolve_all(
    names: List[str], query: Callable[[str], str], deadline: float, workers: int = WORKERS
) -> Dict[str, str]:
    """Resolve every name or raise RefreshAborted (deadline, or too many errors)."""
    results: Dict[str, str] = {}
    errors = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        it = iter(names)
        pending = set()
        done_count = 0
        try:
            while True:
                while len(pending) < workers * 4:
                    name = next(it, None)
                    if name is None:
                        break
                    future = pool.submit(query, name)
                    futures[future] = name
                    pending.add(future)
                if not pending:
                    break
                finished, pending = concurrent.futures.wait(
                    pending, timeout=5, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for future in finished:
                    status = future.result()
                    results[futures.pop(future)] = status
                    errors += status == "ERR"
                    done_count += 1
                if time.monotonic() > deadline:
                    raise RefreshAborted("deadline")
                if done_count >= 500 and errors / done_count > MAX_ERROR_RATE:
                    raise RefreshAborted(f"error rate {errors}/{done_count}")
        except BaseException:
            for future in pending:
                future.cancel()
            raise
    if errors / max(len(names), 1) > MAX_ERROR_RATE:
        raise RefreshAborted(f"error rate {errors}/{len(names)}")
    return results


def probe_names(entries: Iterable[str], psl: PublicSuffixes) -> Set[str]:
    """DNS probes: .zone for suffix entries (registered domain), host for exact entries."""
    probes: Set[str] = set()
    for entry in entries:
        host = entry.lstrip(".")
        if entry.startswith("."):
            registered = psl.registered(host)
            if registered:
                probes.add("." + registered)
        else:
            probes.add(host)
    return probes


def update_dead(
    old: Dead,
    probes: Set[str],
    first: Dict[str, str],
    second: Dict[str, str],
    today: dt.date,
) -> Dead:
    """Merge one check into the cached rows.

    first: status of every probe on resolver 1; second: status on resolver 2 for probes that were NX on resolver 1.
    Dead needs NX on both. Alive needs OK on either resolver. Anything else leaves a row unchanged.
    """
    new: Dead = {}
    for name in probes:
        s1 = first.get(name, "ERR")
        s2 = second.get(name, "ERR")
        row = old.get(name)
        if s1 == "NX" and s2 == "NX":
            new[name] = (row[0] if row else today.isoformat(), "")
        elif row:
            if "OK" in (s1, s2):
                since = dt.date.fromisoformat(row[1]) if row[1] else today
                if (today - since).days >= DEAD_RETURN_DAYS:
                    continue
                new[name] = (row[0], since.isoformat())
            else:
                new[name] = row
    return new


def refresh_dead(entries: Set[str], psl: PublicSuffixes, today: dt.date, clients=None, log=print) -> Dead:
    clients = clients or [Doh(h, p).query for h, p in RESOLVERS]
    for query in clients:
        for name in SENTINEL_ALIVE:
            if query(name) != "OK":
                raise RefreshAborted(f"sentinel {name} did not resolve")
        if query(f"nx-{int(time.time())}-sentinel.com") != "NX":
            raise RefreshAborted("sentinel NXDOMAIN not reported")
    probes = probe_names(entries, psl)
    old = load_dead(DATA / "dead.txt")
    names = sorted(probes)
    t0 = time.monotonic()
    first = resolve_all(names, lambda n: clients[0](n.lstrip(".")), t0 + STAGE_DEADLINE)
    nx = [n for n, s in first.items() if s == "NX"]
    log(f"  resolver 1: {len(names)} names, {len(nx)} NXDOMAIN, {time.monotonic() - t0:.0f}s")
    if len(nx) / max(len(names), 1) > MAX_DEAD_RATE:
        raise RefreshAborted("implausible NXDOMAIN rate")
    second = resolve_all(nx, lambda n: clients[1](n.lstrip(".")), time.monotonic() + STAGE_DEADLINE)
    log(f"  resolver 2: {len(nx)} names, {sum(s == 'NX' for s in second.values())} NXDOMAIN, {time.monotonic() - t0:.0f}s")
    return update_dead(old, probes, first, second, today)


def fetch_text(url: str, timeout: int = 120) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "surge-adblock-prune/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise OSError(f"HTTP {resp.status}")
        return resp.read().decode("utf-8", errors="replace")


def parse_easyprivacy(text: str) -> Set[str]:
    hosts = set()
    for line in text.splitlines():
        m = re.match(r"^\|\|([a-z0-9][a-z0-9.-]*\.[a-z0-9-]+)\^(\$.*)?$", line.strip(), re.I)
        if m:
            hosts.add(m.group(1).lower())
    return hosts


def parse_plain(text: str) -> Set[str]:
    hosts = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if line and line[0] not in "#!":
            hosts.add(line.lstrip("*.").lstrip("."))
    return hosts


def summary(*lines: str) -> None:
    """Print lines and append them to the GitHub Actions step summary when available."""
    print("\n".join(lines))
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n\n")


def warn_if_stale(today: dt.date, data_dir: Optional[Path] = None) -> None:
    data_dir = data_dir or DATA
    for name in ("dead.txt", "junk.txt"):
        last = read_header_date(data_dir / name)
        if last is None or (today - last).days > STALE_WARN_DAYS:
            print(f"::warning::data/{name} is {'missing' if last is None else f'{(today - last).days} days old'}")


# ---------------------------------------------------------------------------
# refresh command
# ---------------------------------------------------------------------------
def refresh(force: bool = False, today: Optional[dt.date] = None) -> int:
    import merge  # deferred: merge imports this module

    today = today or dt.datetime.now(dt.timezone.utc).date()
    dead_path, junk_path = DATA / "dead.txt", DATA / "junk.txt"

    def due(path: Path) -> bool:
        last = read_header_date(path)
        return force or last is None or (today - last).days >= REFRESH_DAYS

    do_dead, do_junk = due(dead_path), due(junk_path)
    if not (do_dead or do_junk):
        summary("prune refresh: skipped, caches are current")
        warn_if_stale(today)
        return 0
    started = time.monotonic()
    report = []
    loaded = {}
    for key in merge.BLOCK_SOURCES:
        meta = merge.SOURCES_META[key]
        loaded[key] = merge.parse_hosts(merge.SOURCES / meta["file"], meta["kind"])
    entries, _, _ = merge.build_block_set(loaded)
    local = merge.LOCAL_SUFFIX_HOSTS | merge.LOCAL_EXACT_HOSTS

    if do_dead:
        try:
            dead = refresh_dead(entries, PublicSuffixes(), today)
            write_dead(dead_path, dead, today)
            report.append(f"dead.txt refreshed: {len(dead)} names")
        except (RefreshAborted, OSError) as error:
            report.append(f"dead.txt refresh skipped, cache kept ({error})")

    if do_junk:
        try:
            privacy = {host.lstrip(".") for host in loaded["tracking_protection"]}
            privacy |= parse_easyprivacy(fetch_text(EASYPRIVACY_URL))
            malware = parse_plain(fetch_text(TIF_URL))
            if len(privacy) < MIN_EASYPRIVACY or len(malware) < MIN_TIF:
                raise OSError("guard list too small")
            junk = junk_candidates(entries, privacy, malware, local)
            write_junk(junk_path, junk, today)
            report.append(f"junk.txt refreshed: {len(junk)} entries")
        except (OSError, ValueError) as error:
            report.append(f"junk.txt refresh skipped, cache kept ({error})")
    summary("prune refresh: " + "; ".join(report) + f"; {time.monotonic() - started:.0f}s")
    warn_if_stale(today)
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["refresh"]:
        sys.exit(refresh(force="--force" in sys.argv))
    sys.exit("usage: prune.py refresh [--force]")
