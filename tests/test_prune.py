import contextlib
import datetime as dt
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import merge
import prune

TODAY = dt.date(2026, 11, 28)
LOCAL = merge.LOCAL_SUFFIX_HOSTS | merge.LOCAL_EXACT_HOSTS
GUARDED = {
    ".pangolin.snssdk.com",
    ".api-access.pangolin-sdk-toutiao5.com",
    ".pglstatp-sdk-toutiao.com",
    ".ctobsnssdk.com",
    ".wxsnsad.tc.qq.com",
}


def write_data(directory, dead="", junk=""):
    (directory / "dead.txt").write_text("# refreshed: 2026-11-27\n" + dead)
    (directory / "junk.txt").write_text("# refreshed: 2026-11-27\n" + junk)


class ApplyTests(unittest.TestCase):
    def test_dead_zone_and_exact_rows(self):
        dead = {".gone.com": ("2026-11-01", ""), "gone-host.example.org": ("2026-11-01", "")}
        self.assertTrue(prune.is_dead(".ads.gone.com", dead))
        self.assertTrue(prune.is_dead("a.gone.com", dead))
        self.assertTrue(prune.is_dead(".gone.com", dead))
        self.assertTrue(prune.is_dead("gone-host.example.org", dead))
        # An NXDOMAIN apex of a suffix entry does not prove its children are gone.
        self.assertFalse(prune.is_dead(".gone-host.example.org", dead))
        self.assertFalse(prune.is_dead(".other.example.org", dead))
        self.assertFalse(prune.is_dead(".notgone.com", dead))

    def test_guard_entries_survive_dead_and_junk(self):
        protected = set(GUARDED) | set(LOCAL)
        entries = protected | {".dead.com", ".junk.de", ".kept.com"}
        dead = "".join(f"{e}\t2026-01-01\n" for e in protected | {".dead.com"})
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            write_data(data, dead=dead, junk="".join(e + "\n" for e in protected | {".junk.de"}))
            kept, counts = prune.apply(entries, data, LOCAL)
        self.assertEqual(kept, protected | {".kept.com"})
        self.assertEqual(counts, {"dead": 1, "junk": 1})

    def test_apply_without_cache_prunes_nothing(self):
        entries = {".a.com", "b.example.net", ".c.de"}
        with tempfile.TemporaryDirectory() as directory:
            kept, counts = prune.apply(entries, Path(directory), LOCAL)
        self.assertEqual(kept, entries)
        self.assertEqual(counts, {"dead": 0, "junk": 0})

    def test_junk_list_is_exact_match(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            write_data(data, junk=".adscale.de\n")
            kept, counts = prune.apply({".adscale.de", ".x.adscale.de", "adscale.de"}, data, LOCAL)
        self.assertEqual(kept, {".x.adscale.de", "adscale.de"})
        self.assertEqual(counts["junk"], 1)


class JunkTests(unittest.TestCase):
    def junk(self, entries, privacy=(), malware=()):
        return prune.junk_candidates(entries, set(privacy), set(malware), LOCAL)

    def test_ad_junk_on_foreign_or_random_names(self):
        entries = {".adscale.de", ".banners.news1.co.il", ".k15eyex4iy6rulx3.cyou", ".ads.example.com", ".wbid.ru"}
        self.assertEqual(
            self.junk(entries),
            {".adscale.de", ".banners.news1.co.il", ".k15eyex4iy6rulx3.cyou", ".wbid.ru"},
        )

    def test_privacy_tracker_malware_and_cn_are_not_junk(self):
        entries = {
            ".sgtm.shop.de",            # tracker-named
            ".analytics.example.fr",
            ".stat.blogg.se",
            ".pixel-abc.ru",
            ".plain-privacy.nl",        # in a tracking-protection list
            ".sub.plain-privacy2.nl",   # parent in a tracking-protection list
            ".phish-shop.br",           # in threat intel
            ".adx.qq-ad.ru",            # CN brand
            ".adserver.example.cn",     # CN TLD
            ".ad.example.hk",
            ".msg.71.am",               # CN vendor on a foreign TLD
            ".adstore-1252524079.file.myqcloud.com.de",
            ".cdn.dbankcloud.ru",
            ".x.hispace.eu",
            ".control-ad.de",           # control: plain foreign ad host is junk
        }
        junk = self.junk(entries, privacy={"plain-privacy.nl", "plain-privacy2.nl"}, malware={"phish-shop.br"})
        self.assertEqual(junk, {".control-ad.de"})

    def test_keep_list_is_not_junk(self):
        entries = {".pglstatp-toutiao.de", ".a.wxsnsad.tc.qq.com", ".ahdohpiechei.com", "ali-bj-pcdn-08.biliapi.net"} | GUARDED
        self.assertEqual(self.junk(entries), set())

    def test_foreign_and_random_helpers(self):
        for host in ("a.de", "a.com.br", "a.xn--p1ai", "a.eu", "a.ru"):
            self.assertTrue(prune.foreign(host), host)
        for host in ("a.com", "a.cn", "a.sg", "a.co.uk", "a.io", "a.tv", "a.net", "a.hk"):
            self.assertFalse(prune.foreign(host), host)
        self.assertTrue(prune.random_looking("fnjyke44je42x892o7wy2lgxg8.cfd"))
        self.assertTrue(prune.random_looking("459517eb349739b.com"))
        self.assertFalse(prune.random_looking("ads.example.com"))


class PublicSuffixTests(unittest.TestCase):
    def test_registered_domain(self):
        psl = prune.PublicSuffixes()
        self.assertEqual(psl.registered("a.b.example.com"), "example.com")
        self.assertEqual(psl.registered("x.y.co.uk"), "y.co.uk")
        self.assertEqual(psl.registered("a.example.com.cn"), "example.com.cn")
        self.assertEqual(psl.registered("a.b.unknowntld"), "b.unknowntld")
        self.assertIsNone(psl.registered("co.uk"))
        self.assertEqual(psl.registered("www.ck"), "www.ck")      # exception rule
        self.assertEqual(psl.registered("a.b.ck"), "a.b.ck")      # wildcard rule

    def test_probe_names(self):
        psl = prune.PublicSuffixes()
        probes = prune.probe_names({".a.b.example.com", "host.example.org", ".example.co.uk", ".co.uk"}, psl)
        self.assertEqual(probes, {".example.com", "host.example.org", ".example.co.uk"})


class UpdateDeadTests(unittest.TestCase):
    def update(self, old, first, second, probes=None, today=TODAY):
        return prune.update_dead(old, set(probes or first), first, second, today)

    def test_new_dead_needs_both_resolvers(self):
        first = {".a.com": "NX", ".b.com": "NX", ".c.com": "NX", ".d.com": "OK", ".e.com": "ERR"}
        second = {".a.com": "NX", ".b.com": "OK", ".c.com": "ERR"}
        self.assertEqual(self.update({}, first, second), {".a.com": ("2026-11-28", "")})

    def test_failures_never_add_or_remove_rows(self):
        old = {".a.com": ("2026-10-01", ""), ".b.com": ("2026-10-01", "2026-10-20")}
        for status in ("ERR", "FAIL"):
            first = {n: status for n in (".a.com", ".b.com", ".c.com")}
            self.assertEqual(self.update(old, first, {}), old)
        # resolver 2 failed after resolver 1 saw NX: rows stay, no new rows
        first = {".a.com": "NX", ".b.com": "NX", ".c.com": "NX"}
        new = self.update(old, first, {".a.com": "ERR", ".b.com": "ERR", ".c.com": "ERR"})
        self.assertEqual(new, old)

    def test_thirty_day_rule(self):
        old = {".a.com": ("2026-09-01", "")}
        probes = {".a.com"}
        # first alive observation only starts the clock
        row = self.update(old, {".a.com": "OK"}, {}, probes, dt.date(2026, 11, 1))
        self.assertEqual(row, {".a.com": ("2026-09-01", "2026-11-01")})
        # 29 days later: still pruned
        row2 = self.update(row, {".a.com": "OK"}, {}, probes, dt.date(2026, 11, 30))
        self.assertEqual(row2, row)
        # 30 days later: returns to the list
        self.assertEqual(self.update(row, {".a.com": "OK"}, {}, probes, dt.date(2026, 12, 1)), {})
        # NXDOMAIN again resets the clock and keeps the first date
        back = self.update(row, {".a.com": "NX"}, {".a.com": "NX"}, probes, dt.date(2026, 11, 20))
        self.assertEqual(back, {".a.com": ("2026-09-01", "")})

    def test_alive_on_either_resolver_starts_the_clock(self):
        old = {".a.com": ("2026-09-01", ""), ".b.com": ("2026-09-01", "")}
        # resolver 1 NX, resolver 2 OK: not dead evidence, but an alive observation
        new = self.update(old, {".a.com": "NX", ".b.com": "OK"}, {".a.com": "OK"})
        self.assertEqual(new, {".a.com": ("2026-09-01", "2026-11-28"), ".b.com": ("2026-09-01", "2026-11-28")})
        # 30 days after the first alive observation the rows are dropped
        later = dt.date(2026, 12, 28)
        self.assertEqual(self.update(new, {".a.com": "NX", ".b.com": "OK"}, {".a.com": "OK"}, today=later), {})

    def test_stale_cache_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            write_data(data)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                prune.warn_if_stale(dt.date(2026, 12, 18), data)
                self.assertEqual(out.getvalue(), "")
                prune.warn_if_stale(dt.date(2026, 12, 19), data)
            self.assertEqual(out.getvalue().count("::warning::"), 2)

    def test_rows_for_names_no_longer_listed_are_dropped(self):
        old = {".a.com": ("2026-10-01", ""), ".gone.com": ("2026-10-01", "")}
        self.assertEqual(self.update(old, {".a.com": "ERR"}, {}, {".a.com"}), {".a.com": ("2026-10-01", "")})

    def test_write_and_load_round_trip(self):
        rows = {".a.com": ("2026-10-01", ""), "h.example.org": ("2026-10-02", "2026-11-01")}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dead.txt"
            prune.write_dead(path, rows, TODAY)
            self.assertEqual(prune.load_dead(path), rows)
            self.assertEqual(prune.read_header_date(path), TODAY)


class DohTests(unittest.TestCase):
    def test_wire_format(self):
        self.assertEqual(prune.build_query("a.bc")[12:], b"\x01a\x02bc\x00\x00\x01\x00\x01")
        for bad in ("é.com", "a..com", "x" * 64 + ".com"):
            with self.assertRaises(ValueError):
                prune.build_query(bad)
        reply = lambda rcode: b"\x00\x00\x81" + bytes([0x80 | rcode]) + b"\x00" * 8
        self.assertEqual(prune.parse_response(reply(3)), "NX")
        self.assertEqual(prune.parse_response(reply(0)), "OK")
        self.assertEqual(prune.parse_response(reply(2)), "FAIL")
        self.assertEqual(prune.parse_response(b"<html>"), "ERR")

    def test_resolve_all_aborts_on_errors_and_deadline(self):
        names = [f"n{i}.com" for i in range(2000)]
        with self.assertRaises(prune.RefreshAborted):
            prune.resolve_all(names, lambda n: "ERR", 10**12, workers=4)
        with self.assertRaises(prune.RefreshAborted):
            prune.resolve_all(names, lambda n: "OK", 0, workers=4)
        self.assertEqual(set(prune.resolve_all(names, lambda n: "NX", 10**12, workers=4).values()), {"NX"})

    def test_sentinel_failure_aborts_before_any_scan(self):
        calls = []

        def broken(name):
            calls.append(name)
            return "NX"  # a resolver answering NXDOMAIN for everything

        psl = prune.PublicSuffixes()
        with self.assertRaises(prune.RefreshAborted):
            prune.refresh_dead({".a.com"}, psl, TODAY, clients=[broken, broken], log=lambda *a: None)
        self.assertEqual(len(calls), 1)

    def test_implausible_nxdomain_rate_aborts(self):
        def query(name):
            return "OK" if name in prune.SENTINEL_ALIVE else "NX"

        entries = {f".d{i}.com" for i in range(2000)}
        with self.assertRaises(prune.RefreshAborted):
            prune.refresh_dead(entries, prune.PublicSuffixes(), TODAY, clients=[query, query], log=lambda *a: None)


class RefreshTests(unittest.TestCase):
    def test_failed_refresh_keeps_cached_files(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            write_data(data, dead=".a.com\t2026-10-01\n", junk=".adscale.de\n")
            for p in data.iterdir():
                p.write_text(p.read_text().replace("2026-11-27", "2026-10-01"))
            before = {p.name: p.read_bytes() for p in data.iterdir()}
            with patch.object(prune, "DATA", data), patch.object(prune.Doh, "query", return_value="ERR"), \
                 patch.object(prune, "fetch_text", side_effect=OSError("offline")), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(prune.refresh(today=TODAY), 0)
            self.assertEqual({p.name: p.read_bytes() for p in data.iterdir()}, before)
            self.assertIn("cache kept", out.getvalue())

    def test_fresh_cache_skips_network(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            write_data(data)
            with patch.object(prune, "DATA", data), patch.object(prune.Doh, "query", side_effect=AssertionError), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(prune.refresh(today=dt.date(2026, 11, 30)), 0)


class MergeIntegrationTests(unittest.TestCase):
    def test_merge_applies_cache_and_keeps_guard(self):
        status = {
            key: {"ok": True, "path": merge.SOURCES / meta["file"], "kind": meta["kind"]}
            for key, meta in merge.SOURCES_META.items()
        }
        with tempfile.TemporaryDirectory() as directory:
            out, data = Path(directory) / "out", Path(directory) / "data"
            data.mkdir()
            base = Path(directory) / "base"
            with patch.object(merge, "fetch_all", return_value=status), patch.object(merge, "OUT", base), \
                 patch.object(merge, "PRUNE_DIR", data), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(merge.main(), 0)
            base_lines = set((base / "block.list").read_text().splitlines())
            victims = sorted(l for l in base_lines if l.startswith(".") and not prune.is_kept(l, LOCAL))[:3]
            exact = sorted(l for l in base_lines if not l.startswith(("#", ".")) and not prune.is_kept(l, LOCAL))[:2]
            guarded = sorted(l for l in base_lines if prune.KEEP_RE.search(l))
            self.assertTrue(guarded)
            dead = "".join(f"{v}\t2026-11-01\n" for v in victims[:2]) + "".join(f"{v}\t2026-11-01\n" for v in guarded)
            write_data(data, dead=dead, junk="".join(l + "\n" for l in [victims[2]] + exact + guarded))
            with patch.object(merge, "fetch_all", return_value=status), patch.object(merge, "OUT", out), \
                 patch.object(merge, "PRUNE_DIR", data), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(merge.main(), 0)
            lines = set((out / "block.list").read_text().splitlines())
            for entry in victims + exact:
                self.assertNotIn(entry, lines)
            for entry in guarded:
                self.assertIn(entry, lines)
            for entry in merge.LOCAL_SUFFIX_HOSTS | merge.LOCAL_EXACT_HOSTS:
                self.assertIn(entry, lines)
            self.assertEqual(len(base_lines) - len(lines), len(victims) + len(exact))
            self.assertEqual((out / "dns-block-ruleset.list").read_text().splitlines()[3:],
                             (base / "dns-block-ruleset.list").read_text().splitlines()[3:])


if __name__ == "__main__":
    unittest.main(verbosity=2)
