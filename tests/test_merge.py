import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import merge


class MergeTests(unittest.TestCase):
    def test_exact_domainset_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "set.list"
            path.write_text("play.kakao.com\n.kakao.net\n")
            lines = merge.to_domainset_lines(merge.fold_suffixes(merge.parse_hosts(path, "domainset")))
        self.assertEqual(lines, [".kakao.net", "play.kakao.com"])

    def test_typed_exact_domain(self):
        self.assertEqual(merge.line_to_host("DOMAIN,play.kakao.com", "ruleset"), "play.kakao.com")

    def test_suffix_folding(self):
        self.assertEqual(
            merge.fold_suffixes({".doubleclick.net", ".googleads.g.doubleclick.net", "doubleclick.net"}),
            {".doubleclick.net"},
        )

    def test_pcdn_suffix_domainset_form(self):
        self.assertEqual(
            merge.LOCAL_SUFFIX_HOSTS,
            {
                ".ahdohpiechei.com",
                ".mcdn.bilivideo.cn",
                ".mcdn.bilivideo.com",
                ".szbdyd.com",
                ".mountaintoys.cn",
            },
        )
        for entry in merge.LOCAL_SUFFIX_HOSTS:
            host = entry[1:]
            self.assertEqual(merge.line_to_host(f"DOMAIN-SUFFIX,{host}", "domainset"), entry)
            self.assertNotIn("*", entry)
            self.assertNotIn("biliapi.net", entry)
        self.assertEqual(
            merge.fold_suffixes({".mcdn.bilivideo.cn", ".a.mcdn.bilivideo.cn", "mcdn.bilivideo.cn"}),
            {".mcdn.bilivideo.cn"},
        )
        self.assertIsNone(merge.line_to_host("*pcdn*.biliapi.net", "plain_hosts"))
        self.assertIsNone(merge.line_to_host("DOMAIN-WILDCARD,*pcdn*.biliapi.net,REJECT", "domainset"))
        kept, removed = merge.drop_short_roots(merge.fold_suffixes(merge.LOCAL_SUFFIX_HOSTS))
        self.assertEqual(kept, set(merge.LOCAL_SUFFIX_HOSTS))
        self.assertEqual(removed, set())

    def test_pcdn_exact_hosts(self):
        self.assertEqual(
            merge.LOCAL_EXACT_HOSTS,
            {
                "ali-bj-pcdn-08.biliapi.net",
                "ali-bj-pcdn-11.biliapi.net",
                "ali-bj-pcdn-12.biliapi.net",
                "ali-bj-pcdn-16.biliapi.net",
                "ali-bj-pcdn-19.biliapi.net",
                "ali-bj-pcdn-24.biliapi.net",
                "ali-bj-pcdn-25.biliapi.net",
                "ali-bj-pcdn-28.biliapi.net",
                "ali-bj-pcdn-37.biliapi.net",
                "ali-bj-pcdn-68.biliapi.net",
                "hw-sh-pcdn-06.biliapi.net",
                "hw-sh-pcdn-08.biliapi.net",
                "hw-sh-pcdn-10.biliapi.net",
                "hw-sh-pcdn-12.biliapi.net",
                "hw-sh-pcdn-14.biliapi.net",
                "hw-sh-pcdn-15.biliapi.net",
                "hw-sh-pcdn-18.biliapi.net",
                "hw-sh-pcdn-19.biliapi.net",
                "hw-sh-pcdn-26.biliapi.net",
                "hw-sh-pcdn-29.biliapi.net",
                "hw-sh-pcdn-37.biliapi.net",
                "hw-sh-pcdn-96.biliapi.net",
                "hw-sh-pcdn-107.biliapi.net",
                "hw-sh-pcdn-112.biliapi.net",
            },
        )
        rejected = {
            "api.biliapi.net",
            "app.biliapi.net",
            "grpc.biliapi.net",
            "mcdn-data.biliapi.net",
            "ali-web-player-tracker.biliapi.net",
            "hw-v2-web-player-tracker.biliapi.net",
            "hw-web-player-tracker.biliapi.net",
            "ks-sh-tracker-02.biliapi.net",
            "ali-bj-pcdn-99.biliapi.net",
            "hw-sh-pcdn-99.biliapi.net",
            "biliapi.net",
        }
        for host in merge.LOCAL_EXACT_HOSTS:
            self.assertEqual(merge.line_to_host(f"DOMAIN,{host}", "domainset"), host)
            self.assertRegex(host, r"^(?:ali-bj-pcdn|hw-sh-pcdn)-[0-9]+\.biliapi\.net$")
            self.assertNotIn("." + host, merge.LOCAL_SUFFIX_HOSTS)
        self.assertTrue(rejected.isdisjoint(merge.LOCAL_EXACT_HOSTS))
        kept, removed = merge.drop_short_roots(
            merge.fold_suffixes(set(merge.LOCAL_SUFFIX_HOSTS) | set(merge.LOCAL_EXACT_HOSTS))
        )
        self.assertEqual(kept, set(merge.LOCAL_SUFFIX_HOSTS) | set(merge.LOCAL_EXACT_HOSTS))
        self.assertEqual(removed, set())

    def test_exact_parent_keeps_child(self):
        self.assertEqual(
            merge.fold_suffixes({"sentry.io", ".o33249.ingest.sentry.io"}),
            {"sentry.io", ".o33249.ingest.sentry.io"},
        )

    def test_short_root_filter(self):
        self.assertEqual(merge.drop_short_roots({".ad.com", ".doubleclick.net"}),
                         ({".doubleclick.net"}, {".ad.com"}))

    def test_hagezi_wildcard_source(self):
        self.assertEqual(merge.line_to_host("doubleclick.net", "plain_hosts"), ".doubleclick.net")

    def test_domainset_reference_is_not_a_host(self):
        self.assertIsNone(merge.line_to_host("DOMAIN-SET,ads.list", "ruleset"))

    def test_full_merge(self):
        status = {
            key: {"ok": True, "path": merge.SOURCES / meta["file"], "kind": meta["kind"]}
            for key, meta in merge.SOURCES_META.items()
        }
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(merge, "fetch_all", return_value=status), patch.object(merge, "OUT", Path(directory)):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(merge.main(), 0)
            block_text = (Path(directory) / "block.list").read_text()
            lines = set(block_text.splitlines())
            self.assertIn("# Local suffix entries: " + ", ".join(sorted(merge.LOCAL_SUFFIX_HOSTS)), lines)
            for entry in merge.LOCAL_SUFFIX_HOSTS:
                self.assertIn(entry, lines)
            self.assertIn("# Local exact entries: " + ", ".join(sorted(merge.LOCAL_EXACT_HOSTS)), lines)
            for host in merge.LOCAL_EXACT_HOSTS:
                self.assertIn(host, lines)
                self.assertNotIn("." + host, lines)
            for absent in (
                ".biliapi.net",
                "biliapi.net",
                ".bilivideo.com",
                ".bilivideo.cn",
                "bilivideo.com",
                "bilivideo.cn",
                "api.biliapi.net",
                "app.biliapi.net",
                "grpc.biliapi.net",
                "mcdn-data.biliapi.net",
                "ali-web-player-tracker.biliapi.net",
                "hw-v2-web-player-tracker.biliapi.net",
                "hw-web-player-tracker.biliapi.net",
                "ks-sh-tracker-02.biliapi.net",
                "ali-bj-pcdn-99.biliapi.net",
                "hw-sh-pcdn-99.biliapi.net",
                "qrstuvwxyzab.com",
                ".qrstuvwxyzab.com",
                ".bilivideo.com",
                ".bilivideo.cn",
            ):
                self.assertNotIn(absent, lines)
            self.assertIn(".ahdohpiechei.com", lines)
            folded = merge.fold_suffixes({".ahdohpiechei.com", ".2026608071.ahdohpiechei.com", "2026608071.ahdohpiechei.com"})
            self.assertEqual(folded, {".ahdohpiechei.com"})
            dnsRules = set((Path(directory) / "dns-block-ruleset.list").read_text().splitlines())
            for rule in ("DOMAIN-SUFFIX,dns.google", "IP-CIDR,1.1.1.1/32,no-resolve", "DOMAIN-SUFFIX,dns.weixin.qq.com"):
                with self.subTest(dnsRule=rule):
                    self.assertIn(rule, dnsRules)
            self.assertNotIn(".dns.google", lines)
            self.assertNotIn("DOMAIN,dns.weixin.qq.com", dnsRules)
            self.assertFalse((Path(directory) / "patch-ruleset.list").exists())

        for host in ("safebrowsing.googleapis.com", "safebrowsing.urlsec.qq.com"):
            with self.subTest(protected=host):
                self.assertFalse(any(host == line or (line.startswith(".") and
                    (host == line[1:] or host.endswith(line))) for line in lines))
        for sourceFile in ("geekdada_tracking_protection_filter.txt", "onehosts_lite_adblock.txt", "hagezi_normal_onlydomains.txt", "hagezi_popupads_onlydomains.txt"):
            with self.subTest(source=sourceFile):
                missing = []
                for entry in (merge.SOURCES / sourceFile).read_text().splitlines():
                    host = entry.strip().lower().lstrip(".")
                    if not host or entry.startswith(("#", "!")) or entry == "[Adblock Plus]":
                        continue
                    if sourceFile == "onehosts_lite_adblock.txt":
                        self.assertTrue(host.startswith("||") and host.endswith("^"), host)
                        host = host[2:-1]
                    parents = {".".join(host.split(".")[i:]) for i in range(len(host.split(".")) - 1)}
                    if parents & merge.SHORT_ROOT_DENY or parents & {"safebrowsing.googleapis.com", "safebrowsing.urlsec.qq.com"}:
                        continue
                    if not any("." + parent in lines for parent in parents):
                        missing.append(host)
                self.assertEqual(len(missing), 0, f"Source entries missing: {missing[:5]}")
        with self.subTest(advertising="doubleclick.net"):
            self.assertIn(".doubleclick.net", lines)


if __name__ == "__main__":
    unittest.main(verbosity=2)
