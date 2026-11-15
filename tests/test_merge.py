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
        for name in ("pay.com", "update.com", "tracker.com", "track.net"):
            self.assertIn(name, merge.SHORT_ROOT_DENY)
        kept, removed = merge.drop_short_roots(
            {".pay.com", ".update.com", ".tracker.com", ".track.net", ".adpay.com", ".clearing-update.com", ".17track.net"}
        )
        self.assertEqual(removed, {".pay.com", ".update.com", ".tracker.com", ".track.net"})
        self.assertEqual(kept, {".adpay.com", ".clearing-update.com", ".17track.net"})
        folded = merge.fold_suffixes({".pay.com", ".api.pay.com", "pay.com"})
        kept, removed = merge.drop_short_roots(folded)
        self.assertEqual(folded, {".pay.com"})
        self.assertEqual(kept, set())
        self.assertEqual(removed, {".pay.com"})

    def test_service_exclusions_keep_specific_hosts(self):
        hosts = {
            ".wxs.qq.com",
            "wxs.qq.com",
            ".wxsnsdy.wxs.qq.com",
            ".wximg.wxs.qq.com",
            ".wxsmw.wxs.qq.com",
            ".wxsnsdythumb.wxs.qq.com",
            ".wxsnsdy.tc.qq.com",
            ".wxsnsdy.video.qq.com",
            ".wxsnsad.tc.qq.com",
            ".szlong.weixin.qq.com",
            ".aedns.weixin.qq.com",
            ".obs.cn-north-1.myhuaweicloud.com",
            ".alibabagroup.obs.cn-north-1.myhuaweicloud.com",
            ".gvt2.com",
            ".beacons.gvt2.com",
            ".kwai.com",
            ".www.kwai.com",
            ".api.kwai.com",
            ".g-api.kwai.com",
            ".cdn.kwai.com",
            ".m.kwai.com",
            ".h5.kwai.com",
            ".az1-app.kwai.com",
            ".az1-m-shop.kwai.com",
            ".az1-m-wallet.kwai.com",
            ".az1-m-live.kwai.com",
            ".az1-m-game.kwai.com",
            ".h5-ad-intl.kwai.com",
            ".gdfp.kwai.com",
            ".og-rta.kwai.com",
            ".kwaiedm.kwai.com",
            ".k-ad.region.kwai.com",
            ".incentive.kwai.com",
            ".az1-incentive.kwai.com",
            ".nsp-appgallery-cmsimg3az-drcn.obs.cn-north-2.myhuaweicloud.com",
            ".game.bilibili.com",
            ".cm.game.bilibili.com",
            ".bilibili.cn",
            ".ahdohpiechei.com",
            "ali-bj-pcdn-08.biliapi.net",
            ".pay.com",
            ".api.pay.com",
        }
        kept, removed = merge.drop_service_hosts(hosts)
        for entry in (
            ".wxs.qq.com",
            "wxs.qq.com",
            ".wxsnsdy.wxs.qq.com",
            ".wximg.wxs.qq.com",
            ".wxsmw.wxs.qq.com",
            ".wxsnsdythumb.wxs.qq.com",
            ".wxsnsdy.tc.qq.com",
            ".wxsnsdy.video.qq.com",
            ".szlong.weixin.qq.com",
            ".aedns.weixin.qq.com",
            ".obs.cn-north-1.myhuaweicloud.com",
            ".gvt2.com",
            ".kwai.com",
            ".www.kwai.com",
            ".api.kwai.com",
            ".g-api.kwai.com",
            ".cdn.kwai.com",
            ".m.kwai.com",
            ".h5.kwai.com",
            ".az1-app.kwai.com",
            ".az1-m-shop.kwai.com",
            ".az1-m-wallet.kwai.com",
            ".az1-m-live.kwai.com",
            ".az1-m-game.kwai.com",
            ".nsp-appgallery-cmsimg3az-drcn.obs.cn-north-2.myhuaweicloud.com",
            ".game.bilibili.com",
            ".bilibili.cn",
        ):
            self.assertIn(entry, removed)
            self.assertNotIn(entry, kept)
        for entry in (
            ".wxsnsad.tc.qq.com",
            ".alibabagroup.obs.cn-north-1.myhuaweicloud.com",
            ".beacons.gvt2.com",
            ".h5-ad-intl.kwai.com",
            ".gdfp.kwai.com",
            ".og-rta.kwai.com",
            ".kwaiedm.kwai.com",
            ".k-ad.region.kwai.com",
            ".incentive.kwai.com",
            ".az1-incentive.kwai.com",
            ".cm.game.bilibili.com",
            ".ahdohpiechei.com",
            "ali-bj-pcdn-08.biliapi.net",
            ".pay.com",
            ".api.pay.com",
        ):
            self.assertIn(entry, kept)
            self.assertNotIn(entry, removed)
        self.assertFalse(merge.service_excluded(".wxsnsad.tc.qq.com"))
        self.assertFalse(merge.service_excluded("ali-bj-pcdn-08.biliapi.net"))
        self.assertFalse(merge.service_excluded(".ahdohpiechei.com"))
        self.assertTrue(merge.service_excluded(".wxa.wxs.qq.com"))
        folded = merge.fold_suffixes(kept)
        self.assertIn(".wxsnsad.tc.qq.com", folded)
        self.assertIn(".alibabagroup.obs.cn-north-1.myhuaweicloud.com", folded)
        self.assertIn(".beacons.gvt2.com", folded)
        self.assertIn(".h5-ad-intl.kwai.com", folded)
        self.assertIn(".cm.game.bilibili.com", folded)
        self.assertIn(".ahdohpiechei.com", folded)
        self.assertIn("ali-bj-pcdn-08.biliapi.net", folded)

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
            for name in merge.SERVICE_EXACT_DENY | merge.SERVICE_TREE_DENY | {"pay.com", "update.com", "tracker.com", "track.net"}:
                self.assertNotIn("." + name, lines)
                self.assertNotIn(name, lines)
            for entry in (
                ".wxa.wxs.qq.com",
                ".wximg.wxs.qq.com",
                ".wxsmw.wxs.qq.com",
                ".wxsnsdy.wxs.qq.com",
                ".wxsnsdythumb.wxs.qq.com",
                ".www.kwai.com",
                ".api.kwai.com",
                ".g-api.kwai.com",
                ".cdn.kwai.com",
                ".m.kwai.com",
                ".h5.kwai.com",
                ".az1-app.kwai.com",
                ".az2-app.kwai.com",
                ".az3-app.kwai.com",
                ".az1-m-shop.kwai.com",
                ".az2-m-wallet.kwai.com",
                ".az3-m-live.kwai.com",
                ".az1-m-game.kwai.com",
                ".game.kwai.com",
                ".region.kwai.com",
                ".nsp-appgallery-cmsimg3az-drcn.obs.cn-north-2.myhuaweicloud.com",
            ):
                self.assertNotIn(entry, lines)
            for entry in (
                ".wxsnsad.tc.qq.com",
                ".alibabagroup.obs.cn-north-1.myhuaweicloud.com",
                ".beacons.gvt2.com",
                ".h5-ad-intl.kwai.com",
                ".gdfp.kwai.com",
                ".og-rta.kwai.com",
                ".kwaiedm.kwai.com",
                ".k-ad.region.kwai.com",
                ".incentive.kwai.com",
                ".az1-incentive.kwai.com",
                ".az2-incentive.kwai.com",
                ".az3-incentive.kwai.com",
                ".cm.game.bilibili.com",
            ):
                self.assertIn(entry, lines)
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
                    if merge.service_excluded(host) or parents & merge.SHORT_ROOT_DENY or parents & {"safebrowsing.googleapis.com", "safebrowsing.urlsec.qq.com"}:
                        continue
                    if not any("." + parent in lines for parent in parents):
                        missing.append(host)
                self.assertEqual(len(missing), 0, f"Source entries missing: {missing[:5]}")
        with self.subTest(advertising="doubleclick.net"):
            self.assertIn(".doubleclick.net", lines)


if __name__ == "__main__":
    unittest.main(verbosity=2)
