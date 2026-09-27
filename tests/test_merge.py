import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import merge


class MergeTests(unittest.TestCase):
    def test_exact_domainset_round_trip(self):
        hosts = merge.parse_hosts(merge.SOURCES / "bm7_privacy_domain.list", "domainset")
        lines = merge.to_domainset_lines(merge.fold_suffixes(hosts))
        self.assertTrue("play.kakao.com" in lines, "exact rule widened or lost")
        self.assertNotIn(".play.kakao.com", lines)

    def test_hosts_exact_scope(self):
        hosts = merge.parse_hosts(merge.SOURCES / "stevenblack_hosts.txt", "hosts")
        self.assertTrue("0.nextyourcontent.com" in hosts)
        self.assertFalse(any(host.startswith(".") for host in hosts))
        self.assertNotIn("0.0.0.0", hosts)
        self.assertNotIn("localhost", hosts)

    def test_typed_exact_domain(self):
        self.assertEqual(merge.line_to_host("DOMAIN,play.kakao.com", "ruleset"), "play.kakao.com")

    def test_suffix_folding(self):
        self.assertEqual(
            merge.fold_suffixes({".doubleclick.net", ".googleads.g.doubleclick.net", "doubleclick.net"}),
            {".doubleclick.net"},
        )

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
            lines = set((Path(directory) / "block.list").read_text().splitlines())
        for host in ("safebrowsing.googleapis.com", "safebrowsing.urlsec.qq.com"):
            with self.subTest(protected=host):
                self.assertFalse(any(host == line or (line.startswith(".") and
                    (host == line[1:] or host.endswith(line))) for line in lines))
        for sourceFile in ("geekdada_dns_filter.txt", "geekdada_tracking_protection_filter.txt", "onehosts_lite_adblock.txt", "stevenblack_hosts.txt"):
            with self.subTest(source=sourceFile):
                missing = []
                for entry in (merge.SOURCES / sourceFile).read_text().splitlines():
                    host = entry.strip().lower().lstrip(".")
                    if not host or entry.startswith(("#", "!")):
                        continue
                    if sourceFile == "stevenblack_hosts.txt":
                        fields = host.split("#", 1)[0].split()
                        if len(fields) != 2 or fields[0] != "0.0.0.0" or fields[1] == "0.0.0.0":
                            continue
                        host = fields[1]
                    if sourceFile == "onehosts_lite_adblock.txt":
                        self.assertTrue(host.startswith("||") and host.endswith("^"), host)
                        host = host[2:-1]
                    parents = {".".join(host.split(".")[i:]) for i in range(len(host.split(".")) - 1)}
                    if parents & merge.SHORT_ROOT_DENY or parents & {"safebrowsing.googleapis.com", "safebrowsing.urlsec.qq.com"}:
                        continue
                    if not (sourceFile == "stevenblack_hosts.txt" and host in lines) and not any("." + parent in lines for parent in parents):
                        missing.append(host)
                self.assertEqual(len(missing), 0, f"Source entries missing: {missing[:5]}")
        with self.subTest(advertising="doubleclick.net"):
            self.assertIn(".doubleclick.net", lines)


if __name__ == "__main__":
    unittest.main(verbosity=2)
