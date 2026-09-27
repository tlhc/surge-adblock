import tempfile
import unittest
from pathlib import Path
import merge


class DnsSourcesTests(unittest.TestCase):
    def test_real_ip_sources(self):
        for name, kind, expected in (
            ('hagezi_doh_ipv4.txt', 'ipv4', 'IP-CIDR,1.1.1.1/32,no-resolve'),
            ('bm7_httpdns.list', 'httpdns', 'DOMAIN,dns.weixin.qq.com'),
        ):
            with self.subTest(source=name):
                rules = merge.ParseDnsRules(merge.SOURCES / name, kind)
                self.assertIn(expected, rules)
                self.assertTrue(merge.SourceIsValid(merge.SOURCES / name, kind))
        rules = merge.ParseDnsRules(merge.SOURCES / 'bm7_httpdns.list', 'httpdns')
        sourceRules = {line for line in (merge.SOURCES / "bm7_httpdns.list").read_text().splitlines() if line and not line.startswith("#")}
        self.assertEqual(set(rules), sourceRules)

    def test_invalid_dns_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.txt'
            for kind, data in [('ipv4', '999.1.1.1'), ('httpdns', 'DOMAIN,example.com\nFINAL,DIRECT')]:
                with self.subTest(kind=kind):
                    path.write_text(data)
                    self.assertFalse(merge.SourceIsValid(path, kind))
