# surge-adblock

Surge ad-blocking DOMAIN-SET, with exclusions for Google and Tencent Safe Browsing service domains.

```ini
DOMAIN-SET,https://raw.githubusercontent.com/tlhc/surge-adblock/main/out/block.list,REJECT,pre-matching,extended-matching,update-interval=86400
```

The update interval is 86400 seconds. Put this line in `[Rule]` before general forwarding rules and `FINAL`.

| File | Role |
|------|------|
| `out/block.list` | Bare hosts match exactly; leading-dot hosts also match subdomains |

Contents: OISD small + anti-AD + AWAvenue + BM7 Privacy + HaGeZi Normal + HaGeZi Fake + HaGeZi Pop-Up Ads + [geekdada DNS filter and Tracking Protection](https://github.com/geekdada/surge-list) + [1Hosts Lite](https://github.com/badmojr/1Hosts) + [StevenBlack Unified](https://github.com/StevenBlack/hosts), deduplicated and suffix-folded. HaGeZi's wildcard-domain feed and 1Hosts Lite's `||host^` rules retain suffix matching. StevenBlack uses the default adware/malware hosts file and converts its `0.0.0.0 host` lines into exact matches. Exact DOMAIN-SET entries retain exact matching, following the [Surge format](https://manual.nssurge.com/rules/domain.html).

`safebrowsing.googleapis.com` and `safebrowsing.urlsec.qq.com`, their subdomains, and suffix rules covering them are excluded before folding. The existing short-root exclusions in `merge.py` apply after folding. `out/patch-ruleset.list` remains a separate optional BanAD subscription.

Generate with `python3 merge.py`; validate with `python3 -W error -m unittest discover -s tests -v`. Tests use downloaded files in `sources/`. Each source updates independently. Failed downloads and responses with no valid rules retain the previous valid source; updates continue with the next source. If a source has neither a valid download nor a valid cached file, generation stops before changing outputs. Broader DNS coverage still requires application-level checks for false positives.

GitHub Actions refreshes all sources daily at 16:00 UTC (00:00 UTC+8), validates the merge, and publishes updated outputs and source snapshots for subsequent fallback. Manual runs use `workflow_dispatch`.

Encrypted DNS and HTTPDNS blocking is generated separately as `out/dns-block-ruleset.list` from [HaGeZi encrypted DNS domains](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-onlydomains.txt), [HaGeZi DoH IPv4](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/ips/doh.txt), and [BM7 BlockHttpDNS](https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BlockHttpDNS/BlockHttpDNS.list). The same daily workflow updates these sources, retains valid cached downloads on failure, and publishes the deduplicated RULE-SET. IPv4 addresses become `/32` rules; BM7 domain matching scope, IPv4 networks, and IPv6 networks are preserved. IP rules block all ports at the listed destinations.

After publishing, subscribe before general forwarding rules. With `encrypted-dns-follow-outbound-mode=true`, route Surge-generated encrypted DNS first using your existing DNS outbound policy (`Proxy` below):

```ini
OR,((PROTOCOL,DOH),(PROTOCOL,DOH3),(PROTOCOL,DOT),(PROTOCOL,DOQ)),Proxy
RULE-SET,https://raw.githubusercontent.com/tlhc/surge-adblock/main/out/dns-block-ruleset.list,REJECT,no-resolve,update-interval=86400
```

Keep this subscription free of `pre-matching`, which would run before the protocol exception. The advertising DOMAIN-SET remains separate so its DNS-stage rejection does not intercept Surge's own encrypted resolvers. Endpoint lists cover listed services; private or unlisted encrypted DNS endpoints require additional controls.
