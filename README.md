# surge-adblock

Surge ad-blocking DOMAIN-SET, with exclusions for Google and Tencent Safe Browsing service domains.

```ini
DOMAIN-SET,https://raw.githubusercontent.com/tlhc/surge-adblock/main/out/block.list,REJECT,pre-matching,extended-matching,update-interval=86400
```

The update interval is 86400 seconds. Put this line in `[Rule]` before general forwarding rules and `FINAL`.

| File | Role |
|------|------|
| `out/block.list` | Bare hosts match exactly; leading-dot hosts also match subdomains |

Contents: OISD small + anti-AD + AWAvenue + BM7 Privacy + HaGeZi light + [geekdada DNS filter](https://github.com/geekdada/surge-list), deduplicated and suffix-folded. HaGeZi's wildcard-domain feed retains suffix matching. Exact DOMAIN-SET entries retain exact matching, following the [Surge format](https://manual.nssurge.com/rules/domain.html).

`safebrowsing.googleapis.com` and `safebrowsing.urlsec.qq.com`, their subdomains, and suffix rules covering them are excluded before folding. The existing short-root exclusions in `merge.py` apply after folding. `out/patch-ruleset.list` remains a separate optional BanAD subscription.

Generate with `python3 merge.py`; validate with `python3 -W error -m unittest discover -s tests -v`. Tests use downloaded files in `sources/`. DNS filter is a required source: a download failure stops generation. Broader DNS coverage still requires application-level checks for false positives.
