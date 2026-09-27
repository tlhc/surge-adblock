# surge-adblock

Surge ad-blocking DOMAIN-SET. No allowlist.

```ini
DOMAIN-SET,https://raw.githubusercontent.com/tlhc/surge-adblock/main/out/block.list,REJECT,86400
```

The policy name is yours. `86400` is the update interval in seconds. Put this line in `[Rule]` before `PROXY`, `DIRECT`, and `FINAL`.

| File | Role |
|------|------|
| `out/block.list` | Block list. One leading-dot host per line |

Contents: OISD small ∪ (anti-AD − OISD) ∪ AWAvenue ∪ (BM7 Privacy − current set) ∪ (HaGeZi light − current set), then suffix fold.
