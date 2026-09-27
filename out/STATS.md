# Surge 广告 DOMAIN-SET 合并统计

> 生成时间：**2026-09-27 13:28:19 SGT**
> 脚本：`merge.py`（可重复运行）  
> **默认交付：block** — 效率 + 少误报 + 覆盖（Pareto）

## 三档产物

| 档位 | 文件 | 主机数（折叠后） | 说明 |
|------|------|----------------:|------|
| **block（默认）** | `out/block.list` | **139716** | OISD 底 + anti-AD 差集 + AWAvenue + Privacy 差集 + HaGeZi 差集 |
| lite | `out/lite.list` | **118515** | OISD ∪ AWAvenue ∪ (anti-AD−OISD)，更小 |
| aggressive | `out/aggressive.list` | **309315** | recommended ∪ (BM7 Advertising_Domain 差集)，**误报更高** |

别名（兼容）：`out/merged-lite.list` → lite，`out/merged-aggressive.list` → aggressive。

配套（勿混入 DOMAIN-SET）：`out/patch-ruleset.list` — 仅 BanAD 的 **DOMAIN-SUFFIX**（563 条）；宽 KEYWORD 已排除。

## 上游拉取

| 源 | 状态 | 解析主机数 |
|----|------|----------:|
| OISD small | OK HTTP 200 — 1155882 bytes | 56536 |
| anti-AD surge2 | OK HTTP 200 — 2055996 bytes | 102114 |
| AWAvenue | OK HTTP 200 — 21202 bytes | 958 |
| BM7 Privacy_Domain | OK HTTP 200 — 925782 bytes | 39916 |
| HaGeZi light onlydomains | OK HTTP 200 — 880126 bytes | 44702 |
| BM7 Advertising_Domain | OK HTTP 200 — 5767498 bytes | 285263 |
| BanAD (companion) | OK HTTP 200 — 15550 bytes | KEYWORD=24, SUFFIX=563 |

## recommended 各源「独特贡献」（按并入顺序）

| 源 | 原始主机 | 相对先前集合重叠 | **新加入 recommended** | 备注 |
|----|--------:|----------------:|----------------------:|------|
| OISD small | 56536 | — | **56536** | 国际低误报底座 |
| anti-AD | 102114 | 39110 | **63004** | CN 向差集 |
| AWAvenue | 958 | 771 | **187** | 国产 App |
| Privacy_Domain | 39916 | 35232 | **4684** | 追踪器差集 |
| HaGeZi light | 44702 | 18250 | **26452** | −OISD 后再 −rec |
| BM7 AdvDomain | 285263 | overlap→rec 110686 | aggressive +**174577** | 不进 recommended |

### 按独特增量排序（recommended）

1. **anti-AD surge2** — +63004
2. **OISD small (pikipig)** — +56536
3. **HaGeZi light onlydomains** — +26452
4. **BM7 Privacy_Domain** — +4684
5. **AWAvenue Ads Rule** — +187

## 去重 / 折叠

| 指标 | 数值 |
|------|-----:|
| OISD + anti-AD 朴素相加 | 158650 |
| OISD ∪ anti-AD（集合并，未折叠） | 119540 |
| 相对朴素相加的去重率 | 24.65% |
| recommended 折叠前 | 150863 |
| recommended 后缀折叠后 | 139741 |
| 折叠去掉子域 | 11122 |
| recommended allowlist 后再计 | 139716 |
| recommended allowlist 移除 | 25 |
| lite 折叠后 | 118515 |
| aggressive 折叠后 | 309315 |
| aggressive 相对 recommended 净增 | 169599 |

后缀折叠规则：若集合中已有 `example.com`，则丢弃 `ads.example.com`（由父域 `.example.com` 覆盖）。

## Allowlist 误报剔除（forced）

| 档位 | 移除主机数 | 样例（最多 12） |
|------|----------:|----------------|
| recommended | **25** | `a.hcaptcha.com`, `ac.dun.163.com`, `ac.dun.163yun.com`, `auth.be.sec.miui.com`, `auth.wosms.cn`, `cmpassport.com`, `enrichgw.10010.com`, `fp-upload.dun.163.com`, `hmrz.wo.cn`, `id.mail.wo.cn`, `id6.me`, `images.identity.okta.com` … (+13) |
| lite | **20** | `a.hcaptcha.com`, `auth.be.sec.miui.com`, `auth.wosms.cn`, `config.cmpassport.com`, `enrichgw.10010.com`, `fp-upload.dun.163.com`, `hmrz.wo.cn`, `id.mail.wo.cn`, `id6.me`, `images.identity.okta.com`, `info.pinyin.sogou.com`, `log.cmpassport.com` … (+8) |
| aggressive | **25** | `a.hcaptcha.com`, `ac.dun.163.com`, `ac.dun.163yun.com`, `auth.be.sec.miui.com`, `auth.wosms.cn`, `cmpassport.com`, `enrichgw.10010.com`, `fp-upload.dun.163.com`, `hmrz.wo.cn`, `id.mail.wo.cn`, `id6.me`, `images.identity.okta.com` … (+13) |

- 强制文件：`allowlist.txt` — 条目 30（精确 18 + 后缀根 12）
- 可选文件：`allowlist-optional.txt` — 列出 6 条，**默认不剔除**
- 伴生 DOMAIN-SET：`out/allowlist-surge.list`（12 行，建议 DIRECT 置于 REJECT 之前）
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
