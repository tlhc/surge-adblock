# 误报（False Positive / 误杀）调研与放行策略

> 调研日期：2026-09-27（SGT）  
> 设计：`allowlist.txt`（强制从各档 DOMAIN-SET 剔除）+ `allowlist-optional.txt`（默认不剔除）+ `out/allowlist-surge.list`（DIRECT 伴生）

## 机制

| 文件 | 作用 |
|------|------|
| `allowlist.txt` | **强制**：后缀折叠后，从 recommended / lite / aggressive 中移除命中主机 |
| `allowlist-optional.txt` | **可选文档**：默认不参与剔除；需要时手动拷入 `allowlist.txt` 或单独 DIRECT |
| `out/allowlist-surge.list` | 由 forced 导出的 leading-dot DOMAIN-SET，建议 **DIRECT 写在 REJECT DOMAIN-SET 之前** |

**行语义（forced / optional 相同）：**

| 写法 | 含义 |
|------|------|
| `example.com` | 精确匹配该主机 |
| `.example.com` | 后缀放行：`example.com` + 所有子域 |

DOMAIN-SET **没有例外规则**：若父域仍在拦截列表中，仅放行子域无效。登录/CDN 关键路径使用 `.host` 后缀写法。  
`out/patch-ruleset.list` **永不**写入宽 `DOMAIN-KEYWORD`（如 `ad`/`volc`）。

---

## 强制放行清单（摘要）

### CN（anti-AD discretion）

| 域 | 原因 | 来源 |
|----|------|------|
| `mmstat.com` | 优酷播放 / 淘宝验证码 / 阿里系登录 | [discretion/README](https://github.com/privacy-protection-tools/anti-AD/blob/master/discretion/README.md) · [#177](https://github.com/privacy-protection-tools/anti-AD/issues/177) [#261](https://github.com/privacy-protection-tools/anti-AD/issues/261) [#605](https://github.com/privacy-protection-tools/anti-AD/issues/605) [#680](https://github.com/privacy-protection-tools/anti-AD/issues/680) [#959](https://github.com/privacy-protection-tools/anti-AD/issues/959) |
| `shouji.sogou.com` | 搜狗输入法跨屏 / 词库 | anti-AD [#623](https://github.com/privacy-protection-tools/anti-AD/issues/623) [#822](https://github.com/privacy-protection-tools/anti-AD/issues/822) [#952](https://github.com/privacy-protection-tools/anti-AD/issues/952)；[AWAvenue FAQ #45](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/issues/45) |
| `id6.me` / `cmpassport.com` / `auth.wosms.cn` / `enrichgw.10010.com` / `ye.dun.163yun.com` 等 | 运营商**本机号码一键登录** | [discretion/anv.txt](https://github.com/privacy-protection-tools/anti-AD/blob/master/discretion/anv.txt) · [#547](https://github.com/privacy-protection-tools/anti-AD/issues/547) [#866](https://github.com/privacy-protection-tools/anti-AD/issues/866) [#971](https://github.com/privacy-protection-tools/anti-AD/issues/971) |

完整 anv 集合已写入 `allowlist.txt`（含 `config/log/log1.cmpassport.com`、`hmrz.wo.cn`、`mob.com` 等）。

### Global

| 域 | 原因 | 来源 |
|----|------|------|
| `.a.hcaptcha.com` | CAPTCHA 子域被拦 → 人机验证失败 | 多列表命中（本仓库 recommended 曾含此域） |
| `.sgtm.adyen.com` | Adyen 结账分析；拦则银联等支付失败 | [HaGeZi Discussion #9435](https://github.com/hagezi/dns-blocklists/discussions/9435)（`checkoutanalytics-live.adyen.com` 同类） |
| `.aadcdn.msftauth.net` / `.aadcdn.msauth.net` | Microsoft 登录 CDN | [Energized #1017](https://github.com/EnergizedProtection/block/issues/1017) |
| `.login.microsoftonline.com` / `.login.live.com` | Entra / MSA 登录 | [OISD FAQ](https://oisd.nl/faq)（`login.live.com` 属「永不拦」类） |
| `.appleid.apple.com` | Apple ID 认证 | Apple 登录关键路径 |

---

## 可选放行（`allowlist-optional.txt`，默认不剔除）

| 域 | 说明 | 来源 |
|----|------|------|
| `.imasdk.googleapis.com` | IMA 广告 SDK；拦则部分视频播不了 | anti-AD [#1087](https://github.com/privacy-protection-tools/anti-AD/issues/1087) |
| `.activity.windows.com` / `edge.activity.windows.com` | Windows 活动遥测；影响 Edge/Authenticator 同步 | anti-AD [#330](https://github.com/privacy-protection-tools/anti-AD/issues/330) [#401](https://github.com/privacy-protection-tools/anti-AD/issues/401) |
| `.fundingchoices.google.com` | 同意横幅；部分站点视频异常 | [OISD FAQ](https://oisd.nl/faq) |
| `browsercfg-drcn.cloud.dbankcloud.cn` | 华为浏览器；拦则翻译不可用 | anti-AD [#1069](https://github.com/privacy-protection-tools/anti-AD/issues/1069) |
| PayPal `i.paypal.com` 等 | App SMS 争议；CNAME 追踪属性 | [HaGeZi #7685](https://github.com/hagezi/dns-blocklists/issues/7685)（未强制） |

---

## 上游误报模式（调研）

### 过宽 KEYWORD（本流水线已隔离）

- BM7 Advertising：[`HOST-KEYWORD,volc` 误杀火山引擎 #1213](https://github.com/blackmatrix7/ios_rule_script/issues/1213) — 维护者确认上游 KEYWORD 易误伤并移除。
- BanAD / AdvertisingLite 含 `ad`/`ads` 等宽 KEYWORD → **只进统计，不进 DOMAIN-SET / patch**。

### 追踪子域 vs 必需功能同父

- Apple `mzstatic` CDN 被 DNS 列表误拦 → App Store / Music 封面裂图（[AdGuardFilters #172059](https://github.com/AdguardTeam/AdguardFilters/issues/172059)）。
- Microsoft 遥测 `events.data.microsoft.com` → OneDrive 登录失败（[anti-AD #1129](https://github.com/privacy-protection-tools/anti-AD/issues/1129)）— 未进 forced（属遥测）；登录 CDN/路径已 forced。
- 支付分析域（Adyen sGTM）被当纯追踪 → 结账失败（HaGeZi #9435）。

### OISD / HaGeZi / AWAvenue

- OISD：低误报优先；含 `apple.com` / `login.live.com` 等的源列表直接拒绝收录 — [FAQ](https://oisd.nl/faq)。
- HaGeZi：分档越高风险越高；提供 referral allowlist；支付/登录 FP 走 Discussions/Issues。
- AWAvenue：[Knowledge / FAQ](https://awavenue.top/Knowledge.html) — 小米云备份、搜狗输入法（`shouji.sogou.com` / 文档亦写 sougou 拼写）等需自行放行。

---

## 如何添加误报域

1. 抓包确认**具体主机**；确认关掉 DOMAIN-SET 后恢复。  
2. 高置信 / 登录支付验证码 → 写入 `allowlist.txt`（必要时 `.suffix`）。  
3. 争议（广告 SDK / 遥测兼功能）→ `allowlist-optional.txt`，或用户侧单独 DIRECT。  
4. `python3 merge.py` → 看 `out/STATS.md` Allowlist 移除计数；spot-check `recommended.list`。  
5. 可选：Surge 中  
   `DOMAIN-SET,…/allowlist-surge.list,DIRECT`  
   写在广告 REJECT DOMAIN-SET **之前**。  
6. CI（`.github/workflows/update.yml`）每次跑 `merge.py`，forced allowlist 自动生效。
