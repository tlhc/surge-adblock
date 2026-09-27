# surge-adblock

面向 **Surge** 的去广告 DOMAIN-SET：合并多源上游、自动驱虫去重、强制白名单，**配置一次，在线自动更新**。

设计目标：单条拦截列表吃掉主要广告/追踪覆盖，少误杀；不叠多份巨量规则。

---

## 快速订阅

> **可见性：** 本仓库为 **private** 时，下方 jsDelivr / 公开 Raw **无法**被 Surge 匿名拉取；在线 DOMAIN-SET 需另行提供可匿名 HTTPS 的镜像，或把仓库改为 public。

> 把下面的 `tlhc` 换成你的 GitHub 用户名或组织名（仓库推送后即可用）。  
> 推荐使用 **jsDelivr**；GitHub Raw 在部分网络下不稳定时可换镜像。

### 主列表（拦截）

| 线路 | 订阅地址 |
|------|----------|
| jsDelivr | `https://cdn.jsdelivr.net/gh/tlhc/surge-adblock@main/out/block.list` |
| GitHub Raw | `https://raw.githubusercontent.com/tlhc/surge-adblock/main/out/block.list` |
| jsDelivr (gcore) | `https://gcore.jsdelivr.net/gh/tlhc/surge-adblock@main/out/block.list` |
| ghproxy 类加速 | `https://ghfast.top/https://raw.githubusercontent.com/tlhc/surge-adblock/main/out/block.list` |

### 白名单（放行，须写在拦截之前）

| 线路 | 订阅地址 |
|------|----------|
| jsDelivr | `https://cdn.jsdelivr.net/gh/tlhc/surge-adblock@main/out/allowlist-surge.list` |
| GitHub Raw | `https://raw.githubusercontent.com/tlhc/surge-adblock/main/out/allowlist-surge.list` |
| jsDelivr (gcore) | `https://gcore.jsdelivr.net/gh/tlhc/surge-adblock@main/out/allowlist-surge.list` |
| ghproxy 类加速 | `https://ghfast.top/https://raw.githubusercontent.com/tlhc/surge-adblock/main/out/allowlist-surge.list` |

格式说明：

- `block.list` / `allowlist-surge.list` 均为 **Surge DOMAIN-SET**（每行一个前导点域名，如 `.example.com`）
- `allowlist.txt` 中的精确主机（不带前导点）只在 merge 时从拦截集合剔除，不导出到 `allowlist-surge.list`；否则加前导点会错误放行其全部子域。需要放行精确主机时，请另加 Surge `DOMAIN,host,DIRECT` 规则。
- 匹配成本低；与文件来自 raw 还是 CDN **无关**，只影响下载稳定性

---

## Surge 配置（在线订阅）

在 `[Rule]` 中、宽泛 `PROXY` / `DIRECT` / `FINAL` **之前**加入（**不要**再叠 anti-AD / BM7 / OISD 原文）：

```ini
# 白名单必须在拦截之前
DOMAIN-SET,https://cdn.jsdelivr.net/gh/tlhc/surge-adblock@main/out/allowlist-surge.list,DIRECT,86400
# 去广告主列表
DOMAIN-SET,https://cdn.jsdelivr.net/gh/tlhc/surge-adblock@main/out/block.list,REJECT-TINYGIF,86400
```

说明：

1. 第四段 `86400` 为更新间隔（秒），与仓库 GitHub Actions **每日更新**对齐；若改为 6 小时构建，可改为 `21600`
2. 策略可用 `REJECT` 或 `REJECT-TINYGIF`（网页图片广告位更友好）
3. 真机请用上表 **HTTPS 订阅地址**，不要使用本机 `file://` 路径

---

## 列表里有什么

| 文件 | 作用 |
|------|------|
| `out/block.list` | 唯一交付的拦截 DOMAIN-SET（约 14 万级主机，随上游变化） |
| `out/allowlist-surge.list` | 强制白名单导出，供 `DIRECT` 前置 |
| `allowlist.txt` | 强制白名单源（merge 时从 block 中剔除并写入上面的导出） |
| `allowlist-optional.txt` | 争议域（默认不剔除，需要可自行并入） |

上游合成（差集合并 + 后缀折叠）：

1. OISD small（国际低误报底座）
2. anti-AD 相对 OISD 的差集（中文区）
3. AWAvenue（国内 App 精打）
4. blackmatrix7 Privacy_Domain 差集（追踪）
5. HaGeZi light onlydomains 差集

误报与加白依据见 [`docs/FALSE_POSITIVES.md`](docs/FALSE_POSITIVES.md)。

---

## 自动更新

仓库内 GitHub Actions：`.github/workflows/update.yml`

- 默认每天定时拉取上游并运行 `python3 merge.py`，更新 `out/*` 后推送 `main`
- 也可在 Actions 页手动 **Run workflow**
- 客户端侧靠 DOMAIN-SET 第四段间隔拉取；**无需**改 Surge 配置

本地重生成：

```bash
python3 merge.py
```

---

## 误杀与反馈

若订阅后出现登录失败、支付中断、验证码/输入法异常：

1. 先确认白名单 DOMAIN-SET 已写在 `block.list` **之前**
2. 在 `allowlist.txt` 增加对应域名（附 `source=` / `reason=`），重新 merge
3. 争议型域名请写入 `allowlist-optional.txt`，不要无依据扩大强制白名单

已知高频误杀域与上游讨论链接见 `docs/FALSE_POSITIVES.md`。

---

## 致谢

- [OISD](https://oisd.nl) / [pikipig/surge-5-anti-ad](https://github.com/pikipig/surge-5-anti-ad)
- [anti-AD](https://github.com/privacy-protection-tools/anti-AD)
- [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)
- [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists)

---

## License

合并脚本与白名单以本仓库为准；各上游列表遵循其原项目许可证，使用前请自行确认。
