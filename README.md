# loon-rules

从原始上游生成适用于 Loon 的分流规则集。参考
[shadowrocket-rules](https://github.com/poohyeban/shadowrocket-rules) 的来源结构，
使用独立的 Loon 转换器；不下载它的生成成品进行二次转换。

**每行只有匹配条件，不包含 DIRECT、REJECT、PROXY、出口、节点或策略组。**
策略及规则集顺序由使用者在 Loon 中设置。本仓库不提供完整代理配置、节点订阅、
证书、脚本插件或 DNS 设置。

## 订阅文件

| 文件 | 内容 |
| --- | --- |
| [China.list](https://raw.githubusercontent.com/poohyeban/loon-rules/main/rules/China/China.list) | 中国域名和 IPv4/IPv6 网段 |
| [China-NoResolve.list](https://raw.githubusercontent.com/poohyeban/loon-rules/main/rules/China/China-NoResolve.list) | 相同匹配集合，IP 规则附加 `no-resolve` |
| [OpenAI.list](https://raw.githubusercontent.com/poohyeban/loon-rules/main/rules/OpenAI/OpenAI.list) | OpenAI 域名、所选 ASN 网段、官方 Voice 网段 |
| [OpenAI-NoResolve.list](https://raw.githubusercontent.com/poohyeban/loon-rules/main/rules/OpenAI/OpenAI-NoResolve.list) | 相同匹配集合，IP 规则附加 `no-resolve` |
| [Ad-Domain.list](https://raw.githubusercontent.com/poohyeban/loon-rules/main/rules/AdGuard/Ad-Domain.list) | AdGuard DNS Filter 的可表达域名子集，已处理例外 |

在 Loon 中添加订阅 URL 并自行选择策略即可。`no-resolve` 不只是性能参数：它不为
域名主动查询 DNS 来匹配该 IP 规则，因此两种版本的实际命中行为可能不同。

`Sources/` 保存各来源未经跨来源覆盖去重的 Loon 文件，可独立使用和审计。
聚合文件只移除被同一集合中无条件域名后缀覆盖的域名条目；不跨规则集做去重。

## 上游及生成方式

| 用途 | 原始来源 |
| --- | --- |
| China 域名 | [v2fly release/cn.txt](https://raw.githubusercontent.com/v2fly/domain-list-community/release/cn.txt) |
| OpenAI 域名 | [v2fly data/openai](https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai) |
| China IP | [P3TERX GeoLite2 Country](https://github.com/P3TERX/GeoLite.mmdb)，选择国家码 CN |
| OpenAI ASN IP | 同仓库 GeoLite2 ASN，仅选择 AS401518、AS401864 |
| ChatGPT Voice IP | [官方 JSON](https://openai.com/chatgpt-voice.json) |
| 广告域名 | [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) |
| OpenAI 人工审核域名 | `data/OpenAI/` 中的来源快照减去明确排除项 |

人工审核域名沿用参考仓库的公开快照，最后审核日期保留在文件内；Actions 不抓取
Help Center 页面，也不宣称这部分已自动跟进官网。共享服务商不会被整体加入 OpenAI。

ASN 只采用数据库中实际存在的目标网段；个别目标 ASN 缺失会在转换报告中明确记录，
不会从其他来源补入或沿用旧网段。全部目标 ASN 缺失则阻止发布。

## Loon 转换边界

要求支持逻辑规则的 **Loon 3.1.7 或更新版本**。普通规则使用 `DOMAIN`、
`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR` 和 `IP-CIDR6`。

- 严格子域名用“后缀 AND NOT 根域名”表达，避免加入原规则未匹配的根域名。
- 有限、完整锚定的正则可以精确枚举，最多 1,000 个结果。
- `.+\.` 加有限域名后缀的正则可转换为严格子域名逻辑规则，覆盖当前两条 AWS 正则。
- AdGuard 的 `.example.com^` 按严格子域名处理；可表达例外从所有相交拦截范围中扣除。
- 部分通配例外使用较宽的固定后缀保护范围，可能少拦截，但不因猜测例外而多拦截。
- 无法安全处理的例外、未展开的 `include:`、损坏的上游结构会阻止发布。
- 不能等价转换的普通拦截条目会跳过并完整记录原因。

不输出 `DOMAIN-WILDCARD`、`DOMAIN-REGEX`，不以 URL 正则冒充域名正则。
当前 mihayo CDN 和 OpenAI Web PubSub 的复杂正则仍有缺口。
Voice 网段规则保持原仓库的 IP 匹配范围，不新增未经验证的协议或端口限制。

这是转换器验证与匹配集合验证，**尚未在 iPhone Loon 中完成真机导入、实际命中、
性能及不同域名拒绝模式测试**。尤其是广告逻辑例外，需要使用者结合实际请求记录验证。
不宣称是完整的 AdGuard DNS 引擎。

## 自动更新与复现

Actions 每天在台北时间 05:17、06:43 计划运行，也支持手动触发。GitHub 可能延迟执行。
先测试，再下载、生成、校验、隐私检查，最后仅提交 `rules/` 和 `reports/`。
任何前置失败均不提交生成文件。

- [转换报告](reports/conversion.json)：计数、全部跳过条目及原因。
- [来源与输出摘要](reports/manifest.json)：来源 URL、输入 SHA-256、输出计数及 SHA-256。
- 同一份输入重复生成的规则和报告保持一致，不加入构建时间、本机路径或身份。
- 动态上游的旧字节不保证永久可下载；保留 `build/inputs/` 可进行哈希校验后的离线重建。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -B -m unittest discover -s tests -v
.venv/bin/python -B -m scripts.build
.venv/bin/python -B -m scripts.audit
# 使用已下载且哈希一致的输入重建
.venv/bin/python -B -m scripts.build --offline
```

CI 使用 Python 3.12。有限正则解析依赖 CPython 的解析器接口，升级 Python 时应重新验证测试。

## 隐私与许可

只提交规则、源代码、公开来源快照与报告。环境、原始下载、缓存和日志不入库。
提交使用 GitHub 机器人身份；隐私检查扫描当前文件、全部可达历史和提交身份，
并阻止本机路径、非机器人邮箱及常见凭据模式。自动检查不能保证识别任意形式的秘密。

生成器代码采用 MIT；上游数据的许可和来源归属见 [SOURCES.md](SOURCES.md)。

依据：[Loon 域名规则](https://nsloon.app/docs/Rule/domain_rule/)、
[逻辑规则](https://nsloon.app/docs/Rule/logic_rule/)、
[IP 规则](https://nsloon.app/docs/Rule/ip_rule/)、
[AdGuard DNS 语法](https://adguard-dns.io/kb/general/dns-filtering-syntax/)。
