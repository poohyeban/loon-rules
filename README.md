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
| [WhatsApp.list](https://raw.githubusercontent.com/poohyeban/loon-rules/main/rules/WhatsApp/WhatsApp.list) | WhatsApp 独立域名分类 |
| [Instagram.list](https://raw.githubusercontent.com/poohyeban/loon-rules/main/rules/Instagram/Instagram.list) | Instagram 独立域名分类 |
| [Facebook.list](https://raw.githubusercontent.com/poohyeban/loon-rules/main/rules/Facebook/Facebook.list) | Facebook 独立域名分类；不额外合入 Messenger、Threads、Oculus |

在 Loon 中添加订阅 URL 并自行选择策略即可。`no-resolve` 不只是性能参数：它不为
域名主动查询 DNS 来匹配该 IP 规则，因此两种版本的实际命中行为可能不同。

`Sources/` 保存各来源未经跨来源覆盖去重的 Loon 文件，可独立使用和审计。
聚合文件只移除被同一集合中无条件域名后缀覆盖的域名条目；不跨规则集做去重。

## 上游及生成方式

| 用途 | 原始来源 |
| --- | --- |
| China 域名 | [v2fly release/cn.txt](https://raw.githubusercontent.com/v2fly/domain-list-community/release/cn.txt) |
| OpenAI 域名 | [v2fly data/openai](https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai) |
| WhatsApp / Instagram / Facebook 主源 | v2fly 的 `data/whatsapp`、`data/instagram`、`data/facebook` |
| 三个服务的辅助核对与补充 | [SukkaW/Surge 原始 global.conf](https://github.com/SukkaW/Surge/blob/master/Source/non_ip/global.conf)，按服务边界筛选 Facebook 分区 |
| China IP | [P3TERX GeoLite2 Country](https://github.com/P3TERX/GeoLite.mmdb)，选择国家码 CN |
| OpenAI ASN IP | 同仓库 GeoLite2 ASN，仅选择 AS401518、AS401864 |
| ChatGPT Voice IP | [官方 JSON](https://openai.com/chatgpt-voice.json) |
| 广告域名 | [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) |
| OpenAI 人工审核域名 | `data/OpenAI/` 中的来源快照减去明确排除项 |

人工审核域名沿用参考仓库的公开快照，最后审核日期保留在文件内；Actions 不抓取
Help Center 页面，也不宣称这部分已自动跟进官网。共享服务商不会被整体加入 OpenAI。

ASN 只采用数据库中实际存在的目标网段；个别目标 ASN 缺失会在转换报告中明确记录，
不会从其他来源补入或沿用旧网段。全部目标 ASN 缺失则阻止发布。

### WhatsApp、Instagram、Facebook 的分类与匹配

三份主源在一次构建中使用同一个 v2fly 提交；Sukka 也固定到本次获取的提交。
Actions 每次重新取得上游版本，报告保存提交号、实际下载 URL 和 SHA-256。
这三份文件目前只有域名规则，不需要重复生成内容相同的 `NoResolve` 版本。

- 复用现有 Loon 转换器：精确域名保持 `DOMAIN`，后缀保持 `DOMAIN-SUFFIX`；
  有限正则按下述转换边界处理，严格子域名条件跳过并记录，不把精确域名扩大成后缀。
- Sukka 的 Facebook 分区包含多个产品；根据主源覆盖关系和
  [审核映射](data/Meta/sukka-review.json) 将适用条目归入三个服务。
  `instagr.am` 是 Instagram 的辅助补充。未审核的新根域名记入报告待确认，
  已归类域名下的新子域名可自动处理，不直接吞入整个综合分区。
- Sukka 的 `facebook`、`whatsapp` 品牌关键词可能匹配无关域名，故记录后排除；
  Messenger、Threads、Oculus 和 Meta 综合站点不从该辅助分区额外引入。
  主源分类保持原意，不声称每个被收录域名都是服务正常运行必需的域名。
- 同一服务内合并两源、去除相同行及被后缀完整覆盖的条目；不为跨文件去重
  而删除独立订阅需要的匹配条件。Sukka 删除条目后，不会由审核映射重新注入。
- 不添加整个 Meta ASN、共享 CDN 的总域名或旧版 WhatsApp IP 大段。
  本次交付为域名分类，不保证覆盖仅有目标 IP 的语音、视频或其他连接。
- 主源出现未展开的 `include:`、辅助分区消失或分类歧义时阻止发布；
  不支持的正则与未分类辅助条目在转换报告中列出，不伪造等价转换。

## Loon 转换边界

发布文件仅使用 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`
和 `IP-CIDR6`，**不输出 `AND`、`OR`、`NOT`**。原有订阅 URL 保持不变。

- 无法由普通规则严格表达的子域名条件跳过并记录，不扩大为包含根域名的后缀。
- 有限、完整锚定的正则可以精确枚举，最多 1,000 个结果。
- 包含 `.+`、`.*` 等无限匹配的正则不展开；当前两条 AWS 正则也跳过。
- 人工审核来源中的 `*.example.com` 保留在原始快照，但不生成逻辑规则或更宽的后缀。
  该范围可能由独立上游的普通规则覆盖；未覆盖部分明确记入转换报告。
- AdGuard 的 `.example.com^` 拦截条目跳过；例外只在生成阶段计算。
  任何与例外相交的拦截规则整条撤掉，接受少拦截，避免误伤白名单。
  严格子域名例外可参与内部集合判断，但绝不发布为逻辑规则。
- 部分通配例外使用较宽的固定后缀保护范围，可能少拦截，但不因猜测例外而多拦截。
- 无法安全处理的例外、未展开的 `include:`、损坏的上游结构会阻止发布。
- 不能等价转换的普通拦截条目会跳过并完整记录原因。

不输出 `DOMAIN-WILDCARD`、`DOMAIN-REGEX`，不以 URL 正则冒充域名正则。
当前 mihayo CDN 和 OpenAI Web PubSub 的复杂正则仍有缺口。
Voice 网段规则保持原仓库的 IP 匹配范围，不新增未经验证的协议或端口限制。

2026-10-03 的单机对照测试中，加入一条纯域名 `AND/NOT` 嵌套规则后，X 首次
加载从不超过 1 秒变为约 7 秒，删除后恢复；尚未确定 Loon 内部具体等待原因，
也不据此断言所有版本或所有逻辑规则都有问题。本项目因此采用无逻辑规则的兼容策略。
生成器与发布审计都会拒绝逻辑规则，防止定时更新重新引入。

自动检查验证转换边界、例外保护及输出一致性，**不能替代新版完整清单的 iPhone
导入、实际命中、性能及不同域名拒绝模式测试**，仍需使用者结合实际请求记录验证。
不宣称是完整的 AdGuard DNS 引擎。

## 自动更新与复现

Actions 每天在台北时间 05:17、06:43 计划运行，也支持手动触发。GitHub 可能延迟执行。
先测试，再下载、生成、离线复现校验、隐私检查，最后仅提交 `rules/` 和 `reports/`。
任何前置失败均不提交生成文件。

- [转换报告](reports/conversion.json)：计数、全部跳过条目及原因。
- [来源与输出摘要](reports/manifest.json)：来源 URL、已固定的 Git 提交、输入 SHA-256、输出计数及 SHA-256。
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
