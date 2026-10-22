# Surge · X / Meta 精简分流规则

2026-10-22 复查。此目录仅为 Surge 规则文件，**没有脚本、模块、MITM、重写、广告劫持或额外远程依赖**。域名规则只用于分流，不会注入或修改流量。

## 订阅地址

X / Twitter（11 条域名规则）：
`https://raw.githubusercontent.com/xytxg/test111/main/surge-x-meta/X.list`

Meta（25 条域名规则，Facebook、Instagram、Threads、WhatsApp、Messenger、Meta AI）：
`https://raw.githubusercontent.com/xytxg/test111/main/surge-x-meta/Meta.list`

可选 Meta IP 版本（额外包含 `IP-ASN,32934,no-resolve`，范围较宽）：
`https://raw.githubusercontent.com/xytxg/test111/main/surge-x-meta/Meta-WithIP.list`

## Surge 配置

在现有的 `[Rule]` 下，`GEOIP` / `FINAL` 之前加入：

```ini
RULE-SET,https://raw.githubusercontent.com/xytxg/test111/main/surge-x-meta/X.list,Proxy,update-interval=86400
RULE-SET,https://raw.githubusercontent.com/xytxg/test111/main/surge-x-meta/Meta.list,Proxy,update-interval=86400
```

`Proxy` 只是示例策略组，**必须替换为你的配置已有的组名**。X、Meta 可以分别设置为不同组，不需要 MITM、脚本或 Rewrite。

## 文件说明

- `X.list`：X/Twitter，仅域名，不包含 Grok/xAI
- `Meta.list`：Meta 社交产品，默认推荐
- `Meta-WithIP.list`：较宽范围，包含 Meta ASN；仅在需要 IP 直连分流时使用
- `Surge-Inline-Proxy.txt`：不需远程加载的内联 `[Rule]` 示例
- `Surge-Remote-Example.txt`：远程订阅示例

没有加入 Facebook 冒充域名、广域云服务 IP 段、`DOMAIN-KEYWORD` 或第三方统计域名。覆盖性不能保证 100%；请根据 Surge 请求日志按需补充，避免扩大匹配范围。

参考 Surge 官方文档：https://manual.nssurge.com/rules/ruleset.html
