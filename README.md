# Surge AI 规则

Mac 和 iOS 使用同一套客户端规则，将 AI 流量交给私有配置中定义的
`SG-Lightsail-via-Zouter` 链式节点。节点凭证、SSH 密钥、MITM 证书和完整个人配置不进入本仓库。
原有 `Rules/Binance.list` 保持原样。

## 订阅

将 [examples/AI-Rules.snippet](examples/AI-Rules.snippet) 中的规则合入现有配置，
不要覆盖整份配置。链式节点需在个人配置中使用 Surge 的 `underlying-proxy` 定义。

| 文件 | 内容 |
| --- | --- |
| [AI-Sukka.list](Rules/AI-Sukka.list) | Sukka AI 域名主表 |
| [AI-Supplement.list](Rules/AI-Supplement.list) | MetaCubeX 的 OpenAI、Anthropic、Gemini 专用补充，去除已被主表覆盖的条目 |
| [AI-Voice-IP.list](Rules/AI-Voice-IP.list) | Sukka 从 OpenAI 官方数据生成的语音 IP；仅与 UDP 3478 条件一起使用 |
| [AI-Sources.json](Rules/AI-Sources.json) | 上游地址、输入与输出 SHA-256、条数及校验信息 |

补充规则包含文件上传、LiveKit、Claude 内容与 MCP 内容、Gemini 辅助接口等域名。
保留 Sukka 本身的范围，包括其 `api.github.com` 规则；因此这不是严格只影响三家应用的白名单。
Sukka 的 Google URL-REGEX 规则依赖客户端已有的 HTTPS 可见性；本仓库不安装或启用 MITM。
Apple Intelligence 使用其他策略，不加入本套补充规则。
Sukka 的 IP 表还包含 ASN 兜底；本项目只提取语音 CIDR，排除的 ASN 记录在来源清单中。

## 自动更新

GitHub Actions 每 6 小时（UTC 00:17、06:17、12:17、18:17；北京时间 08:17、14:17、20:17、02:17）
下载全部上游、运行回归校验，再把生成文件作为一个 Git 提交发布。
可在 Actions 中手动运行 **Update AI rules**。
GitHub 调度可能延迟，不承诺在分钟点准时完成。

Mac/iOS 的三条订阅都设置 `update-interval=21600`，由各自的 Surge 定期下载并缓存；
iOS 需要同步并加载更新后的个人配置。设备离线期间仍使用上次缓存。

每次构建除固定正反样例外，还对全部上游专用域名生成根域名/子域名校验，检查转换和去重后覆盖仍在。
上游下载失败、格式变化、无效规则值、未审阅的新正则、关键域名缺失、共享服务误匹配或条数骤降时，
构建失败且不发布，GitHub 上上一版有效规则继续可用。此流程不需要香港服务器执行分流。

Surge 没有 DOMAIN-REGEX。已知 ChatGPT Azure WebPubSub 动态规则转为限定服务前缀的
DOMAIN-WILDCARD，范围比原先的数字正则略宽；新增正则必须审阅，不会静默丢弃。
样本校验验证规则匹配，不代表已逐一完成真实登录、上传、语音或推理测试。

## 本地验证

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build_ai.py
```

构建器只使用 Python 标准库。生成结果保持稳定；内容没有变化时不会产生新提交。

## 来源与许可

- [SukkaW/Surge](https://github.com/SukkaW/Surge)：AGPL-3.0；
  [AI 域名](https://ruleset.skk.moe/List/non_ip/ai.conf)、[语音 IP](https://ruleset.skk.moe/List/ip/ai.conf)。
- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)：GPL-3.0；
  使用 `sing` 分支的 `openai`、`anthropic`、`google-gemini` 类别。
- [OpenAI 网络说明和语音数据来源](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps)。

新增构建代码及组合规则采用 AGPL-3.0-or-later；上游贡献保留各自版权与许可，
许可全文见 `LICENSE` 和 `licenses/`。此许可说明不改变原有 Binance 文件的权利归属。
