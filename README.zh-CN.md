# agentwatchdog

**面向终端 AI 编码 agent 的宿主机侧运行审计。不装 hook、不套 wrapper、被监控方无法退出——只读 `/proc`，绝不碰你的 prompt。**

> **状态**：功能已完备，目前正与前身工具在一台生产 VPS 上并行烧机验证，
> 结束后打 `v0.1.0`。仅支持 Linux。
>
> [31582749.xyz](https://31582749.xyz/zh/) &middot; [English](README.md)

---

## 要解决的问题

你在服务器上跑 AI 编码 agent——挂在 cron 里、跑在 CI 里、通过 SSH 远程会话、或在多人共用的机器上。迟早你会问出这些问题：

- 凌晨三点是谁在这台机器上启动了 agent？被哪个父进程拉起来的？
- 是不是有个脚本在死循环地重启 agent，一直在烧 API 费用？
- 六小时前那个非交互 agent 是挂死了，还是还在干活？
- 一个根本不该用 agent 的账号，是不是刚刚跑了一个？

现有的可观测性工具回答的是另一个问题——*我花了多少 token？*——而且全部站在 **agent 内部**回答：要你启用 OTel exporter、要你装 hook、要你记得用 wrapper 命令、要你把流量路由过代理。

这有一个结构性弱点：**被监控的东西必须配合**。不设那个环境变量、不装那个 hook、直接调用二进制——工具就瞎了。而跑飞的 cron、配错的服务、越权的用户，恰恰是永远不会配合的那些。

## 做法

agentwatchdog 站在 **agent 外部**、从操作系统层面观察。systemd timer 每分钟跑一次单趟扫描：读 `/proc`、按指纹识别 agent 进程、记录谁在跑什么。

| | agent 内部工具（OTel / hook / wrapper） | agentwatchdog |
|---|---|---|
| 观察位置 | agent 进程内部 | 宿主机 `/proc` |
| 能否被绕过 | 能——不配合即失效 | 不能——进程存在就能看见 |
| 依赖 | collector / Docker / Node 包 | 无：Python 3 标准库 + systemd |
| prompt 内容 | 部分工具读会话记录 | 绝不读取，落盘前先脱敏 |
| 回答的问题 | token、成本、会话细节 | 谁在跑 / 跑什么 / 谁拉起的 / 行为正常吗 |
| 服务对象 | 键盘前的开发者 | 主机的运维者 |

两种视角是互补的。想要按 token 计费的仪表盘，请用 OTel 系工具——本项目不做那个。这里做的是主机的审计日志。

## 快速开始

一个文件，除 `python3` 外零依赖：

```sh
curl -fsSLO https://github.com/Ymakercc/agentwatchdog/releases/latest/download/agentwatchdog.pyz
chmod +x agentwatchdog.pyz

# 先看清它会记录什么，再决定要不要装：
./agentwatchdog.pyz dry-run

# 在你自己的机器上现场验证脱敏承诺：
./agentwatchdog.pyz selftest

# 觉得可以，再正式安装：
sudo mv agentwatchdog.pyz /usr/local/bin/agentwatchdog
sudo agentwatchdog install        # systemd timer + 配置 + logrotate
```

也可从源码安装：`pip install .`（PyPI 发布随 `v0.1.0` 一起）。

`dry-run` 什么都不写——连日志目录都不建——也什么都不发。它的存在就是为了让你在生产机上先看到完整输出，再决定信不信任这个工具。

## 能检测什么

| 告警 | 级别 | 含义 |
|---|---|---|
| `unexpected_user` | critical | 白名单外的账号跑了 agent。带 `loginuid`，所以「alice 通过 sudo 以 root 身份跑了 agent」是一条明确告警，不是谜题 |
| `parent_spawn_storm` | critical | 同一个父进程持续拉起 agent。人类不会这么干——这是重启循环，每次尝试都在计费。判据是*连续多次扫描*而不是数启动次数，所以比扫描间隔更快的循环照样抓得到。告警携带父进程的完整祖先链 |
| `user_high_frequency` | warning | 一个账号启动 agent 的速度远超人手输入 |
| `long_running_process` | warning | 非交互 agent 超时未退——大概率挂死 |
| `high_cpu` / `high_mem` | warning | 持续性资源异常（生命周期均值，启动瞬间的峰值不会误报） |
| `agents_during_high_load` | warning | 主机已经过载时还有多个 agent 挤进来 |

告警追加写入本地 `alerts.jsonl`，**默认不外发**。需要投递时通过 `NOTIFY` 显式开启：

- `exec` —— 把告警 JSON 从 stdin 灌给你已有的任何命令（Telegram bot、`mail`、你的告警平台）。设计上不经过 shell。
- `webhook` —— POST JSON 到 HTTPS 端点。明文 HTTP 直接拒绝而不是警告：告警里有用户名、路径和进程树。

## 隐私：用代码强制，不靠承诺

这个工具靠读命令行吃饭，所以约束是硬性的，并作为 CI 的独立 job 阻断发布：

1. **绝不打开 `/proc/PID/environ`。** 有一条测试记录扫描期间的每一次 `open()`，该文件一旦出现即失败。环境变量里的 API key 不可能经此泄露。
2. **prompt 永不落盘。** 命令行在写入*之前*就按 agent 规则脱敏——因为每家 CLI 放 prompt 的位置都不同（`claude -p "…"`、`codex exec "…"`、`aider -m "…"`）。
3. **位置参数默认拒绝。** 除非指纹明确列为安全字面量（如子命令名），一律打码；未知 flag 按布尔量处理，其后的 token 同样打码。新出的 agent、或某次升级挪动了 prompt 位置，都漏不出去。
4. **形似凭证的值在任何位置都会被打码**——各家 key 前缀、JWT、长不透明 token。
5. **允许离开主机的数据从构造上就是匿名的。** `export` 输出计数与时间桶，按固定形状拼装并在*运行时*对照 key 白名单校验——证明不了匿名的导出直接拒绝，而不是发布出去。

命令行只保留摘要，用于关联相同调用。摘要是 HMAC，密钥每台主机单独生成、存在日志目录之外、永不导出——因为一个普通哈希紧挨着 `codex exec <redacted>` 放着，等于告诉对方命令的形状、只剩提示词要猜，猜一次算一次哈希就能确认。没有密钥就不写摘要：退回无密钥哈希是唯一不能做的事。

在你自己的机器上跑 `agentwatchdog selftest`，亲眼看这些承诺对真实运行中的 agent 成立。

## 支持的 agent

检测是数据而非代码：每个 agent 是 `agents.d/` 里的一份 JSON 指纹，运维者可在 `/etc/agentwatchdog/agents.d/` 添加或覆盖指纹，不必等新版本。

| Agent | 识别 | flag 表 |
|---|---|---|
| Claude Code | ✅ | **已对真机核验** |
| OpenAI Codex CLI | ✅ | **已对真机核验** |
| aider | ✅ | **已对 0.86.2 核验** |
| Gemini CLI | ✅ | 按文档编写（best-effort） |
| OpenCode | ✅ | 按文档编写（best-effort） |

「best-effort」损失的是细节，绝不是隐私：认不出的参数一律打码而不是打印。两个真机核验抓到的坑，说明这类表不能凭记忆写：Codex 在*顶层*就接受位置 prompt，不只在 `exec` 之后；Codex 的 `-p` 是 `--profile`，而 Claude Code 的 `-p` 是 prompt——把一家的规则搬给另一家会静默泄露。添加或修正指纹见 [CONTRIBUTING.md](CONTRIBUTING.md)，这是本项目最欢迎的 PR。

## 配置

`/etc/agentwatchdog.conf`，扁平 `KEY=VALUE`，每次扫描重读，SSH 里用 `vi` 就能改。默认值保证新装机器安静：不外发、无用户白名单（写下谁属于这台机器，检查才启用）、阈值宽松不狼来了。

最常改的几项：

```ini
ALLOWED_USERS=root deploy          # 留空 = 不启用 unexpected_user 检查
PERSISTENT_REGEX=remote-control    # 额外豁免的常驻会话
MAX_RUNTIME_SEC=14400              # 单趟 agent 超过 4h 视为挂死
NOTIFY=jsonl                       # 追加 exec 和/或 webhook 以外发
```

## 边界与诚实的局限

- **仅 Linux。** 设计本身就*是* `/proc`。macOS（`libproc`）在路线图上；不打算支持 Windows。
- **进程级，不是内容级。** 它告诉你 agent *跑过*、谁跑的、表现如何——刻意不告诉你*它被问了什么*。
- **它是采样的。** 每 `--interval` 秒（默认 60 秒，对齐到整分钟）拍一张快照。在两次扫描之间起止的 agent 不会被看见，所以短命一次性调用的计数是下界。重启循环的判定不依赖抓到其中任何一次尝试，而且风暴告警会附上内核的 fork 速率，让你看到进程列表看不到的量级。
- **只观察，不拦截。** 这是审计辅助，不是沙箱，更不是防线：root 可以像停任何 systemd 单元一样停掉它。
- **仅用于你拥有或获授权审计的主机。** 它在设计上就不适合暗中监视人——没有 prompt、没有击键、没有文件内容——让它变成那种东西的贡献会被拒绝。见 [SECURITY.md](SECURITY.md)。

## 许可证

Apache-2.0。agentwatchdog 是独立项目，与 Anthropic、OpenAI、Google 或任何 agent 厂商无隶属或背书关系；产品名称仅用于指认被观察的软件。
