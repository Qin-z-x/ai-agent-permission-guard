# ai-agent-permission-guard

[![CI](https://github.com/Qin-z-x/ai-agent-permission-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Qin-z-x/ai-agent-permission-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![stdlib-only core](https://img.shields.io/badge/core-stdlib%20only-brightgreen.svg)](scripts/check_core_deps.py)

**Audit an AI agent's tool manifest before you deploy it.** Agent manifests
declare which tools exist and what they may touch — shell commands, filesystem
scopes, network egress, environment variables, auto-approval. When those
declarations are broad, the agent (or a prompt-injected model) inherits them.
`agent-perm-guard` reads JSON **and YAML** manifests, applies least-privilege
rules, computes a weighted risk score and prints a concrete fix per finding.

```console
$ python -m agent_perm_guard scan examples/risky_agent.yaml
agent-perm-guard 0.1.0  scan  1 manifest(s)
manifest 1/1  examples/risky_agent.yaml                     risk=100 grade=F tools=4 findings=16
  HIGH   PERM-SHELL                 tool=shell          tool can run shell/exec commands
  HIGH   PERM-PIPE-EXEC             tool=shell          command downloads and executes remote content (curl/wget | sh)
  HIGH   PERM-FS-WRITE-BROAD        tool=shell          filesystem write scope is unbounded (*)
  HIGH   PERM-NETWORK-BROAD         tool=shell          unrestricted network access (no egress allowlist)
  LOW    PERM-SECRET-ENV            tool=shell          environment variables are passed to the tool (review the set)
  HIGH   PERM-AUTO-APPROVE          tool=shell          dangerous tool is auto-approved without human review
  HIGH   PERM-SHELL                 tool=file_writer    tool can run shell/exec commands
  HIGH   PERM-FS-WRITE-BROAD        tool=file_writer    filesystem write scope is unbounded (C:/Users/Public)
  HIGH   PERM-FS-SENSITIVE          tool=file_writer    filesystem scope includes sensitive/credential paths
  HIGH   PERM-AUTO-APPROVE          tool=file_writer    dangerous tool is auto-approved without human review
  HIGH   PERM-NETWORK-BROAD         tool=http_fetch     unrestricted network access (no egress allowlist)
  MEDIUM PERM-SECRET-ENV            tool=http_fetch     secret-like environment variables are exposed to the tool
  HIGH   PERM-AUTO-APPROVE          tool=http_fetch     dangerous tool is auto-approved without human review
  HIGH   PERM-SHELL                 tool=backup         tool can run shell/exec commands
  HIGH   PERM-AUTO-APPROVE          tool=backup         dangerous tool is auto-approved without human review
  LOW    PERM-IMAGE-LATEST          tool=backup         container image is not pinned (alpine:latest)
summary: 1 manifest(s), 16 finding(s): 13 high, 1 medium, 2 low; max risk=100 grade=F
```

The safe example is a read-only docs agent with a narrow workspace and an egress
allowlist — it passes the strictest gate:

```console
$ python -m agent_perm_guard scan examples/safe_agent.json --fail-on low
PASS: no finding at or above severity 'low'
```

## Rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `PERM-SHELL` | high | shell/exec capability (`command`, `shell: true`, type shell) |
| `PERM-PIPE-EXEC` | high | `curl ... \| sh`, `wget ... \| bash`, `Invoke-Expression`, `powershell -enc`, `bash -c` |
| `PERM-FS-WRITE-BROAD` | high | write scope `*`, `/`, `C:\`, `~`, `$HOME`, `AppData`, `/Users`, ... |
| `PERM-FS-SENSITIVE` | high | `.ssh`, `.aws`, `.kube`, `.env`, System32, /etc, /proc, autostart, credentials |
| `PERM-NETWORK-BROAD` | high / medium | `network: true`, `*`, `0.0.0.0/0`, `internet`; plaintext `http://` entries medium |
| `PERM-SECRET-ENV` | high / medium / low | inherited environment / secret-like env keys / any env passed |
| `PERM-AUTO-APPROVE` | high / medium | auto-approved dangerous tool / auto-approved tool |
| `PERM-NO-CONFIRMATION` | medium | destructive tool without `requires_confirmation` |
| `PERM-IMAGE-LATEST` | low | container image without a pinned tag (`:latest`) |
| `PERM-UNKNOWN-TOOL-SHAPE` | low | tool without name/permissions; policy cannot be reviewed |

Risk score: `high` 25, `medium` 10, `low` 3, capped at 100. Grades: A (0),
B (1-24), C (25-49), D (50-74), F (75-100). The score is a triage heuristic, not
a measurement of real exploitability.

## YAML and JSON

JSON is parsed with the stdlib `json` module. YAML is parsed with a small
**stdlib-only subset parser** included in the package (`agent_perm_guard/yaml_lite.py`):
mappings, sequences (including sequences of mappings), quoted/plain scalars,
comments, inline lists (`[a, b]`) and inline maps (`{a: b}`). Anchors,
multi-document streams and block scalars are not supported; the parser raises a
clear error instead of guessing.

## Install

```bash
git clone https://github.com/Qin-z-x/ai-agent-permission-guard.git
cd ai-agent-permission-guard
python -m pip install -e .          # optional: installs the agent-perm-guard CLI
```

No runtime dependencies. Python 3.10+.

## CLI

```text
python -m agent_perm_guard scan   <manifest...> [--json] [--fail-on {low,medium,high}]
python -m agent_perm_guard report <manifest...> [--json]
```

Paths may be files or directories (recursive, `.json`/`.yaml`/`.yml`).
Exit codes: `0` success / gate not reached, `1` `--fail-on` threshold reached,
`2` usage error, missing path or malformed manifest.

Typical CI gate:

```bash
python -m agent_perm_guard scan agents/*.yaml --fail-on high
```

## Honest scope and limits

* **Manifest auditor, not a runtime sandbox.** It reads *declared* permissions;
  a tool can do more than its manifest says and a manifest can omit fields.
* Framework dialects vary; the loader understands common `tools`/`functions`
  shapes and ignores unknown fields rather than rejecting them.
* The YAML parser is a subset by design (no anchors/block scalars) — use JSON if
  your manifest needs them.
* The risk score is a prioritisation heuristic, not a CVSS-like metric.
* This does not disclose a new vulnerability and does not claim a new CVE.
* The real controls are runtime: container/seccomp sandbox, mounted filesystems,
  egress policy, per-tool scoped credentials and human approval.

## Tests and CI

```bash
python scripts/check_core_deps.py            # stdlib-only core check
python -m unittest discover -s tests -t .    # 38 tests
python scripts/capture_evidence.py           # regenerate docs/EVIDENCE.md + captures
```

CI (`.github/workflows/ci.yml`) runs on GitHub Actions for Python 3.10 and 3.12:
stdlib-only check, unit tests (including the YAML parser), the JSON/YAML parity
smoke test, the safe-manifest gate and both expected outcomes of `--fail-on high`.

## Suggested GitHub topics

`security`, `llm`, `ai-agents`, `permissions`, `least-privilege`, `audit`, `yaml`,
`python`, `cli`, `mcp`

## 中文简介

**ai-agent-permission-guard**（CLI 名 `agent-perm-guard`）用于在部署 AI Agent 前审计其工具清单
（JSON 或 YAML）：是否存在 shell/exec 能力、`curl | bash` 远程安装、过宽的文件写入范围
（`*`、`/`、`C:\`、`~`、AppData 等）、敏感读取路径（`.ssh`、`.aws`、System32、/etc、自启动目录）、
不受限的网络访问、继承环境变量或暴露密钥、auto-approve 自动批准、破坏性工具缺少人工确认以及
未固定版本的容器镜像。输出加权风险分（0–100）、等级（A–F）和每条发现的**最小权限修复建议**。

核心库**仅使用 Python 标准库**，内置一个小型 YAML 子集解析器（支持映射、序列、标量、注释、
行内列表/映射；不支持锚点与多文档）。提供 `scan` / `report` 两个 CLI 子命令，支持 `--json` 与
`--fail-on` CI 门禁（发现高危返回退出码 1）。本项目是清单审计器，不是运行时沙箱：清单可能不完整
或不诚实，必须配合容器/seccomp、挂载范围、出口策略与最小权限凭据。不声称发现新漏洞或新 CVE。

## 视频演示

B站：https://www.bilibili.com/video/BV1fj1pzfE2W（64 秒）

视频使用本仓库自带的合成/无害样例与真实命令输出；本项目是启发式检测工具，边界见上文说明。

## License

MIT -- see [LICENSE](LICENSE). Prior art acknowledged: OWASP least-privilege and
agentic-AI security guidance, container/network sandboxing practice, and public
agent-tool permission research.

## 系列：LLM 安全防护工具

本项目是「LLM 安全 7 件套」之一：[llm-markdown-xss-guard](https://github.com/Qin-Z-x/llm-markdown-xss-guard)（模型输出 XSS 净化）、[tool-call-arg-guard](https://github.com/Qin-Z-x/tool-call-arg-guard)（工具调用参数注入校验）、[model-pii-redactor](https://github.com/Qin-Z-x/model-pii-redactor)（模型输出 PII/密钥脱敏）、[rag-poison-guard](https://github.com/Qin-Z-x/rag-poison-guard)（RAG 语料投毒扫描）、[llm-sql-injection-guard](https://github.com/Qin-Z-x/llm-sql-injection-guard)（模型生成 SQL 注入 lint）、[llm-file-path-guard](https://github.com/Qin-Z-x/llm-file-path-guard)（生成代码路径穿越扫描）

- GitHub 主页（全部 14 个项目）：https://github.com/Qin-Z-x
- B站演示合集（7 工具 4 分钟）：https://www.bilibili.com/video/BV1jH1pz4ED7

- 7 件套在线索引：https://github.com/Qin-Z-x/llm-security-toolkit （页面：https://qin-z-x.github.io/llm-security-toolkit/）
