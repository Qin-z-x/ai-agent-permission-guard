## agent-perm-guard v0.1.0

Audit an AI agent's tool manifest before deploying it. Stdlib-only Python.

### Included

- `python -m agent_perm_guard scan|report <manifest...>` — JSON **and YAML**
  manifests (a small stdlib YAML-subset parser is included), files or
  directories; `--json`, `--fail-on`; exit codes 0/1/2.
- Rules: unrestricted shell/exec, curl-pipe-shell installs, broad filesystem
  write scope, sensitive read paths (`.ssh`, `.aws`, System32, /etc, autostart),
  unrestricted network access, inherited/secret env vars, auto-approve flags,
  destructive tools without confirmation and unpinned container images.
- Weighted risk score (0-100), grade (A-F) and a concrete least-privilege fix
  per finding.
- 38 unit tests (including the YAML parser), GitHub Actions CI on Python
  3.10/3.12, captured evidence over risky and safe sample manifests.

### Honest notes

- This is a manifest auditor, not a runtime sandbox: it reads declared
  permissions and flags risky combinations. It does not disclose a new
  vulnerability and does not claim a new CVE.
- Manifests can lie or be incomplete; pair the audit with OS/container
  sandboxing, egress control and runtime policy enforcement.
