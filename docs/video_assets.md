# Video assets: agent-perm-guard

Every quoted output below was captured from the real CLI on the build machine.

## Beat sheet (outputs are captured from real runs)

| time | beat | command | captured output (first line) |
| --- | --- | --- | --- |
| 0:00-0:30 | Hook: the agent manifest grants shell, root writes and secret env | `python -m agent_perm_guard scan examples/risky_agent.yaml` | agent-perm-guard 0.1.0  scan  1 manifest(s) |
| 0:30-1:05 | Gate deployment on the audit | `python -m agent_perm_guard scan examples/risky_agent.yaml --fail-on high` | agent-perm-guard 0.1.0  scan  1 manifest(s) |
| 1:05-1:40 | YAML and JSON manifests both work | `python -m agent_perm_guard scan examples/risky_agent.json` | agent-perm-guard 0.1.0  scan  1 manifest(s) |
| 1:40-2:10 | Least-privilege fixes are printed | `python -m agent_perm_guard report examples/risky_agent.yaml` | agent-perm-guard 0.1.0  scan  1 manifest(s) |
| 2:10-2:35 | Safe manifest is clean; tests | `python -m agent_perm_guard scan examples/safe_agent.json --fail-on low` | agent-perm-guard 0.1.0  scan  1 manifest(s) |

## Real command transcripts for the recording

### 0:00-0:30 -- Hook: the agent manifest grants shell, root writes and secret env

Show the risk score, grade F and the high findings.

```console
$ python -m agent_perm_guard scan examples/risky_agent.yaml
agent-perm-guard 0.1.0  scan  1 manifest(s)
manifest 1/1  examples/risky_agent.yaml                      risk=100 grade=F tools=4 findings=16
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
  HIGH   PERM-AUTO-APPROVE          tool=http_fetch     dangerous tool is auto-appro
... (truncated; full output in docs/EVIDENCE.md)
[exit code: 0]
```

### 0:30-1:05 -- Gate deployment on the audit

`--fail-on high` exits 1 in CI/CD before the agent is deployed.

```console
$ python -m agent_perm_guard scan examples/risky_agent.yaml --fail-on high
agent-perm-guard 0.1.0  scan  1 manifest(s)
manifest 1/1  examples/risky_agent.yaml                      risk=100 grade=F tools=4 findings=16
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
  HIGH   PERM-AUTO-APPROVE          tool=http_fetch     dangerous tool is auto-appro
... (truncated; full output in docs/EVIDENCE.md)
[exit code: 1]
```

### 1:05-1:40 -- YAML and JSON manifests both work

The same policy applies to a JSON manifest; no external YAML dependency.

```console
$ python -m agent_perm_guard scan examples/risky_agent.json
agent-perm-guard 0.1.0  scan  1 manifest(s)
manifest 1/1  examples/risky_agent.json                      risk=100 grade=F tools=4 findings=16
  HIGH   PERM-SHELL                 tool=shell          tool can run shell/exec commands
  HIGH   PERM-PIPE-EXEC             tool=shell          command downloads and executes remote content (curl/wget | sh)
  HIGH   PERM-FS-WRITE-BROAD        tool=shell          filesystem write scope is unbounded (*)
  HIGH   PERM-NETWORK-BROAD         tool=shell          unrestricted network access (no egress allowlist)
  LOW    PERM-SECRET-ENV            tool=shell          environment variables are passed to the tool (review the set)
  HIGH   PERM-AUTO-APPROVE          tool=shell          dangerous tool is auto-approved without human review
  HIGH   PERM-SHELL                 tool=file_writer    tool can run shell/exec commands
  HIGH   PERM-FS-WRITE-BROAD        tool=file_writer    filesystem write scope is unbounded (C:\Users\Public)
  HIGH   PERM-FS-SENSITIVE          tool=file_writer    filesystem scope includes sensitive/credential paths
  HIGH   PERM-AUTO-APPROVE          tool=file_writer    dangerous tool is auto-approved without human review
  HIGH   PERM-NETWORK-BROAD         tool=http_fetch     unrestricted network access (no egress allowlist)
  MEDIUM PERM-SECRET-ENV            tool=http_fetch     secret-like environment variables are exposed to the tool
  HIGH   PERM-AUTO-APPROVE          tool=http_fetch     dangerous tool is auto-appro
... (truncated; full output in docs/EVIDENCE.md)
[exit code: 0]
```

### 1:40-2:10 -- Least-privilege fixes are printed

Each finding carries a concrete fix (narrow the scope, remove secret env, require approval).

```console
$ python -m agent_perm_guard report examples/risky_agent.yaml
agent-perm-guard 0.1.0  scan  1 manifest(s)
manifest 1/1  examples/risky_agent.yaml                      risk=100 grade=F tools=4 findings=16
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
  HIGH   PERM-AUTO-APPROVE          tool=http_fetch     dangerous tool is auto-appro
... (truncated; full output in docs/EVIDENCE.md)
[exit code: 0]
```

### 2:10-2:35 -- Safe manifest is clean; tests

Then run the tests: 38, including the YAML parser and every rule.

```console
$ python -m agent_perm_guard scan examples/safe_agent.json --fail-on low
agent-perm-guard 0.1.0  scan  1 manifest(s)
manifest 1/1  examples/safe_agent.json                       risk=0   grade=A tools=3 findings=0
summary: 1 manifest(s), 0 finding(s): 0 high, 0 medium, 0 low; max risk=0 grade=A
PASS: no finding at or above severity 'low'
[exit code: 0]
```

## Ready files for the edit

- `docs/screenshots/terminal_clean.txt`
- `docs/screenshots/terminal_gate.txt`
- `docs/screenshots/terminal_json.txt`
- `docs/screenshots/terminal_report.txt`
- `docs/screenshots/terminal_scan.txt`
- `docs/screenshots/terminal_tests.txt`
- `docs/EVIDENCE.md`
- `examples/risky_agent.yaml`
- `examples/safe_agent.json`

## OBS/screen-recording notes

- Record a 1920x1080 terminal at 120x32 characters; the commands above fit without wrapping.
- Run every command from the repository root so the relative paths match.
- The JSON runs are for the evidence log only and are not needed on camera.

## Caveats to state on camera

The audit reads declared permissions only; incomplete or dishonest manifests can pass. Pair it with OS/container sandboxing and runtime policy enforcement.
