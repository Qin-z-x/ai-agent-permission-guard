"""agent_perm_guard core: audit AI agent tool manifests for risky permissions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .yaml_lite import YamlError
from .yaml_lite import load_file as yaml_load_file
from .yaml_lite import loads as yaml_loads

VERSION = "0.1.0"

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES, start=1)}
RISK_WEIGHTS = {"low": 3, "medium": 10, "high": 25}
GRADES = ((0, "A"), (24, "B"), (49, "C"), (74, "D"), (100, "F"))

SHELL_KEYS = ("command", "exec", "execute", "shell", "script", "cmd", "entrypoint")
DANGEROUS_PIPE_RE = re.compile(r"(?i)(?:curl|wget)[^\n|]{0,160}\|\s*(?:ba)?sh\b|invoke-expression|\biex\b|powershell(?:\.exe)?\s+-enc|bash\s+-c\b")
BROAD_SCOPE_RE = re.compile(r"(?i)^(?:\*{1,2}|/|\\|[a-z]:[\\/]?|~/?|\$home/?|%userprofile%|/home/?|/users/?|[a-z]:[\\/]users(?:[\\/].*)?|appdata(?:[\\/].*)?|all|any)$")
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:\.ssh|\.aws|\.gnupg|\.kube|\.env\b|id_rsa|id_ed25519|authorized_keys|credentials|/etc/|"
    r"system32|syswow64|\\windows\\|/proc/|start menu|launchagents|launchdaemons|\.docker/config|\.netrc)"
)
SECRET_ENV_RE = re.compile(r"(?i)(?:token|secret|password|passwd|api[_-]?key|private[_-]?key|credential|access[_-]?key|auth)")
BROAD_NETWORK_VALUES = {"*", "**", "0.0.0.0/0", "::/0", "all", "any", "internet", "unrestricted"}
IMAGE_LATEST_RE = re.compile(r"^[\w./-]+(?::latest)?$")

FIXES = {
    "PERM-SHELL": "Do not expose a raw shell: provide narrow, typed tools (argv lists) and run them in a sandbox without shell=True.",
    "PERM-PIPE-EXEC": "Remove remote-install pipelines (curl | sh). Pin a verified artifact and install it from a reviewed build step, not from the agent.",
    "PERM-FS-WRITE-BROAD": "Narrow the write scope to a dedicated work directory (e.g. ./workspace/**) and mount only that directory into the sandbox.",
    "PERM-FS-SENSITIVE": "Deny credential/system paths explicitly and keep secrets out of the agent's filesystem view; mount only the needed read-only inputs.",
    "PERM-NETWORK-BROAD": "Egress through a proxy with an allowlist of required hostnames; deny everything else, including metadata/private ranges.",
    "PERM-SECRET-ENV": "Do not inherit the environment and do not pass long-lived secrets to tools; use short-lived, scoped credentials issued per call.",
    "PERM-AUTO-APPROVE": "Require human approval for dangerous tools; auto-approve only idempotent, low-impact, read-only tools.",
    "PERM-NO-CONFIRMATION": "Mark destructive tools as requiring confirmation and enforce the flag in the runtime, not only in the manifest.",
    "PERM-IMAGE-LATEST": "Pin container images by digest or immutable tag; ':latest' makes the tool's behaviour change silently.",
    "PERM-UNKNOWN-TOOL-SHAPE": "Give each tool an explicit name and permissions block so the auditor (and the runtime policy) can reason about it.",
}
__all__ = ["Finding", "scan_manifest", "scan_manifests", "audit_data", "compute_risk", "load_manifest", "summarize", "VERSION", "FIXES"]


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    tool: str = ""
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "tool": self.tool,
            "message": self.message,
            "fix": FIXES.get(self.code, ""),
            "data": self.data,
        }


def load_manifest(path) -> dict:
    """Load a JSON or YAML manifest."""
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if file_path.suffix.lower() == ".json":
        payload = json.loads(text)
    else:
        payload = yaml_loads(text)
    if not isinstance(payload, dict):
        raise ValueError("manifest must be a mapping at the top level")
    return payload


def _entries(value) -> list:
    if value is True:
        return ["*"]
    if value in (False, None):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if isinstance(value, dict):
        result = []
        for key, item in value.items():
            if key in ("read", "write", "paths", "allow", "allowlist", "scope", "paths_write", "paths_read"):
                result.extend(_entries(item))
        return result
    return []


def _filesystem(tool: dict, manifest: dict) -> dict:
    permissions = tool.get("permissions") if isinstance(tool.get("permissions"), dict) else {}
    filesystem = permissions.get("filesystem") if isinstance(permissions.get("filesystem"), dict) else {}
    if not filesystem:
        filesystem = permissions.get("fs") if isinstance(permissions.get("fs"), dict) else {}
    if not filesystem:
        filesystem = tool.get("filesystem") if isinstance(tool.get("filesystem"), dict) else {}
    if not filesystem and isinstance(manifest.get("permissions"), dict):
        filesystem = manifest["permissions"].get("filesystem", {}) if isinstance(manifest["permissions"].get("filesystem"), dict) else {}
    return filesystem if isinstance(filesystem, dict) else {}


def _network(tool: dict) -> object:
    permissions = tool.get("permissions") if isinstance(tool.get("permissions"), dict) else {}
    network = permissions.get("network", tool.get("network"))
    if network is None and isinstance(tool.get("egress"), (list, str, bool)):
        network = tool.get("egress")
    return network


def _env(tool: dict) -> object:
    permissions = tool.get("permissions") if isinstance(tool.get("permissions"), dict) else {}
    env = permissions.get("env", tool.get("env", permissions.get("environment")))
    if env is None:
        env = tool.get("environment")
    return env


def _truthy(value) -> bool:
    return value is True or (isinstance(value, str) and value.lower() in ("true", "yes", "on")) or value == 1


def _tools_of(manifest: dict) -> list:
    raw = manifest.get("tools") or manifest.get("functions") or manifest.get("actions") or []
    tools = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                tools.append(item)
    elif isinstance(raw, dict):
        for name, item in raw.items():
            if isinstance(item, dict):
                merged = dict(item)
                merged.setdefault("name", name)
                tools.append(merged)
    return tools


def _audit_tool(tool: dict, manifest: dict) -> list:
    findings = []
    name = str(tool.get("name") or tool.get("id") or "(unnamed)")
    command = tool.get("command") or tool.get("exec") or tool.get("entrypoint") or tool.get("script") or tool.get("cmd")
    shell_flag = _truthy(tool.get("shell")) or str(tool.get("type", "")).lower() in ("shell", "exec", "command")
    has_shell = bool(command) or shell_flag
    auto_approve = _truthy(tool.get("auto_approve")) or _truthy(tool.get("autoApprove")) or _truthy(tool.get("auto_approve_tools")) or _truthy(manifest.get("auto_approve"))
    confirmed = _truthy(tool.get("requires_confirmation")) or _truthy(tool.get("require_confirmation")) or _truthy(tool.get("human_approval")) or _truthy(tool.get("confirm"))

    if has_shell:
        severity = "high" if auto_approve else "high"
        findings.append(
            Finding("PERM-SHELL", severity, "tool can run shell/exec commands", name, {"command": str(command)[:200] if command else True})
        )
    if command and DANGEROUS_PIPE_RE.search(str(command)):
        findings.append(Finding("PERM-PIPE-EXEC", "high", "command downloads and executes remote content (curl/wget | sh)", name, {"command": str(command)[:200]}))

    filesystem = _filesystem(tool, manifest)
    read_entries = _entries(filesystem.get("read")) + _entries(filesystem.get("read_paths")) + _entries(filesystem.get("paths_read"))
    write_entries = _entries(filesystem.get("write")) + _entries(filesystem.get("write_paths")) + _entries(filesystem.get("paths_write"))
    if not write_entries:
        write_entries = _entries(tool.get("write_scope")) + _entries(filesystem.get("scope"))
    if write_entries:
        broad = [entry for entry in write_entries if BROAD_SCOPE_RE.match(entry.strip())]
        if broad:
            findings.append(Finding("PERM-FS-WRITE-BROAD", "high", "filesystem write scope is unbounded (%s)" % ", ".join(broad[:3]), name, {"scope": broad[:10]}))
    sensitive = [entry for entry in read_entries + write_entries if SENSITIVE_PATH_RE.search(entry)]
    if sensitive:
        findings.append(Finding("PERM-FS-SENSITIVE", "high", "filesystem scope includes sensitive/credential paths", name, {"paths": sensitive[:10]}))

    network = _network(tool)
    if network is not None:
        entries = _entries(network)
        broad_network = [entry for entry in entries if entry.strip().lower() in BROAD_NETWORK_VALUES]
        if network is True or broad_network:
            findings.append(Finding("PERM-NETWORK-BROAD", "high", "unrestricted network access (no egress allowlist)", name, {"network": entries[:5] or True}))
        else:
            suspicious = [entry for entry in entries if entry.startswith("http://")]
            if suspicious:
                findings.append(Finding("PERM-NETWORK-BROAD", "medium", "plaintext http:// egress entry", name, {"network": suspicious[:5]}))

    env = _env(tool)
    if env is not None:
        if env is True or (isinstance(env, str) and env.strip().lower() in ("*", "inherit", "all")):
            findings.append(Finding("PERM-SECRET-ENV", "high", "tool inherits the full environment (secrets included)", name, {"env": "inherit"}))
        else:
            env_count = len(_entries(env)) if not isinstance(env, dict) else len(env)
            secret_keys = []
            if isinstance(env, dict):
                secret_keys = [str(key) for key in env if SECRET_ENV_RE.search(str(key))]
            else:
                secret_keys = [entry for entry in _entries(env) if SECRET_ENV_RE.search(entry)]
            if secret_keys:
                findings.append(Finding("PERM-SECRET-ENV", "medium", "secret-like environment variables are exposed to the tool", name, {"env": secret_keys[:10]}))
            elif env_count:
                findings.append(Finding("PERM-SECRET-ENV", "low", "environment variables are passed to the tool (review the set)", name, {"count": env_count}))

    if auto_approve and (has_shell or write_entries or network is not None):
        findings.append(Finding("PERM-AUTO-APPROVE", "high", "dangerous tool is auto-approved without human review", name))
    elif auto_approve:
        findings.append(Finding("PERM-AUTO-APPROVE", "medium", "tool is auto-approved", name))

    dangerous = has_shell or bool([entry for entry in write_entries if BROAD_SCOPE_RE.match(entry.strip())]) or (network is True)
    if dangerous and not confirmed and not auto_approve:
        findings.append(Finding("PERM-NO-CONFIRMATION", "medium", "destructive tool has no confirmation flag", name))

    image = tool.get("image") or tool.get("docker") or tool.get("container")
    if isinstance(image, str) and image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
        findings.append(Finding("PERM-IMAGE-LATEST", "low", "container image is not pinned (%s)" % image, name, {"image": image}))

    if not name or name == "(unnamed)" or not (has_shell or filesystem or network is not None or env is not None):
        findings.append(Finding("PERM-UNKNOWN-TOOL-SHAPE", "low", "tool has no explicit name/permissions; policy cannot be reviewed", name))
    return findings


def audit_data(manifest: dict) -> dict:
    """Audit a parsed manifest and return the finding list."""
    findings = []
    for tool in _tools_of(manifest):
        findings.extend(_audit_tool(tool, manifest))
    top_auto = _truthy(manifest.get("auto_approve")) and not _tools_of(manifest)
    if top_auto:
        findings.append(Finding("PERM-AUTO-APPROVE", "high", "manifest auto-approves every action", "(manifest)"))
    if not _tools_of(manifest):
        findings.append(Finding("PERM-UNKNOWN-TOOL-SHAPE", "low", "manifest declares no tools/functions", "(manifest)"))
    return findings


def compute_risk(findings) -> dict:
    score = min(sum(RISK_WEIGHTS[finding.severity] for finding in findings), 100)
    grade = "F"
    for threshold, letter in GRADES:
        if score <= threshold:
            grade = letter
            break
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    max_severity = "none"
    for severity in SEVERITIES:
        if counts[severity]:
            max_severity = severity
    return {"score": score, "grade": grade, "counts": counts, "total": len(findings), "max_severity": max_severity}


def summarize(findings) -> dict:
    return compute_risk(findings)


def _scan_file(path) -> dict:
    manifest = load_manifest(path)
    findings = audit_data(manifest)
    risk = compute_risk(findings)
    return {
        "path": Path(path).as_posix(),
        "name": str(manifest.get("name") or Path(path).name),
        "tools": len(_tools_of(manifest)),
        "findings": [finding.to_dict() for finding in findings],
        "risk": risk,
    }


def iter_manifests(paths) -> list:
    manifests = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in (".json", ".yaml", ".yml"):
                    manifests.append(child)
        elif path.is_file():
            manifests.append(path)
        else:
            raise FileNotFoundError(str(path))
    return manifests


def scan_manifest(path) -> dict:
    return _scan_file(path)


def scan_manifests(paths) -> dict:
    reports = [_scan_file(path) for path in iter_manifests(paths)]
    totals = {severity: 0 for severity in SEVERITIES}
    score = 0
    for report in reports:
        for severity in SEVERITIES:
            totals[severity] += report["risk"]["counts"][severity]
        score = max(score, report["risk"]["score"])
    grade = "F"
    for threshold, letter in GRADES:
        if score <= threshold:
            grade = letter
            break
    return {
        "tool": "agent-perm-guard",
        "version": VERSION,
        "summary": {
            "manifests": len(reports),
            "findings": sum(totals.values()),
            "counts": totals,
            "max_risk_score": score,
            "max_grade": grade,
        },
        "manifests": reports,
        "clean": sum(totals.values()) == 0,
    }
