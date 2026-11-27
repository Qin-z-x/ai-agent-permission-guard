"""agent-perm-guard: audit AI agent tool manifests for risky permissions."""

from .core import (
    FIXES,
    Finding,
    VERSION,
    audit_data,
    compute_risk,
    iter_manifests,
    load_manifest,
    scan_manifest,
    scan_manifests,
    summarize,
)
from .yaml_lite import YamlError, loads as yaml_loads

__version__ = VERSION
__all__ = [
    "FIXES",
    "Finding",
    "VERSION",
    "YamlError",
    "audit_data",
    "compute_risk",
    "iter_manifests",
    "load_manifest",
    "scan_manifest",
    "scan_manifests",
    "summarize",
    "yaml_loads",
    "__version__",
]
