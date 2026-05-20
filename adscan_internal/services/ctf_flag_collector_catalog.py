"""Static catalogs for the CTF flag collector.

Pure data, no logic. Adding a new alternative path or a new excluded
walk directory should never require touching the orchestrator or the
strategy implementations — extend the tuples here and the rest of the
collector picks the change up automatically.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Strategy 2 — Alternative known paths (host-global, owner-independent).
# ---------------------------------------------------------------------------

ALTERNATIVE_FLAG_PATHS: tuple[str, ...] = (
    # Root of C: — common in beginner THM and crafted boxes.
    r"\C$\flag.txt",
    r"\C$\root.txt",
    r"\C$\user.txt",
    r"\C$\system.txt",
    r"\C$\proof.txt",
    # Public desktop — multi-user CTF setups.
    r"\C$\Users\Public\Desktop\flag.txt",
    r"\C$\Users\Public\Desktop\root.txt",
    r"\C$\Users\Public\Desktop\user.txt",
    r"\C$\Users\Public\flag.txt",
    # Web roots — IIS / XAMPP / Apache CTFs.
    r"\C$\inetpub\wwwroot\flag.txt",
    r"\C$\inetpub\wwwroot\user.txt",
    r"\C$\xampp\htdocs\flag.txt",
    # ProgramData.
    r"\C$\ProgramData\flag.txt",
    r"\C$\ProgramData\root.txt",
)


# Per-owner alternative path templates. ``{user}`` is filled at runtime.
PER_OWNER_ALTERNATIVE_TEMPLATES: tuple[str, ...] = (
    r"\C$\Users\{user}\Documents\flag.txt",
    r"\C$\Users\{user}\Documents\proof.txt",
    r"\C$\Users\{user}\Documents\user.txt",
    r"\C$\Users\{user}\Documents\root.txt",
    r"\C$\Users\{user}\flag.txt",
)


def build_alternative_candidates(
    users: tuple[str, ...] | list[str],
    *,
    max_total: int = 30,
) -> list[tuple[str, str, str | None]]:
    """Build ``(path, kind, owner)`` triples for the alternative strategy.

    Args:
        users: Candidate owner names for per-owner templates.
        max_total: Hard cap on total alternative paths (keeps latency bounded).

    Returns:
        List of ``(share_path, kind, owner_or_None)``. ``kind`` is inferred
        from the filename so the panel can display it accurately.
    """
    out: list[tuple[str, str, str | None]] = []

    for path in ALTERNATIVE_FLAG_PATHS:
        kind = _kind_from_basename(path)
        out.append((path, kind, None))

    for user in users:
        for template in PER_OWNER_ALTERNATIVE_TEMPLATES:
            path = template.format(user=user)
            kind = _kind_from_basename(path)
            out.append((path, kind, user))

    if len(out) > max_total:
        out = out[:max_total]
    return out


# ---------------------------------------------------------------------------
# Strategy 3 — Bounded SMB walk configuration.
# ---------------------------------------------------------------------------

WALK_DEPTH: int = 4
WALK_MAX_ENTRIES: int = 2000
WALK_MAX_FILE_SIZE: int = 1024
WALK_TIMEOUT_SECONDS: float = 18.0

# Roots launched in parallel — each gets its own ``list_r`` invocation.
WALK_ROOTS: tuple[str, ...] = (
    r"\C$\\",
    r"\C$\Users\\",
    r"\C$\inetpub\\",
    r"\C$\xampp\\",
)

# Directory names skipped by the walk (case-insensitive match on basename).
# Each of these is enormous on a typical Windows host; they never carry
# CTF flags.
WALK_EXCLUDE_DIRS: tuple[str, ...] = (
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "$Recycle.Bin",
    "$WinREAgent",
    "$SysReset",
    "Recovery",
    "PerfLogs",
    "Microsoft",          # under ProgramData — huge, no flags
    "Package Cache",      # under ProgramData
    "WindowsApps",
    "SystemApps",
    "Microsoft.NET",
    "assembly",
)

# Filename extensions considered for flag candidates.
WALK_FLAG_EXTENSIONS: tuple[str, ...] = (".txt", ".flag")

# Exact filenames that are always plausible flag candidates.
WALK_FLAG_EXACT_NAMES: frozenset[str] = frozenset(
    {"user.txt", "root.txt", "system.txt", "flag.txt", "proof.txt"}
)

# Filename noise — names that match the extension filter but are
# extremely unlikely to carry a flag and are common on Windows.
WALK_NAME_NOISE: frozenset[str] = frozenset(
    {
        "readme.txt",
        "license.txt",
        "eula.txt",
        "changelog.txt",
        "install.txt",
        "history.txt",
        "version.txt",
        "manifest.txt",
        "desktop.ini",
        "thumbs.db",
    }
)

# Wildcard pattern: ``*flag*.txt`` (case-insensitive).
_FLAG_WILDCARD_RE = re.compile(r"flag", re.IGNORECASE)


def is_flag_candidate_name(name: str, *, size: int) -> bool:
    """Return True if the filename pattern + size look like a flag.

    Args:
        name: Basename only (no path).
        size: File size in bytes.
    """
    if not name:
        return False
    if size < 0 or size > WALK_MAX_FILE_SIZE:
        return False
    lname = name.lower()
    if lname in WALK_NAME_NOISE:
        return False
    if lname in WALK_FLAG_EXACT_NAMES:
        return True
    # extension gate
    if not any(lname.endswith(ext) for ext in WALK_FLAG_EXTENSIONS):
        return False
    if _FLAG_WILDCARD_RE.search(lname):
        return True
    return False


def _kind_from_basename(path: str) -> str:
    """Infer the flag kind from the file basename.

    Returns one of ``user``, ``root``, ``system``, ``flag``, ``proof``,
    ``unknown``.
    """
    base = path.rsplit("\\", 1)[-1].lower()
    if base.startswith("user"):
        return "user"
    if base.startswith("root"):
        return "root"
    if base.startswith("system"):
        return "system"
    if base.startswith("proof"):
        return "proof"
    if "flag" in base:
        return "flag"
    return "unknown"


__all__ = [
    "ALTERNATIVE_FLAG_PATHS",
    "PER_OWNER_ALTERNATIVE_TEMPLATES",
    "WALK_DEPTH",
    "WALK_MAX_ENTRIES",
    "WALK_MAX_FILE_SIZE",
    "WALK_TIMEOUT_SECONDS",
    "WALK_ROOTS",
    "WALK_EXCLUDE_DIRS",
    "WALK_FLAG_EXTENSIONS",
    "WALK_FLAG_EXACT_NAMES",
    "WALK_NAME_NOISE",
    "build_alternative_candidates",
    "is_flag_candidate_name",
]
