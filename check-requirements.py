#!/usr/bin/env python3
"""Warning-only drift check for requirements_upstream.txt.

Compares the frozen requirements file against the two things it tracks:

  1. the upstream z2jh hub lock file (images/hub/requirements.txt) — our
     top block is a verbatim copy of it, so drift means upstream changed
     their pins and we should merge those changes;
  2. the jjsc direct pins in unfrozen/requirements-jsc.txt — checks PyPI
     for newer versions within the same major series.

Always exits 0 (it only warns); run it from anywhere, it locates the files
relative to its own path. Set REQUIREMENTS_BASE_URL to mirror the upstream
file if plain HTTPS to GitHub is unavailable.
"""

import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

BASE = Path(__file__).resolve().parent
REQ = BASE / "requirements_upstream.txt"
UNFROZEN = BASE / "unfrozen" / "requirements-jsc.txt"
UPSTREAM_URL = os.environ.get(
    "REQUIREMENTS_BASE_URL",
    "https://raw.githubusercontent.com/jupyterhub/zero-to-jupyterhub-k8s/main/"
    "images/hub/requirements.txt",
)

# Packages that upstream z2jh does not include in its hub lock file, so a
# "new upstream package" would never surface as drift.
KNOWN_EXTRA_UPSTREAM = {
    "python-ldap",  # pulled in by unfrozen/requirements.txt (ldap extra)
    "psycopg2",     # pulled in by unfrozen/requirements.txt (postgres extra)
}

warnings: list[str] = []


def parse(path: Path) -> set[str]:
    """name(lower) -> 'name==version' lines."""
    pins = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9._\[\]-]+)==([^\s#]+)", line)
        if m and not m.group(1).startswith("setuptools"):
            pins[re.sub(r"[-_]+", "-", m.group(1)).lower()] = f"{m.group(1)}=={m.group(2)}"
    return pins


local = parse(REQ)
local_direct = parse(UNFROZEN)


def section_before_separator() -> set[str]:
    """Pins above the jjsc separator (the copied upstream block)."""
    pins = {}
    for line in REQ.read_text().splitlines():
        if line.startswith("# --- jjsc"):
            break
        m = re.match(r"^([A-Za-z0-9._\[\]-]+)==([^\s#]+)", line)
        if m:
            pins[re.sub(r"[-_]+", "-", m.group(1)).lower()] = f"{m.group(1)}=={m.group(2)}"
    return pins


# ---- 1. drift vs upstream z2jh lock file --------------------------------
try:
    raw = urllib.request.urlopen(UPSTREAM_URL, timeout=30).read().decode()
except Exception as exc:  # noqa: BLE001 - warn and continue
    warnings.append(f"could not fetch upstream requirements ({exc}); skipped drift check")
else:
    upstream_lines = raw.splitlines()
    upstream_pins: dict[str, str] = {}
    for line in upstream_lines:
        m = re.match(r"^([A-Za-z0-9._\[\]-]+)==([^\s#]+)", line)
        if m:
            upstream_pins[re.sub(r"[-_]+", "-", m.group(1)).lower()] = (
                f"{m.group(1)}=={m.group(2)}"
            )
    ours = section_before_separator()
    ours_all = set(local)
    for name, pin in sorted(upstream_pins.items()):
        ours_pin = ours.get(name)
        if ours_pin is None:
            if name in ours_all:
                warnings.append(f"{pin}: not in the upstream block of the local file")
            elif name in KNOWN_EXTRA_UPSTREAM:
                pass
            else:
                warnings.append(f"{pin}: new upstream package, not in the local file")
        elif ours_pin != pin:
            warnings.append(f"{ours_pin} vs upstream {pin}")

# ---- 2. newer jjsc versions on PyPI -------------------------------------
# Matches loose series pins like ==2.1.* (and full pins like ==2.1.6);
# the check compares against the latest release in the major.minor series.
for spec in UNFROZEN.read_text().splitlines():
    m = re.match(r"^\s*([A-Za-z0-9._\[\]-]+)==(\d+)\.(\d+)(?:\.\*)?(?:\.\d+)?\s*$", spec)
    if not m:
        continue
    name, major, minor = m.group(1), m.group(2), m.group(3)
    prefix = f"{major}.{minor}."
    try:
        releases = json.loads(
            urllib.request.urlopen(
                f"https://pypi.org/pypi/{quote(name)}/json", timeout=30
            ).read()
        )["releases"]
        latest_in_series = None
        for ver in releases:
            if not ver.startswith(prefix) or re.search(r"[abc]|rc|dev", ver):
                continue  # skip pre-releases
            key = [int(p) for p in re.match(r"\d+[\d.]*", ver).group(0).split(".")]
            if latest_in_series is None or key > latest_in_series[0]:
                latest_in_series = (key, ver)
        cur = local.get(re.sub(r"[-_]+", "-", name).lower())
        if latest_in_series and (cur is None or cur.split("==")[1] != latest_in_series[1]):
            warnings.append(
                f"{name}: {cur or 'not pinned'} -> {latest_in_series[1]} "
                f"(newer {name} in {prefix}* series)"
            )
    except Exception as exc:  # noqa: BLE001 - warn and continue
        warnings.append(f"could not query PyPI for {name} ({exc}); skipped")


now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
if warnings:
    print(f"{now} — requirements drift check: {len(warnings)} warning(s):")
    for w in warnings:
        print(f"  - {w}")
    print("Refresh with ./update-requirements.sh (jjsc section) and/or merge the "
          "upstream block changes (see check output).")
else:
    print(f"{now} — requirements drift check: no drift detected.")
sys.exit(0)
