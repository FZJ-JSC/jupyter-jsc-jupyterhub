#!/usr/bin/env python3
"""Drift check for requirements_upstream.txt.

Compares the frozen requirements file against the things it tracks:

  1. the upstream z2jh hub lock file (images/hub/requirements.txt) — our
     top block is a verbatim copy of it, so drift means upstream changed
     their pins and we should merge those changes;
  2. the jjsc direct pins in unfrozen/requirements-jsc.txt — checks PyPI
     for newer versions within the same major series;
  3. sidecar/requirements_pip.txt — must track the main file's versions;
  4. overrides.txt — pins that deliberately deviate from the frozen file
     (e.g. a CVE fix ahead of upstream); warns once the frozen file has
     caught up and the override can be removed again.

Exits 1 when drift is detected (CI pairs that with allow_failure, so the
pipeline is not blocked); run it from anywhere, it locates the files
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
SIDECAR = BASE / "sidecar" / "requirements_pip.txt"
OVERRIDES = BASE / "overrides.txt"
UPSTREAM_URL = os.environ.get(
    "REQUIREMENTS_BASE_URL",
    "https://raw.githubusercontent.com/jupyterhub/zero-to-jupyterhub-k8s/main/"
    "images/hub/requirements.txt",
)

# Upstream z2jh packages we intentionally do not pin in this project; a name
# here silences the "new upstream package" warning for it.
KNOWN_EXTRA_UPSTREAM = {
    "python-ldap",  # pulled in by unfrozen/requirements.txt (ldap extra)
    "psycopg2",     # pulled in by unfrozen/requirements.txt (postgres extra)
}

warnings: list[str] = []


def parse(path: Path, skip_setuptools: bool = True) -> set[str]:
    """name(lower) -> 'name==version' lines (setuptools skipped by default)."""
    pins = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9._\[\]-]+)==([^\s#]+)", line)
        if m and (not skip_setuptools or not m.group(1).startswith("setuptools")):
            pins[re.sub(r"[-_]+", "-", m.group(1)).lower()] = f"{m.group(1)}=={m.group(2)}"
    return pins


local = parse(REQ)
local_direct = parse(UNFROZEN)
main_all = parse(REQ, skip_setuptools=False)


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
upstream_pins: dict[str, str] = {}
try:
    raw = urllib.request.urlopen(UPSTREAM_URL, timeout=30).read().decode()
except Exception as exc:  # noqa: BLE001 - warn and continue
    warnings.append(f"could not fetch upstream requirements ({exc}); skipped drift check")
else:
    upstream_lines = raw.splitlines()
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
    for name in sorted(set(ours) - set(upstream_pins)):
        warnings.append(
            f"{ours[name]}: in local upstream block, but no longer in upstream z2jh lock file"
        )

# ---- 2. newer jjsc versions on PyPI -------------------------------------
# Matches loose series pins like ==2.1.* or major-only pins like ==35.*
# (and full pins like ==2.1.6); the check compares against the latest
# release in the pinned major.minor (or major) series.
for spec in UNFROZEN.read_text().splitlines():
    m = re.match(r"^\s*([A-Za-z0-9._\[\]-]+)==(\d+)(?:\.(\d+))?(?:\.\*)?(?:\.\d+)?\s*$", spec)
    if not m:
        continue
    name, major, minor = m.group(1), m.group(2), m.group(3)
    prefix = f"{major}.{minor}." if minor else f"{major}."
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


# ---- 3. sidecar pins must track the main frozen file --------------------
# sidecar/requirements_pip.txt pins a subset of the hub packages so both
# images ship the same versions; any version mismatch (or a sidecar pin
# missing from the main file) is drift.
if SIDECAR.exists():
    for name, pin in sorted(parse(SIDECAR, skip_setuptools=False).items()):
        main_pin = main_all.get(name)
        if main_pin is None:
            warnings.append(f"{pin}: sidecar pin not present in requirements_upstream.txt")
        elif main_pin.split("==")[1] != pin.split("==")[1]:
            warnings.append(f"{name}: sidecar {pin.split('==')[1]} vs main {main_pin.split('==')[1]}")


# ---- 4. overrides: flag the ones that can be removed again --------------
# Every pin in overrides.txt is a deliberate deviation from the frozen file
# (e.g. a CVE fix that upstream has not shipped yet). Once the frozen file
# has caught up to (or past) the overridden version, the override is just
# drift and should be deleted again.
def vkey(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v)) or (0,)


if OVERRIDES.exists():
    for line in OVERRIDES.read_text().splitlines():
        m = re.match(r"^\s*([A-Za-z0-9._\[\]-]+)==([^\s#]+)", line)
        if not m:
            continue
        name = re.sub(r"[-_]+", "-", m.group(1)).lower()
        ovr_ver = m.group(2)
        frozen_pin = main_all.get(name)
        if frozen_pin is not None:
            if vkey(frozen_pin.split("==")[1]) >= vkey(ovr_ver):
                warnings.append(
                    f"overrides.txt: {name}=={ovr_ver} can be removed - "
                    f"the frozen file is already at {frozen_pin.split('==')[1]}"
                )
        elif upstream_pins:
            up_pin = upstream_pins.get(name)
            if up_pin is not None and vkey(up_pin.split("==")[1]) >= vkey(ovr_ver):
                warnings.append(
                    f"overrides.txt: {name}=={ovr_ver} can be removed - "
                    f"upstream z2jh is already at {up_pin.split('==')[1]}"
                )


now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
if warnings:
    print(f"{now} — requirements drift check: {len(warnings)} warning(s):")
    for w in warnings:
        print(f"  - {w}")
    print("Refresh with ./update-requirements.sh (jjsc section), merge the "
          "upstream block changes, and/or remove overrides.txt entries that "
          "are no longer needed (see check output).")
    sys.exit(1)
else:
    print(f"{now} — requirements drift check: no drift detected.")
    sys.exit(0)
