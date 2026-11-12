#!/usr/bin/env bash
#
# update-requirements.sh — refresh upstream, jjsc, and sidecar Python pins
#
# Usage:
#   ./update-requirements.sh          dry run: print what would change
#   ./update-requirements.sh --yes    apply the changes
#
# How it works:
#   1. Fetches the upstream z2jh hub lock file (REQUIREMENTS_BASE_URL can
#      override its URL), then runs pip-compile in a python:3.14-trixie environment with
#      (in a docker container if docker is available, otherwise in the local
#      python — which is what the GitLab CI image is),
#        input        = unfrozen/requirements-jsc.txt (loose jjsc pins)
#        constraints  = the freshly fetched upstream lock file
#      so shared packages (requests, certifi, ...) keep the upstream versions —
#      no drift — and only packages that are genuinely new for jjsc get fresh
#      versions. If jjsc ever requires a version newer than an upstream pin,
#      pip-compile fails loudly without modifying the requirements.
#   2. Rebuilds the upstream and jjsc sections, retains the manual footer,
#      and synchronizes the sidecar's existing Python pins with the hub.
#   3. Writes a markdown report of pin changes to requirements-update-report.md.
#      The CI job uses it as the merge request description (see create-mr.py).
#
# See also check-requirements.py (standalone drift check, used by CI).

set -euo pipefail
cd "$(dirname "$0")"

REQ=requirements_upstream.txt
UNFROZEN=unfrozen/requirements-jsc.txt
SIDECAR=sidecar/requirements_pip.txt
UPSTREAM_URL=${REQUIREMENTS_BASE_URL:-https://raw.githubusercontent.com/jupyterhub/zero-to-jupyterhub-k8s/main/images/hub/requirements.txt}
# Markdown report of the pin changes (was -> now), used as the merge request
# description (see create-mr.py).
REPORT_FILE=${REPORT_FILE:-requirements-update-report.md}
IMAGE=${PUBPI_IMAGE:-python:3.14-trixie}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

apply=false
[[ "${1:-}" == "--yes" ]] && apply=true

# With docker: compile in the pinned python image. Without docker: assume the
# local python already matches (GitLab CI runs this script inside
# python:3.14-trixie, so no container is needed).
if ! command -v docker >/dev/null; then
    if [[ "$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')" != "3.14" ]]; then
        echo "error: no docker, and local python is not 3.14 — cannot run pip-compile with the pinned interpreter" >&2
        exit 1
    fi
    echo "no docker — running pip-compile with the local python 3.14"
fi

# 1) Fetch and validate the upstream lock before compiling. Do not write any
#    tracked file until all generated outputs have been checked.
mkdir -p "$WORK/unfrozen"
cp "$UNFROZEN" "$WORK/unfrozen/"
python3 - "$UPSTREAM_URL" "$WORK/constraints.txt" <<'PY'
import re
import sys
import urllib.request
from pathlib import Path

url, destination = sys.argv[1:]
text = urllib.request.urlopen(url, timeout=30).read().decode("utf-8")
names = []
for line in text.splitlines():
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    match = re.fullmatch(r"([A-Za-z0-9._-]+)==([^\s#]+)(?:\s+#.*)?", line)
    if not match:
        raise SystemExit(f"invalid line in upstream requirements: {line!r}")
    names.append(re.sub(r"[-_.]+", "-", match.group(1)).lower())
if "jupyterhub" not in names or len(names) != len(set(names)):
    raise SystemExit("invalid upstream requirements: missing jupyterhub or duplicate pins")
Path(destination).write_text(text)
PY

# 2) Compile. PyPI is occasionally flaky — retry once.
if command -v docker >/dev/null; then
    docker run --rm -v "$WORK:/work" -w /work "$IMAGE" bash -c '
      # Pinned version: an unpinned pip-tools can change resolution or output
      # formatting between runs, producing spurious diffs.
      pip install --quiet 'pip-tools==7.6.2' 2>/dev/null
      compile() {
        pip-compile --no-header --no-emit-index-url --strip-extras \
          --constraint /work/constraints.txt \
          -o /work/compiled.txt /work/unfrozen/requirements-jsc.txt
      }
      if ! compile >/dev/null 2>/tmp/pc1.log; then
        echo "pip-compile failed, retrying once (transient PyPI issues)..." >&2
        if ! compile; then
          echo "--- first attempt log ---" >&2
          cat /tmp/pc1.log >&2
          exit 1
        fi
      fi
    '
else
    # Local interpreter (GitLab CI's python:3.14-trixie) — compile in $WORK
    # instead of the container's /work mount point.
    # Pinned version: an unpinned pip-tools can change resolution or output
    # formatting between runs, producing spurious diffs.
    python3 -m pip install --quiet 'pip-tools==7.6.2' 2>/dev/null
    compile() {
      pip-compile --no-header --no-emit-index-url --strip-extras \
        --constraint "$WORK/constraints.txt" \
        -o "$WORK/compiled.txt" "$WORK/unfrozen/requirements-jsc.txt"
    }
    if ! compile >/dev/null 2>/tmp/pc1.log; then
      echo "pip-compile failed, retrying once (transient PyPI issues)..." >&2
      if ! compile; then
        echo "--- first attempt log ---" >&2
        cat /tmp/pc1.log >&2
        exit 1
      fi
    fi
fi

# 3) Rebuild: fetched upstream block + compiled jjsc section + original footer.
python3 - "$REQ" "$WORK/constraints.txt" "$WORK/compiled.txt" > "$WORK/newfile" <<'PY'
import re
import sys

req_path, upstream_path, compiled_path = sys.argv[1:]
text = open(req_path).read()
lines = text.splitlines()

sep = next(i for i, l in enumerate(lines) if l.startswith("# --- jjsc"))
end = next(i for i, l in enumerate(lines) if l.startswith("# Pinned manually"))
upstream = open(upstream_path).read().rstrip().splitlines()
footer = lines[end:]

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

upstream_names = {norm(l.split("==")[0]) for l in upstream if "==" in l and not l.lstrip().startswith("#")}
footer_names = {norm(l.split("==")[0]) for l in footer if "==" in l and not l.lstrip().startswith("#")}
if upstream_names & footer_names:
    raise SystemExit(f"upstream pins conflict with manual footer: {', '.join(sorted(upstream_names & footer_names))}")

# compiled.txt -> normalized name -> [raw_name, version, via-list]
entries, cur = {}, None
for line in open(compiled_path):
    m = re.match(r"^([A-Za-z0-9._\[\]-]+)==(.+)$", line)
    if m:
        cur = [m.group(1), m.group(2), []]
        entries[norm(m.group(1))] = cur
        continue
    if cur is None:
        continue
    m = re.match(r"^    # via (.+)$", line)
    if m:
        cur[2].append(m.group(1).strip())
        continue
    m = re.match(r"^    #   (.+)$", line)
    if m:
        cur[2].append(m.group(1).strip())

# The jjsc section: only packages not already covered by the upstream block
# (shared ones stay there); setuptools belongs in the footer.
R = "-r unfrozen/requirements-jsc.txt"
blocks = []
for n in sorted(entries):
    name, version, via = entries[n]
    if n in upstream_names or n == "setuptools":
        continue
    via = [R if v.startswith("-r") else v for v in via]
    via = sorted(set(via), key=lambda v: (not v.startswith("-r"), v.lower()))
    block = f"{name}=={version}"
    if len(via) == 1:
        block += f"\n    # via {via[0]}"
    elif len(via) > 1:
        block += "\n    # via" + "".join(f"\n    #   {v}" for v in via)
    blocks.append(block)

sys.stdout.write(
    "\n".join(upstream) + "\n\n" + lines[sep] + "\n\n"
    + "\n\n".join(blocks) + "\n\n\n"
    + "\n".join(footer) + "\n"
)
PY

# 4) Match sidecar pins to the newly generated hub requirements.
python3 - "$WORK/newfile" "$SIDECAR" "$WORK/sidecar.txt" <<'PY'
import re
import sys
from pathlib import Path

hub_path, sidecar_path, destination = map(Path, sys.argv[1:])
pattern = re.compile(r"^([A-Za-z0-9._-]+)==([^\s#]+)(.*)$")
def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

hub = {}
for line in hub_path.read_text().splitlines():
    match = pattern.match(line)
    if match:
        name = norm(match.group(1))
        if name in hub:
            raise SystemExit(f"duplicate pin in generated hub requirements: {name}")
        hub[name] = match.group(2)
lines = []
for line in sidecar_path.read_text().splitlines(keepends=True):
    match = pattern.match(line.rstrip("\n"))
    if match:
        name = norm(match.group(1))
        if name not in hub:
            raise SystemExit(f"sidecar pin missing from generated hub requirements: {name}")
        newline = "\n" if line.endswith("\n") else ""
        line = f"{match.group(1)}=={hub[name]}{match.group(3)}{newline}"
    lines.append(line)
destination.write_text("".join(lines))
PY

# Always create a fresh report, even when only the apk updater changes pins.
python3 - "$REQ" "$WORK/newfile" "$SIDECAR" "$WORK/sidecar.txt" "$REPORT_FILE" <<'PY'
import re
import sys
from datetime import datetime, timezone

old_path, new_path, old_sidecar, new_sidecar, report_path = sys.argv[1:]


def pins(path):
    """normalized name -> (raw name, version) for every pin line."""
    out = {}
    for line in open(path):
        m = re.match(r"^([A-Za-z0-9._\[\]-]+)==(.+)$", line)
        if m:
            out[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = (m.group(1), m.group(2))
    return out


def section(title, old_path, new_path):
    old, new = pins(old_path), pins(new_path)
    rows = [
        [new[n][0], old[n][1], new[n][1]]
        for n in sorted(set(old) & set(new))
        if old[n][1] != new[n][1]
    ]
    rows += [[new[n][0], "-", new[n][1]] for n in sorted(set(new) - set(old))]
    rows += [[old[n][0], old[n][1], "-"] for n in sorted(set(old) - set(new))]
    lines = [f"## {title}", ""]
    if rows:
        lines += ["| package | was | now |", "|---|---|---|"]
        lines += [f"| {n} | {o} | {w} |" for n, o, w in rows]
    else:
        lines.append("_no pin changes_")
    return lines + [""]

L = [
    "# Requirements update report - "
    + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    "",
    "Automated by the scheduled `update-requirements` job. This branch/MR "
    "accumulates updates over time - merge when you need them (e.g. due to "
    "a CVE).",
    "",
    "The upstream block is refreshed from the z2jh lock file and the jjsc "
    "section is recompiled against it. Review `overrides.txt` after merging "
    "the updated pins; overrides are not removed automatically.",
    "",
]
L += section("Hub Python pins (`requirements_upstream.txt`)", old_path, new_path)
L += section("Sidecar Python pins (`sidecar/requirements_pip.txt`)", old_sidecar, new_sidecar)
open(report_path, "w").write("\n".join(L))
PY
echo "wrote $REPORT_FILE"
changed=false
for pair in "$REQ:$WORK/newfile" "$SIDECAR:$WORK/sidecar.txt"; do
    old=${pair%%:*}
    new=${pair#*:}
    if diff -u "$old" "$new"; then
        continue
    else
        status=$?
        if [[ $status -ne 1 ]]; then
            exit "$status"
        fi
        changed=true
    fi
done
if $changed && $apply; then
    cp "$WORK/newfile" "$REQ"
    cp "$WORK/sidecar.txt" "$SIDECAR"
    echo "updated $REQ and $SIDECAR"
elif $changed; then
    echo "dry run — re-run with --yes to apply."
else
    echo "no Python requirements changes."
fi
