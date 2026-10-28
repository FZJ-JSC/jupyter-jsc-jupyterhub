#!/usr/bin/env bash
#
# update-requirements.sh — refresh the jjsc section of requirements_upstream.txt
#
# Usage:
#   ./update-requirements.sh          dry run: print what would change
#   ./update-requirements.sh --yes    apply the changes
#
# How it works:
#   1. Runs pip-compile (pip-tools) in a python:3.14-trixie environment with
#      (in a docker container if docker is available, otherwise in the local
#      python — which is what the GitLab CI image is),
#        input        = unfrozen/requirements-jsc.txt (loose jjsc pins)
#        constraints  = the upstream block of requirements_upstream.txt
#      so shared packages (requests, certifi, ...) keep the upstream versions —
#      no drift — and only packages that are genuinely new for jjsc get fresh
#      versions. If jjsc ever requires a version newer than an upstream pin,
#      pip-compile fails loudly: update the upstream block first.
#   2. Replaces everything between the "# --- jjsc customizations" separator
#      and the "# Pinned manually" footer with the compiled entries. The
#      upstream block and the setuptools footer are kept byte-identical.
#
# See also check-requirements.py (standalone drift check, used by CI).

set -euo pipefail
cd "$(dirname "$0")"

REQ=requirements_upstream.txt
UNFROZEN=unfrozen/requirements-jsc.txt
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

# 1) Stage inputs. The jjsc input keeps its canonical path so the generated
#    "# via -r unfrozen/requirements-jsc.txt" comments match, and the
#    constraints file is the upstream block (everything above the separator).
mkdir -p "$WORK/unfrozen"
cp "$UNFROZEN" "$WORK/unfrozen/"
awk '/^# --- jjsc customizations/{exit} {print}' "$REQ" > "$WORK/constraints.txt"

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

# 3) Rebuild: verbatim upstream block + compiled jjsc section + verbatim footer.
python3 - "$REQ" "$WORK/compiled.txt" > "$WORK/newfile" <<'PY'
import re
import sys

req_path, compiled_path = sys.argv[1], sys.argv[2]
text = open(req_path).read()
lines = text.splitlines()

sep = next(i for i, l in enumerate(lines) if l.startswith("# --- jjsc"))
end = next(i for i, l in enumerate(lines) if l.startswith("# Pinned manually"))
upstream, footer = lines[:sep + 1], lines[end:]

def norm(name):
    return re.sub(r"[-_]+", "-", name).lower()

upstream_names = {norm(l.split("==")[0]) for l in upstream if "==" in l}

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
    "\n".join(upstream) + "\n\n"
    + "\n\n".join(blocks) + "\n\n\n"
    + "\n".join(footer) + "\n"
)
PY

if diff -u "$REQ" "$WORK/newfile" > "$WORK/changes.diff"; then
    echo "no changes — the jjsc section is already up to date."
else
    cat "$WORK/changes.diff"
    if $apply; then
        mv "$WORK/newfile" "$REQ"
        echo "updated $REQ"
    else
        echo "dry run — re-run with --yes to apply."
    fi
fi
