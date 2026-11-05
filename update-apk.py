#!/usr/bin/env python3
"""Version check + update for the pinned alpine packages of the sidecar image.

Checks sidecar/requirements_apk.txt against the alpine package index of the
alpine release used by sidecar/Dockerfile (parsed from the FROM line),
main + community repos.

Version policy (same as the jupyterhub-outpost image):
  * a newer release with the same leading (first) version number is applied
    automatically (e.g. 2.52.x within 2.x, all 0.x within 0);
  * plain re-releases of the same version (a revision bump, e.g. -r0 -> -r1)
    are applied too - that is how alpine ships security updates;
  * a release with a different leading version number is never applied - it
    is only reported. Review it and bump the pin by hand when you adopt it.

The script is safe to run repeatedly: it always converges to "latest within
series" for the pinned alpine release.

Usage:
  python3 update-apk.py                    dry run (print report only)
  python3 update-apk.py --yes              apply the safe updates in place
  python3 update-apk.py --report-file f    markdown report destination
                                           (default: requirements-update-report.md;
                                           appended when the file already
                                           exists, e.g. written by
                                           update-requirements.sh)

The CI job (update-requirements in .gitlab-ci.yml) runs this on a schedule;
changed pins are committed together with requirements_upstream.txt and
reported in the merge request.
"""
import argparse
import io
import re
import sys
import tarfile
import time
import urllib.request
from datetime import datetime
from datetime import timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
APK_REQ = BASE / "sidecar" / "requirements_apk.txt"
DOCKERFILE = BASE / "sidecar" / "Dockerfile"
ARCH = "x86_64"
REPOS = ("main", "community")

APK_RE = re.compile(r"^([A-Za-z0-9._\[\]-]+)==([^\s#]+)$")

applied = []  # (name, old, new)
pending_major = []  # (name, old, new)
warnings = []


def warn(msg: str) -> None:
    warnings.append(msg)
    print(f"WARNING: {msg}", file=sys.stderr)


def http_get(url: str, timeout: int = 30, attempts: int = 3) -> bytes:
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read()
        except Exception as exc:  # noqa: BLE001 - warn & retry
            last = exc
            if i < attempts - 1:
                time.sleep(2)
    raise last


def parse_pins(path: Path) -> list[tuple[str, str]]:
    pins = []
    for line in path.read_text().splitlines():
        m = APK_RE.match(line)
        if m:
            pins.append((m.group(1), m.group(2)))
    return pins


def alpine_release_from_dockerfile() -> str | None:
    m = re.search(r"alpine(\d+\.\d+)", DOCKERFILE.read_text())
    return m.group(1) if m else None


def apkindex_versions(release: str) -> dict[str, str]:
    """package name -> 'upstream-rRevision' for one alpine release."""
    idx: dict[str, str] = {}
    for repo in REPOS:
        url = (
            f"https://dl-cdn.alpinelinux.org/alpine/v{release}/"
            f"{repo}/{ARCH}/APKINDEX.tar.gz"
        )
        try:
            raw = http_get(url, timeout=60)
        except Exception as exc:  # noqa: BLE001 - warn & continue
            warn(f"alpine: could not fetch {repo} index ({exc}); skipped")
            continue
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                member = next(
                    (m for m in tf.getmembers() if m.name == "APKINDEX"), None
                )
                f = tf.extractfile(member) if member else None
                if f is None:
                    continue
                current = None
                for line in f.read().decode(errors="replace").splitlines():
                    if line.startswith("P:"):
                        current = line[2:].strip()
                    elif line.startswith("V:") and current:
                        idx.setdefault(current, line[2:].strip())
        except Exception as exc:  # noqa: BLE001 - warn & continue
            warn(f"alpine: could not parse {repo} index ({exc}); skipped")
    return idx


def split_apk(v: str) -> tuple[str, str]:
    """'10.2_p1-r0' -> ('10.2_p1', '0'); keeps the last '-r<digits>'."""
    m = re.match(r"^(.*)-r(\d+)$", v)
    return (m.group(1), m.group(2)) if m else (v, "0")


def leading_numeric_tuple(v: str) -> tuple[int, ...]:
    """'10.2_p1' -> (10, 2); '20251016.3.1' -> (20251016, 3, 1)."""
    m = re.match(r"((?:\d+\.)*\d+)", v)
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def check_apk(pins: list[tuple[str, str]]) -> None:
    release = alpine_release_from_dockerfile()
    if not release:
        warn(
            "alpine: could not determine the alpine release from "
            "sidecar/Dockerfile; apk check skipped"
        )
        return
    idx = apkindex_versions(release)
    if not idx:
        warn("alpine: no package index could be fetched; apk check skipped")
        return
    for name, version in pins:
        cur = idx.get(name)
        if cur is None:
            warn(
                f"alpine: {name} not found in the alpine v{release} index "
                "(main/community); skipped"
            )
            continue
        pin_v, _ = split_apk(version)
        idx_v, _ = split_apk(cur)
        pt = leading_numeric_tuple(pin_v)
        it = leading_numeric_tuple(idx_v)
        n = max(len(pt), len(it))
        pt = pt + (0,) * (n - len(pt))
        it = it + (0,) * (n - len(it))
        if it < pt:
            warn(
                f"alpine: {name}=={version} is newer than the alpine repo "
                f"version {cur}; skipped"
            )
            continue
        if it > pt:
            if pt and pt[0] == it[0]:
                applied.append((name, version, cur))
            else:
                pending_major.append((name, version, cur))
        elif cur != version:
            # same version core: alpine re-release (revision bump or build
            # suffix change) - safe to follow
            applied.append((name, version, cur))


def apply_updates(path: Path, updates: dict[str, str]) -> int:
    if not updates:
        return 0
    text = path.read_text()
    lines = text.splitlines()
    changed = 0
    out = []
    for line in lines:
        m = APK_RE.match(line)
        if m and m.group(1) in updates:
            line = f"{m.group(1)}=={updates[m.group(1)]}"
            changed += 1
        out.append(line)
    path.write_text("\n".join(out) + ("\n" if text.endswith("\n") else ""))
    return changed


def build_section(release: str) -> list[str]:
    L = [f"## Sidecar apk (alpine {release})", ""]
    L.append(
        "Pins in `sidecar/requirements_apk.txt` refreshed against the "
        f"alpine v{release} package index (main + community): revision "
        "re-releases and updates within the pinned leading version are "
        "applied automatically."
    )
    L += ["", "### Applied (within the pinned leading version)", ""]
    if applied:
        L += ["| package | was | now |", "|---|---|---|"]
        L += [f"| {n} | {o} | {w} |" for n, o, w in sorted(applied)]
    else:
        L.append("_none - all pins are up to date within their series_")
    L += [
        "",
        "### NOT applied: new leading versions (breaking changes possible)",
        "",
    ]
    if pending_major:
        L += ["| package | current | latest |", "|---|---|---|"]
        L += [f"| {n} | {o} | {w} |" for n, o, w in sorted(pending_major)]
        L += [
            "",
            "_Review manually; bump the pin in `sidecar/requirements_apk.txt` "
            "by hand to adopt a leading version._",
        ]
    else:
        L.append("_none_")
    if warnings:
        L += ["", "### Warnings", ""]
        L += [f"- {w}" for w in warnings]
    L.append("")
    return L


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--yes",
        action="store_true",
        help="apply the safe updates in place (default: dry run)",
    )
    ap.add_argument(
        "--report-file",
        default=str(BASE / "requirements-update-report.md"),
        help="markdown report destination (appended when it already exists)",
    )
    args = ap.parse_args()

    pins = parse_pins(APK_REQ)
    check_apk(pins)
    updates = {n: w for n, o, w in applied}

    if args.yes and updates:
        n = apply_updates(APK_REQ, updates)
        print(f"updated: {n} apk pin(s) in {APK_REQ.name}")
    elif updates:
        print("dry run - re-run with --yes to apply.")

    release = alpine_release_from_dockerfile() or "?"
    report = Path(args.report_file)
    # Write the section when something was applied, or when the report
    # already exists (e.g. from update-requirements.sh in the same CI run)
    # and there are pending majors or warnings worth showing in the MR.
    if applied or (report.exists() and (pending_major or warnings)):
        section = build_section(release)
        if report.exists():
            text = report.read_text().rstrip() + "\n\n" + "\n".join(section)
        else:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            header = [
                f"# Requirements update report - {now}",
                "",
                "Automated by the scheduled `update-requirements` job. This "
                "branch/MR accumulates updates over time - merge when you "
                "need them (e.g. due to a CVE).",
                "",
            ]
            text = "\n".join(header) + "\n" + "\n".join(section)
        report.write_text(text)
        print(f"wrote {report}")

    print(
        f"summary: {len(applied)} apk update(s) applied, "
        f"{len(pending_major)} leading version(s) pending review, "
        f"{len(warnings)} warning(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
