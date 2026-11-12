# JupyterHub for Jupyter-JSC

This repository contains a DockerImage, which is used to provide a JupyterHub.
It is based on the official jupyterhub/k8s-hub image, but installs a few extra packages.

## Requirements updates and merge requests

- The scheduled `update-requirements` CI job fetches the latest upstream hub
  lock file, recompiles the jjsc section against it, and synchronizes the
  sidecar's Python pins (`update-requirements.sh`). It also refreshes the sidecar's
  pinned alpine packages (`update-apk.py`, same version policy as the
  jupyterhub-outpost image: in-series updates and revision re-releases are
  applied, new leading versions are only reported). Both keep one
  accumulating merge request on `ci/update-requirements` up to date; its
  description carries a report of the pin changes (was -> now). Overrides are
  left unchanged: review and remove caught-up overrides after updating the
  frozen pins. JupyterHub version updates may also require new patches.
- Merge requests may only be merged while their pipeline is green. The hard
  gates are the build jobs (`build-test`, `build-test-sidecar`). The
  `check-requirements` job is advisory (allow_failure) in all pipelines: it
  compares the frozen pins against live PyPI, so a new upstream release
  would turn every open MR red by the mere passage of time - its drift
  reports are handled by the accumulating update MR instead. To enforce the
  gate, protect `main` in the GitLab UI: Settings -> Repository -> Protected
  branches -> `main` -> "Pipelines must be successful" (and optionally
  restrict "Allowed to merge" to maintainers).
