# JupyterHub for Jupyter-JSC

This repository contains a DockerImage, which is used to provide a JupyterHub.
It is based on the official jupyterhub/k8s-hub image, but installs a few extra packages.

## Requirements updates and merge requests

- The scheduled `update-requirements` CI job refreshes the jjsc section of
  `requirements_upstream.txt` (`update-requirements.sh`) and the sidecar's
  pinned alpine packages (`update-apk.py`, same version policy as the
  jupyterhub-outpost image: in-series updates and revision re-releases are
  applied, new leading versions are only reported). Both keep one
  accumulating merge request on `ci/update-requirements` up to date; its
  description carries a report of the pin changes (was -> now).
- Merge requests may only be merged while their pipeline is green. The
  `check-requirements` job is blocking in merge request pipelines (advisory
  in scheduled/manual ones). To enforce this, protect `main` in the GitLab
  UI: Settings -> Repository -> Protected branches -> `main` ->
  "Pipelines must be successful" (and optionally restrict "Allowed to
  merge" to maintainers).
