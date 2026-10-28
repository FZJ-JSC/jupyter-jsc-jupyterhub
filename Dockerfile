# syntax = docker/dockerfile:1.3
# VULN_SCAN_TIME=2026-10-19_05:13:49
# ==========================================================
# Upstream z2jh block - keep in sync with upstream, do not edit freely
# ==========================================================
# Verbatim copy of
#   https://github.com/jupyterhub/zero-to-jupyterhub-k8s/blob/main/images/hub/Dockerfile
# (synced 2026-10-28 from main @ e1606f9)
#
# To update: fetch the upstream file, replace everything from the top of this
# banner to the "jjsc additions" separator below, and re-apply the one
# documented deviation:
#   requirements.txt -> requirements_upstream.txt
# (our frozen copy of the upstream lock file).
#
# All JSC-specific changes (apt extras, version overrides, JupyterHub
# patches) live in the "jjsc" stage below the separator.
# ==========================================================

# The build stage
# ---------------
# This stage is building Python wheels for use in later stages by using a base
# image that has more pre-requisites to do so, such as a C++ compiler.
#
# NOTE: If the image version is updated, also update it in ci/refreeze and
#       singleuser-sample's Dockerfile!
#
FROM python:3.14-trixie as build-stage

# Build wheels
#
# We set pip's cache directory and expose it across build stages via an
# ephemeral docker cache (--mount=type=cache,target=${PIP_CACHE_DIR}). We use
# the same technique for the directory /tmp/wheels.
#
COPY requirements_upstream.txt requirements_upstream.txt
ARG PIP_CACHE_DIR=/tmp/pip-cache
RUN --mount=type=cache,target=${PIP_CACHE_DIR} \
    pip wheel \
        --wheel-dir=/tmp/wheels \
        # pycurl 7.45.3 has wheels, but they aren't portable
        # https://github.com/pycurl/pycurl/issues/834
        --no-binary pycurl \
        -r requirements_upstream.txt \
        # Additional wheels for default-stage. Updates below should be repeated
        # in default-stage.
        #
        py-spy


# The final stage - slim version
# ------------------------------
# This stage is built and published as quay.io/jupyterhub/k8s-hub-slim. It is meant to
# provide no non-essential packages.
#
FROM python:3.14-slim-trixie as slim-stage
ENV DEBIAN_FRONTEND=noninteractive

ARG NB_USER=jovyan \
    NB_UID=1000 \
    HOME=/home/jovyan
RUN adduser \
        --disabled-password \
        --gecos "Default user" \
        --uid ${NB_UID} \
        --home ${HOME} \
        --force-badname \
        ${NB_USER}

RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
        # requirement for pycurl
        libcurl4 \
        # requirement for using postgres database
        libpq5 \
        # requirement for using a local sqlite database
        sqlite3 \
        tini \
 && rm -rf /var/lib/apt/lists/*

# install wheels built in the build stage
# --no-index ensures _only_ wheels from the build stage are installed
COPY requirements_upstream.txt /tmp/requirements_upstream.txt
ARG PIP_CACHE_DIR=/tmp/pip-cache
RUN --mount=type=cache,target=${PIP_CACHE_DIR} \
    --mount=type=cache,from=build-stage,source=/tmp/wheels,target=/tmp/wheels \
    pip install \
        --no-index \
        --find-links=/tmp/wheels/ \
        -r /tmp/requirements_upstream.txt

WORKDIR /srv/jupyterhub
RUN chown ${NB_USER}:${NB_USER} /srv/jupyterhub
USER ${NB_USER}

EXPOSE 8081
ENTRYPOINT ["tini", "--"]
CMD ["jupyterhub", "--config", "/usr/local/etc/jupyterhub/jupyterhub_config.py"]


# The final stage - default version
# ---------------------------------
# We add a few non-critical packages on top of the slim version to provide some
# additional utility.
#
FROM slim-stage as default-stage

USER root

ARG PIP_CACHE_DIR=/tmp/pip-cache
RUN --mount=type=cache,target=${PIP_CACHE_DIR} \
    --mount=type=cache,from=build-stage,source=/tmp/wheels,target=/tmp/wheels \
    pip install \
        --no-index \
        --find-links=/tmp/wheels/ \
        # Updates below should be repeated in build-stage.
        #
        # py-spy is useful for profiling performance of running hubs
        py-spy

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl \
        dnsutils \
        git \
        less \
        vim \
 && rm -rf /var/lib/apt/lists/*

USER ${NB_USER}


# ==========================================================
# jjsc additions (everything below is JSC-specific)
# ==========================================================
# Applied on top of default-stage, in this order:
#   1. apt packages that z2jh's default image does not ship
#   2. version overrides (overrides.txt, e.g. CVE fixes ahead of upstream)
#   3. JupyterHub source clone + jjsc patches (editable install)
#
FROM default-stage as jjsc

USER root

# 1) jjsc apt extras (upstream's own apt list is installed in the block above).
#    grep strips comment lines, xargs -r skips the install for an empty file.
COPY requirements_apt_jjsc.txt /tmp/requirements_apt_jjsc.txt
RUN apt-get update \
 && grep -vE '^\s*#' /tmp/requirements_apt_jjsc.txt | xargs -r apt-get install -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# 2) version overrides (see overrides.txt): install the overridden packages on
#    top of the frozen set, constrained by the frozen file (minus the
#    overridden names, whose locked pins would forbid the bump). No-op while
#    overrides.txt has no pin lines. An override that needs a newer
#    transitive dependency fails the build - add that dependency to
#    overrides.txt as well.
COPY overrides.txt /tmp/overrides.txt
ARG PIP_CACHE_DIR=/tmp/pip-cache
RUN --mount=type=cache,target=${PIP_CACHE_DIR} \
    if grep -qE '^[A-Za-z0-9]' /tmp/overrides.txt; then \
        echo "applying version overrides:" \
        ; grep -E '^[A-Za-z0-9]' /tmp/overrides.txt \
        ; OVERRIDDEN=$(grep -E '^[A-Za-z0-9]' /tmp/overrides.txt | cut -d= -f1 | tr '[:upper:]' '[:lower:]' | sed -E 's/[-_]+/-/g') \
        ; awk -v ovr="$OVERRIDDEN" 'BEGIN{n=split(ovr,a," ");for(i=1;i<=n;i++)seen[a[i]]=1}{if($0~/^[A-Za-z0-9]/){name=$0;sub(/==.*/,"",name);name=tolower(name);gsub(/[-_]+/,"-",name);if(name in seen)next}print}' /tmp/requirements_upstream.txt > /tmp/override-constraints.txt \
        ; pip install \
            -c /tmp/override-constraints.txt \
            -r /tmp/overrides.txt \
    ; fi

# 3) JupyterHub source + jjsc patches. JUPYTERHUB_VERSION is overridable from
#    CI (--build-arg) so the cloned+patched source always matches the
#    jupyterhub pin in requirements_upstream.txt; the default keeps local
#    builds working without the arg.
ARG JUPYTERHUB_VERSION=6.1.1
ENV JUPYTERHUB_VERSION=${JUPYTERHUB_VERSION}
COPY ./patches/patch_files /src/patches/patch_files
COPY ./patches/install_patches.sh /src/patches/install_patches.sh
RUN git -c http.version=HTTP/1.1 clone -b ${JUPYTERHUB_VERSION} https://github.com/jupyterhub/jupyterhub.git /src/jupyterhub && \
    rm -rf /src/jupyterhub/.git* && \
    rm -rf /var/lib/apt/lists/* && \
    chown -R ${NB_USER}:${NB_USER} /src/jupyterhub && \
    chown -R ${NB_USER}:${NB_USER} /src/patches

RUN /src/patches/install_patches.sh

USER ${NB_USER}
