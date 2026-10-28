# Devel image = our own CI-built production image + the layers needed for
# interactive development (dev tooling via apt, pytest/selenium, sshd
# entrypoint).
#
# The base already contains:
#   * the frozen requirements (requirements_upstream.txt: upstream pins +
#     jjsc packages)
#   * the JupyterHub source + installed patches (/src/jupyterhub, patched and
#     installed editable by install_patches.sh)
# so no pip/patch layers are repeated here.
#
# Default base = the latest tagged release, re-published as :latest by the
# "build-tags" job on every tag pipeline.
# Build via CI (buildkit authenticates to CI_REGISTRY via the job's registry
# credentials; the build-devel job passes BASE_IMAGE explicitly), or locally:
#   docker build -f devel/Dockerfile \
#       --build-arg BASE_IMAGE=<registry>/jupyterjsc/k8s/images/jhub:latest \
#       -t devel .
ARG BASE_IMAGE=gitlab.jsc.fz-juelich.de/jupyterjsc/k8s/images/jhub:latest
FROM ${BASE_IMAGE}

USER root

# Dev tooling (vim, git, sshd, ...). The prod image is slim and does not
# include these.
COPY devel/requirements_apt.txt /tmp/requirements_apt.txt
RUN apt-get update && \
    cat /tmp/requirements_apt.txt | xargs apt install -yq && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Test tooling
COPY --chown=jovyan:users devel/requirements_build.txt /tmp/requirements_build.txt
RUN /usr/local/bin/pip3 install -r /tmp/requirements_build.txt

# Add entrypoint (starts sshd, (re)installs the patched JupyterHub editable,
# links /src/jupyterhub-patched and the jjsc config dirs into /home/jovyan)
COPY --chown=jovyan:users devel/entrypoint.sh /src/.
RUN chown -R jovyan:users /home/jovyan
ENTRYPOINT ["/src/entrypoint.sh"]
