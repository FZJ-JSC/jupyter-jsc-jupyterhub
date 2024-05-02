ARG K8S_HUB_VERSION=3.3.7
FROM jupyterhub/k8s-hub-slim:${K8S_HUB_VERSION}

USER root

COPY requirements_apt.txt /tmp/requirements_apt.txt
RUN apt-get update && \
    cat /tmp/requirements_apt.txt | xargs apt install -yq && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Install patches for specific JupyterHub Version
RUN apt update && \
    apt install git && \
    git clone -b ${JUPYTERHUB_VERSION} https://github.com/jupyterhub/jupyterhub.git /src/jupyterhub && \
    rm -rf /src/jupyterhub/.git* && \
    apt remove -y git && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* && \
    chown -R jovyan:users /src/jupyterhub

COPY --chown=jovyan:users ./patches/patch_files /src/patches/patch_files
COPY --chown=jovyan:users ./patches/install_patches.sh /src/patches/install_patches.sh
RUN /src/patches/install_patches.sh

# Add requirements
COPY --chown=jovyan:users ./requirements.txt /tmp/requirements.txt
RUN /usr/local/bin/pip3 install -r /tmp/requirements.txt

# Add entrypoint
USER jovyan
