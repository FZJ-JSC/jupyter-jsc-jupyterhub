ARG K8S_HUB_VERSION=4.2.0
FROM jupyterhub/k8s-hub-slim:${K8S_HUB_VERSION}
ARG JUPYTERHUB_VERSION=5.4.2
ENV JUPYTERHUB_VERSION=$JUPYTERHUB_VERSION

USER root

COPY devel/requirements_apt.txt /tmp/requirements_apt.txt
RUN apt-get update && \
    cat /tmp/requirements_apt.txt | xargs apt install -yq && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Add requirements
COPY --chown=jovyan:users devel/requirements_build.txt /tmp/requirements_build.txt
RUN /usr/local/bin/pip3 install -r /tmp/requirements_build.txt
COPY --chown=jovyan:users ./requirements.txt /tmp/requirements.txt
RUN /usr/local/bin/pip3 install -r /tmp/requirements.txt

# Install patches for specific JupyterHub Version
RUN apt update && \
    apt install git && \
    git clone -b ${JUPYTERHUB_VERSION} https://github.com/jupyterhub/jupyterhub.git /src/jupyterhub && \
    git clone -b 2.1.0 https://github.com/jupyterhub/traefik-proxy.git /src/traefik-proxy && \
    rm -rf /src/jupyterhub/.git* && \
    apt remove -y git && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* && \
    chown -R jovyan:users /src/jupyterhub && \
    chown -R jovyan:users /src/traefik-proxy
    
COPY --chown=jovyan:users ./patches/patch_files /src/patches/patch_files
COPY --chown=jovyan:users ./patches/patch_files_traefik /src/patches/patch_files_traefik
COPY --chown=jovyan:users ./patches/install_patches.sh /src/patches/install_patches.sh
RUN /src/patches/install_patches.sh

# Add entrypoint
COPY --chown=jovyan:users devel/entrypoint.sh /src/.
RUN chown -R jovyan:users /home/jovyan
ENTRYPOINT ["/src/entrypoint.sh"]
