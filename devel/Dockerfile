#ARG JUPYTERHUB_VERSION=2.1.1
#FROM jupyterhub/jupyterhub:${JUPYTERHUB_VERSION}
ARG K8S_HUB_VERSION=1.2.0
FROM jupyterhub/k8s-hub:${K8S_HUB_VERSION}
# FROM keyword removes all ARG definitions
ARG JUPYTERHUB_VERSION=2.1.1
ENV JUPYTERHUB_VERSION=$JUPYTERHUB_VERSION

USER root

COPY devel/requirements_apt.txt /tmp/requirements_apt.txt
RUN apt-get update && \
    cat /tmp/requirements_apt.txt | xargs apt install -yq && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

COPY devel/requirements_build.txt /tmp/requirements_build.txt
RUN /usr/local/bin/pip3 install -r /tmp/requirements_build.txt

# Add requirements
COPY --chown=jovyan:users ./requirements.txt /tmp/requirements.txt
RUN /usr/local/bin/pip3 install -r /tmp/requirements.txt

# Add custom files
RUN mkdir -p /src/jupyterhub-custom
COPY --chown=jovyan:users ./custom/${JUPYTERHUB_VERSION} /src/jupyterhub-custom/jsc_custom
RUN /usr/local/bin/pip3 install -r /src/jupyterhub-custom/jsc_custom/requirements.txt

# Install patches for specific JupyterHub Version
RUN apt update && \
    apt install git && \
    git clone -b ${JUPYTERHUB_VERSION} https://github.com/jupyterhub/jupyterhub.git /src/jupyterhub && \
    rm -rf /src/jupyterhub/.git* && \
    apt remove -y git && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* && \
    chown -R jovyan:users /src/jupyterhub
    
COPY --chown=jovyan:users ./patches/${JUPYTERHUB_VERSION}/patch_files /src/patches/${JUPYTERHUB_VERSION}/patch_files
COPY --chown=jovyan:users ./patches/install_patches.sh /src/patches/install_patches.sh
RUN /src/patches/install_patches.sh

# Add entrypoint
COPY --chown=jovyan:users devel/entrypoint.sh /src/.
USER root
ENTRYPOINT ["/src/entrypoint.sh"]
