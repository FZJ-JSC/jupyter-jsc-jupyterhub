ARG K8S_HUB_VERSION=3.3.7
FROM jupyterhub/k8s-hub:${K8S_HUB_VERSION}

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

# Add entrypoint
COPY --chown=jovyan:users devel/entrypoint.sh /src/.
USER root
ENTRYPOINT ["/src/entrypoint.sh"]
