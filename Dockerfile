ARG K8S_HUB_VERSION=3.3.7
FROM jupyterhub/k8s-hub-slim:${K8S_HUB_VERSION}

USER root

COPY requirements_apt.txt /tmp/requirements_apt.txt
RUN apt-get update && \
    cat /tmp/requirements_apt.txt | xargs apt install -yq && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Add requirements
COPY --chown=jovyan:users ./requirements.txt /tmp/requirements.txt
RUN /usr/local/bin/pip3 install -r /tmp/requirements.txt

# Add entrypoint
USER jovyan
