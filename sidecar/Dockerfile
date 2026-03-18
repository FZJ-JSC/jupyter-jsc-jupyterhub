FROM python:3.13-alpine3.23 as builder

RUN apk add --no-cache \
    bash coreutils curl git kubectl openssh \
    postgresql-client \
    build-base libffi-dev openssl-dev

RUN pip install --prefix=/usr/local \
    jupyterhub \
    kubernetes==33.1.0 \
    aiohttp \
    python-dateutil \
    pyyaml

FROM dhi.io/python:3.13-alpine3.23

# Copy packages from builder
COPY --from=builder /usr/local /usr/local
COPY --from=builder /bin/sh /bin/sh
COPY --from=builder /bin/bash /bin/bash
COPY --from=builder /usr/bin /usr/bin

COPY internal_ssl.py /internal_ssl.py
COPY check_frontend_files.sh /check_frontend_files.sh
COPY check_incidents_reservations.py /check_incidents_reservations.py
COPY check_liveness.sh /check_liveness.sh
COPY dind_check_liveness.sh /dind_check_liveness.sh
COPY restart_hub.sh /restart_hub.sh
COPY restart_hub_init.sh /restart_hub_init.sh
COPY collect_metrics.sh /collect_metrics.sh
COPY collect_user_kpi.sh /collect_user_kpi.sh
COPY entrypoint.sh /entrypoint.sh

# RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]