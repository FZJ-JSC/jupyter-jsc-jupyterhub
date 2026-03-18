FROM python:3.13-alpine3.23 as builder

RUN apk add --no-cache \
    bash git openssh \
    build-base libffi-dev openssl-dev

RUN pip install --prefix=/install \
    jupyterhub \
    kubernetes==33.1.0 \
    aiohttp \
    python-dateutil \
    pyyaml

FROM dhi.io/python:3.13-alpine3.23
COPY --from=builder /install /usr/local
COPY internal_ssl.py /internal_ssl.py
COPY check_frontend_files.sh /check_frontend_files.sh
COPY check_incidents_reservations.py /check_incidents_reservations.py