# ---- Builder stage (normal Alpine) ----
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

# ---- Final hardened image ----
FROM dhi.io/python:3.13-alpine3.23

COPY --from=builder /install /usr/local
