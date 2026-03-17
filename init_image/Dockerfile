FROM python:3.13-alpine
RUN apk add bash git openssh
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install jupyterhub kubernetes==33.1.0 aiohttp python-dateutil pyyaml certipy
