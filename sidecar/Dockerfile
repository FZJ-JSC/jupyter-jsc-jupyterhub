FROM python:3.13-alpine3.23

COPY requirements_apk.txt /tmp/requirements_apk.txt
RUN apk update && xargs -a /tmp/requirements_apk.txt apk add --no-cache

COPY requirements_pip.txt /tmp/requirements_pip.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r /tmp/requirements_pip.txt

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

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]