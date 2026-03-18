#!/bin/sh
if [[ $INIT_CONTAINER == "true" ]]; then
    echo "Running initialization script once..."
    python3 -u /internal_ssl.py
    chown -R 1000:100 /mnt/persistent/internal-ssl
    chown -R 1000:100 /mnt/shared-data
    chown -R 1000:100 /mnt/persistent
    /bin/bash /check_frontend_files.sh once
    mkdir -p /mnt/shared-data/reservation_key
    cp -rp /mnt/reservation-keypair/..data/* /mnt/shared-data/reservation_key/.
    chown 1000:1000 -R /mnt/shared-data/reservation_key
    chmod 400 /mnt/shared-data/reservation_key/*
    python3 -u /check_incidents_reservations.py 0
elif [[ $CHECK_FRONTEND_FILES == "true" ]]; then
    echo "Running sidecar script in loop to check for frontend updates..."
    /bin/bash /mnt/check_frontend_files/..data/run.sh
elif [[ $CHECK_INCIDENTS_RESERVATIONS == "true" ]]; then
    echo "Running sidecar script in loop to check for incidents and reservations updates..."
    python3 -u /check_incidents_reservations.py ${CHECK_INTERVAL:-60}
elif [[ $CHECK_LIVENESS == "true" ]]; then
    echo "Running sidecar script in loop to check hub liveness..."
    /bin/bash /check_liveness.sh
elif [[ $DIND_CHECK_LIVENESS == "true" ]]; then
    echo "Running sidecar script in loop to check dind liveness..."
    /bin/bash /dind_check_liveness.sh
elif [[ $RESTART_HUB == "true"]]; then
    echo "Running script to restart the hub..."
    /bin/bash restart_hub.sh
elif [[ $RESTART_HUB_INIT == "true" ]]; then
    echo "Running initialization script to restart the hub and pull static files from git..."
    /bin/bash restart_hub_init.sh
elif [[ $RUN_METRICS == "true" ]]; then
    echo "Running script to collect and expose custom metrics..."
    /bin/bash collect_metrics.sh
elif [[ $RUN_USER_KPI == "true" ]]; then
    echo "Running script to collect and expose user KPI metrics..."
    /bin/bash collect_user_kpi.sh
else
    echo "No valid mode specified. Exiting."
    exit 1
fi