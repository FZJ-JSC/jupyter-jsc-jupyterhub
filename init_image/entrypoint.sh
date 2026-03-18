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
fi