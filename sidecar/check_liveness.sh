#!/bin/bash

# Initialize failure counter
FAIL_COUNT=0

# Continuous loop to check the target pod's health every 5 seconds
while true; do
    # Check the health of the target pod
    if ! curl --fail --silent --show-error --connect-timeout 5 --max-time 10 "${HEALTH_ENDPOINT}"; then
    echo "$(date) - Health check failed for the hub"
    FAIL_COUNT=$((FAIL_COUNT+1))
    else
    echo "$(date) - Health check passed for the hub"
    FAIL_COUNT=0
    fi

    # If ${LIVENESS_PROBE_NUMBER_OF_FAILS} consecutive failures, restart the target deployment
    if [ $FAIL_COUNT -ge ${LIVENESS_PROBE_NUMBER_OF_FAILS} ]; then
    echo "$(date) - Health check failed ${LIVENESS_PROBE_NUMBER_OF_FAILS} times in a row. Restarting deployment ${TARGET_DEPLOYMENT}..."
    kubectl rollout restart deployment ${TARGET_DEPLOYMENT} -n ${TARGET_NAMESPACE}
    sleep ${LIVENESS_PROBE_INITIAL_DELAY_SECONDS:-30}  # Wait for the pod to restart and become healthy
    FAIL_COUNT=0  # Reset counter after restart
    fi

    sleep ${LIVENESS_PROBE_SLEEP_SECONDS:-5}
done