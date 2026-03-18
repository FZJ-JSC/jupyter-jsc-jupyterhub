#!/bin/bash

DIND_POD=$(kubectl get pods -n $DIND_NAMESPACE -l name=$DIND_DAEMONSET -o jsonpath='{.items[0].metadata.name}')
echo "Monitoring dind pod: $DIND_POD"
while true; do
    if kubectl exec -n $DIND_NAMESPACE $DIND_POD -- docker -H unix:///var/run/dind/docker.sock info >/dev/null 2>&1; then
        echo "[$(date)] dind pod is LIVE"
    else
        echo "[$(date)] dind pod is DOWN, restarting it now"
        kubectl rollout restart daemonset $DIND_DAEMONSET
        sleep 30
        DIND_POD=$(kubectl get pods -n $DIND_NAMESPACE -l name=$DIND_DAEMONSET -o jsonpath='{.items[0].metadata.name}')
    fi
    sleep 30
done