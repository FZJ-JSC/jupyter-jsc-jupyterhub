#!/bin/bash
kubectl patch service hub -n ${TARGET_NAMESPACE} -p '{"spec":{"selector":{"component":"maintenance"}}}'
kubectl rollout restart deployment hub -n ${TARGET_NAMESPACE}
kubectl rollout status deployment hub -n ${TARGET_NAMESPACE}
sleep 10
kubectl patch service hub -n ${TARGET_NAMESPACE} -p '{"spec":{"selector":{"component":"hub"}}}'