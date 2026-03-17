#!/bin/bash

NAME=dev2
HOSTNAME=...

POD_NAME=$(kubectl -n ${NAME} get pods --selector app=jupyterhub,component=hub -o jsonpath="{.items[?(@.status.phase=='Running')].metadata.name}")

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if kubectl -n ${NAME} get pod ${POD_NAME} -o yaml | grep -q "devel"; then
    if [[ ! -f ${DIR}/devel ]]; then
      ssh-keygen -f ${DIR}/devel -t ed25519 
    fi

    KUBERNETES_SERVICE_HOST=$(kubectl -n ${NAME} exec ${POD_NAME} -c hub -- env | grep KUBERNETES_SERVICE_HOST)
    KUBERNETES_SERVICE_HOST=${KUBERNETES_SERVICE_HOST##*=}

    KUBERNETES_SERVICE_PORT=$(kubectl -n ${NAME} exec ${POD_NAME} -c hub -- env | grep KUBERNETES_SERVICE_PORT)
    KUBERNETES_SERVICE_PORT=${KUBERNETES_SERVICE_PORT##*=}

    PROXY_API_SERVICE_HOST=""
    PROXY_API_SERVICE_PORT="8081"
    HUB_SERVICE_PORT=$(kubectl -n ${NAME} get svc hub -o jsonpath='{.spec.ports[0].port}')



    SQL_DATABASE="${NAME}"
    SQL_HOST="postgresql-pooler.database.svc"
    SQL_PORT="5432"
    SQL_PASSWORD=$(kubectl -n ${NAME} get secret ${NAME}.${NAME}.postgresql.credentials.postgresql.acid.zalan.do -o jsonpath='{.data.password}' | base64 -d)
    SQL_USER=$(kubectl -n ${NAME} get secret ${NAME}.${NAME}.postgresql.credentials.postgresql.acid.zalan.do -o jsonpath='{.data.username}' | base64 -d)

    OAUTH_CLIENT_ID=$(kubectl -n ${NAME} get secret unity-secrets -o jsonpath='{.data.client_id}' | base64 -d)
    OAUTH_CLIENT_SECRET=$(kubectl -n ${NAME} get secret unity-secrets -o jsonpath='{.data.client_secret}' | base64 -d)

    CONFIGPROXY_AUTH_TOKEN=$(kubectl -n ${NAME} get secret hub -o 'go-template={{index .data "hub.config.ConfigurableHTTPProxy.auth_token"}}' | base64 -d)

    VARS=$(kubectl -n "${NAME}" get secret generics -o json | jq -r '.data | keys[]')
    # Decode and build the extra JSON lines
    EXTRA_LINES=""
    for VAR in $VARS; do
      VALUE=$(kubectl -n "${NAME}" get secret generics -o jsonpath="{.data.${VAR}}" | base64 -d)
      ESCAPED_VALUE=$(printf '%s' "$VALUE" | jq -R '.')  # Proper JSON escaping
      EXTRA_LINES+="        \"$VAR\": $ESCAPED_VALUE,\n"
    done

    EXTRA_LINES=$(echo -e "$EXTRA_LINES" | sed '$ s/,$//')

    head -n -6 launch.json.template > launch.json
    echo -e "$EXTRA_LINES" >> launch.json
    echo "        \"CUSTOM_CONFIG_PATH\": \"/home/jovyan/jupyterhub_custom_config.yaml\"" >> launch.json
    echo "    }," >> launch.json
    echo "      \"preLaunchTask\": \"delete-tmp-internal-ssl\"," >> launch.json
    echo "      \"justMyCode\": false" >> launch.json
    echo "    }" >> launch.json
    echo "  ]" >> launch.json
    echo "}" >> launch.json

    sed -i -e "s@<NAMESPACE>@${NAME}@g" -e "s@<HOSTNAME>@${HOSTNAME}@g" -e "s@<APP>@${NAME}@g" -e "s@<KUBERNETES_SERVICE_HOST>@${KUBERNETES_SERVICE_HOST}@g" -e "s@<KUBERNETES_SERVICE_PORT>@${KUBERNETES_SERVICE_PORT}@g" -e "s@<OAUTH_CLIENT_ID>@${OAUTH_CLIENT_ID}@g" -e "s@<OAUTH_CLIENT_SECRET>@${OAUTH_CLIENT_SECRET}@g" -e "s@<SQL_PASSWORD>@${SQL_PASSWORD}@g" -e "s@<SQL_DATABASE>@${SQL_DATABASE}@g" -e "s@<SQL_HOST>@${SQL_HOST}@g" -e "s@<SQL_PORT>@${SQL_PORT}@g" -e "s@<SQL_USER>@${SQL_USER}@g" -e "s@<CONFIGPROXY_AUTH_TOKEN>@${CONFIGPROXY_AUTH_TOKEN}@g" -e "s@<PROXY_API_SERVICE_HOST>@${PROXY_API_SERVICE_HOST}@g" -e "s@<PROXY_API_SERVICE_PORT>@${PROXY_API_SERVICE_PORT}@g" -e "s@<HUB_SERVICE_PORT>@${HUB_SERVICE_PORT}@g" ${DIR}/launch.json

    kubectl -n ${NAME} exec ${POD_NAME} -- mkdir -p /home/jovyan/.ssh
    kubectl -n ${NAME} exec ${POD_NAME} -- mkdir -p /home/jovyan/.vscode

    kubectl -n ${NAME} cp ${DIR}/devel.pub ${POD_NAME}:/home/jovyan/.ssh/authorized_keys
    kubectl -n ${NAME} cp ${DIR}/settings.json ${POD_NAME}:/home/jovyan/.vscode/.
    kubectl -n ${NAME} cp ${DIR}/launch.json ${POD_NAME}:/home/jovyan/.vscode/.
    kubectl -n ${NAME} cp ${DIR}/tasks.json ${POD_NAME}:/home/jovyan/.vscode/.

    kubectl -n ${NAME} cp ${DIR}/init.sh ${POD_NAME}:/home/jovyan/init.sh

    # kubectl -n ${NAME} exec ${POD_NAME} -- cp -r /mnt/shared-data/share /home/jovyan/.
    kubectl -n ${NAME} exec ${POD_NAME} -- chown -R jovyan:users /home/jovyan/init.sh
    kubectl -n ${NAME} exec ${POD_NAME} -- bash /home/jovyan/init.sh


    echo "kubectl -n ${NAME} port-forward pod/${POD_NAME} 2222:2222"
else
    echo "${NAME} is not in devel mode. Update here: https://gitlab.jsc.fz-juelich.de/kaas/jupyter/-/tree/jupyter-stag-hubs/${NAME}/z2jh/fleet.yaml"
fi
