import random
import uuid

from jupyterhub.apihandlers import default_handlers
from jupyterhub.apihandlers.users import UserServerAPIHandler
from jupyterhub.scopes import needs_scope


class UserRandomServerAPIHandler(UserServerAPIHandler):
    """Generate random name for each start. Used for testing"""

    # Example: TOKEN="..."
    # $ curl -X "POST" -H "Authorization: token $TOKEN" -d'{"name": "display", "system": "HDF-Cloud", "vo": "default", "service": "JupyterLab/JupyterLab"}' http://localhost:8000/hub/api/users/demo-user-1@fz-juelich.de/random/server

    # Stop:
    # $ IFS=', ' read -r -a SERVERS <<< $(curl -X "GET" -H "Authorization: token $TOKEN"  http://localhost:8000/hub/api/users/demo-user-1@fz-juelich.de | python3 -c 'import sys, json; d = json.load(sys.stdin) ; print(" ".join(d["servers"].keys()));')
    # for SERVER in "${SERVERS[@]}"; do curl -X "DELETE" -H "Authorization: token $TOKEN" -d'{"remove": true}' http://localhost:8000/hub/api/users/demo-user-1@fz-juelich.de/servers/${SERVER} ; done

    # Cancel:
    # for SERVER in "${SERVERS_A[@]}"; do curl -X "POST" -H "Authorization: token $TOKEN" -d'{"failed": true, "progress": 100, "html_message": "Stop Server"}' http://localhost:8000/hub/api/users/progress/update/demo-user-1@fz-juelich.de/${SERVER} ; done

    # Multiple POST at same time: (-n : number of requests, -c : number of workers run concurrently)
    # wget  https://hey-release.s3.us-east-2.amazonaws.com/hey_linux_amd64 ; mv hey_linux_amd64 /usr/local/bin/hey
    # hey -n 2 -c 1 -m "POST" -H "Authorization: token $TOKEN" -d '{"name": "display", "system": "HDF-Cloud", "vo": "default", "service": "JupyterLab/JupyterLab"}' http://localhost:8000/hub/api/users/demo-user-1@fz-juelich.de/random/server
    @needs_scope("servers")
    async def post(self, user_name):
        c = random.choice("abcdef")
        server_name = f"{c}{uuid.uuid4().hex[:31]}"
        return await super().post(user_name, server_name)


default_handlers.append(
    (r"/api/users/([^/]+)/random/server", UserRandomServerAPIHandler)
)
