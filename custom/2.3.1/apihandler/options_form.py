import json

from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.scopes import needs_scope
from tornado import web

class SpawnOptionsFormAPIHandler(APIHandler):
    @needs_scope("access:servers")
    async def get(self, user_name, server_name=''):
        user = self.find_user(user_name)
        if user is None:
            # no such user
            self.log.error(f"APICall: SpawnOptionsUpdate - No user {user_name} found",
                extra={
                    "user": user,
                    "log_name": f"{user_name}:{server_name}"
                }
            )
            raise web.HTTPError(404)
        orm_user = user.orm_user

        if server_name not in orm_user.orm_spawners:
            # user has no such server
            self.log.error(f"APICall: SpawnOptionsUpdate - No spawner {server_name} for user {user_name} found",
                extra={
                    "user": user,
                    "spawner": server_name,
                    "log_name": f"{user_name}:{server_name}"
                }
            )
            raise web.HTTPError(404)
        spawner = user.spawners[server_name]
        service_type = spawner.user_options.get("service", "JupyterLab/JupyterLab").split("/")[1]
        tmp = await spawner.get_options_form()
        qargs = self.request.query_arguments
        if "system" in qargs.keys():
            for systemb in qargs["system"]:
                ret = {}
                system = systemb.decode("utf8")
                ret[system] = {
                    "dropdown_lists": {},
                    "resources": {}
                }
                ret[system]["dropdown_lists"]["accounts"] = tmp.get("dropdown_lists", {}).get("accounts", {}).get(system, [])
                ret[system]["dropdown_lists"]["projects"] = tmp.get("dropdown_lists", {}).get("projects", {}).get(system, {})
                ret[system]["dropdown_lists"]["partitions"] = tmp.get("dropdown_lists", {}).get("partitions", {}).get(system, {})
                ret[system]["dropdown_lists"]["reservations"] = tmp.get("dropdown_lists", {}).get("reservations", {}).get(system, {})
                ret[system]["resources"] = tmp.get("resources", {}).get(service_type, {}).get(system, {})
            if type(system) == list:
                system = system[0]
            self.write(json.dumps(ret))
        else:
            self.write(json.dumps(tmp))
