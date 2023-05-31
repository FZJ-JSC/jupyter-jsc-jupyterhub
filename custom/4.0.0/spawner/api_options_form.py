import json

from jupyterhub.apihandlers import default_handlers
from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.scopes import needs_scope
from tornado import web

from ..misc import get_custom_config


class SpawnOptionsFormAPIHandler(APIHandler):
    @needs_scope("access:servers")
    async def get(self, user_name, server_name=""):
        user = self.find_user(user_name)
        if user is None:
            # no such user
            self.log.error(
                f"APICall: SpawnOptionsUpdate - No user {user_name} found",
                extra={"user": user, "log_name": f"{user_name}:{server_name}"},
            )
            raise web.HTTPError(404)
        orm_user = user.orm_user

        if server_name not in orm_user.orm_spawners:
            # user has no such server
            self.log.error(
                f"APICall: SpawnOptionsUpdate - No spawner {server_name} for user {user_name} found",
                extra={
                    "user": user,
                    "spawner": server_name,
                    "log_name": f"{user_name}:{server_name}",
                },
            )
            raise web.HTTPError(404)

        # Collect information from Spawner object
        # spawner = user.spawners[server_name]
        # service_type = spawner.user_options.get(
        #     "service", "JupyterLab/JupyterLab"
        # ).split("/")[1]
        # system = spawner.user_options.get("system")
        # account = spawner.user_options.get("account")
        # interactive_partitions = (
        #     get_custom_config()
        #     .get("systems", {})
        #     .get(system, {})
        #     .get("interactive_partitions", [])
        # )
        # tmp = auth_state.get("options_form", {})
        # tmp = await spawner.get_options_form()
        # if type(tmp) == str:
        #     self.log.info(tmp)

        # # Restructure options form to account+system specific output (defined by spawner.user_options)
        # ret = {
        #     "dropdown_lists": {"projects": [], "partitions": {}, "reservations": {}},
        #     "resources": {},
        # }

        # # fill in return dict
        # # Skip projects which only have interactive partitions, these are useless for slurm jobs
        # projects = []
        # # ret["dropdown_lists"]["projects"] = tmp.get("dropdown_lists", {}).get("projects", {}).get(system, {}).get(account, [])

        # # skip all interactive_partitions
        # all_partitions = (
        #     tmp.get("dropdown_lists", {})
        #     .get(service, {})
        #     .get(system, {})
        #     .get(account, {})
        #     .get(project, {})
        # )
        # for project in list(all_partitions.keys()):
        #     batch_partitions = [
        #         x
        #         for x in all_partitions.get(project, [])
        #         if x not in interactive_partitions
        #     ]
        #     if len(batch_partitions) > 0:
        #         projects.append(project)
        #         ret["dropdown_lists"]["partitions"][project] = batch_partitions
        # ret["dropdown_lists"]["projects"] = projects
        # ret["dropdown_lists"]["reservations"] = (
        #     tmp.get("dropdown_lists", {})
        #     .get("reservations", {})
        #     .get(system, {})
        #     .get(account, {})
        # )
        # ret["resources"] = (
        #     tmp.get("resources", {}).get(service_type, {}).get(system, {})
        # )
        auth_state = await user.get_auth_state()
        ret = {}
        ret["dropdown_lists"] = auth_state.get("options_form", {}).get(
            "dropdown_lists", {}
        )
        ret["resources"] = auth_state.get("options_form", {}).get("resources", {})
        ret["reservations"] = auth_state.get("options_form", {}).get("reservations", {})
        self.write(json.dumps(ret))


default_handlers.append(
    (r"/api/users/([^/]+)/server/optionsform", SpawnOptionsFormAPIHandler)
)
default_handlers.append(
    (r"/api/users/([^/]+)/servers/([^/]+)/optionsform", SpawnOptionsFormAPIHandler)
)
