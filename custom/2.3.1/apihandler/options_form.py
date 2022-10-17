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
        spawner = orm_user.orm_spawners[server_name]
        ret = await spawner.get_options_form()
        self.write(json.dumps(ret))