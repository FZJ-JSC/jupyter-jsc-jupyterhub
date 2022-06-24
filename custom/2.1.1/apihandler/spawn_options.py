from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.scopes import needs_scope
from tornado import web

from custom_utils import check_formdata_keys

class SpawnUpdateOptionsAPIHandler(APIHandler):
    @needs_scope("read:servers")
    async def post(self, username, server_name=''):
        user = self.find_user(username)
        if user is None:
            # no such user
            self.log.error(f"APICall: SpawnOptionsUpdate - No user {username} found",
                extra={
                    "user": user,
                    "log_name": f"{username}:{server_name}"
                }
            )
            raise web.HTTPError(404)
        orm_user = user.orm_user

        if server_name not in orm_user.orm_spawners:
            # user has no such server
            self.log.error(f"APICall: SpawnOptionsUpdate - No spawner {server_name} for user {username} found",
                extra={
                    "user": user,
                    "spawner": server_name,
                    "log_name": f"{username}:{server_name}"
                }
            )
            raise web.HTTPError(404)
        spawner = orm_user.orm_spawners[server_name]
        # Save new options
        formdata = self.get_json_body()
        try:
            check_formdata_keys(formdata, user.authenticator.custom_config)
        except KeyError as err:
            self.set_header("Content-Type", "text/plain")
            self.write(f"Bad Request - {str(err)}")
            self.log.error("APICall: SpawnOptionsUpdate - KeyError", 
                extra={
                    "user": user,
                    "error": err,
                    "log_name": f"{username}:{server_name}"
                }
            )
            self.set_status(400)
            return
        spawner.user_options = formdata
        self.db.commit()
        self.set_status(204)