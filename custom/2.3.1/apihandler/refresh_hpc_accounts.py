import ast
import re

from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.scopes import needs_scope


class HPCUpdateAPIHandler(APIHandler):
    # Might want to define a more restrictive custom scope once available
    @needs_scope("admin:users")
    async def post(self, username):
        user = self.find_user(username)
        if user is None:
            self.set_status(404)
            return
        auth_state = await user.get_auth_state()
        if (
            auth_state
            and "oauth_user" in auth_state.keys()
        ):
            # User is logged in
            body = self.get_json_body()
            if type(body) == str:
                body = ast.literal_eval(body)
            # test if it's just one string
            if len(body) > 0 and len(body[0]) == 1:
                body = [''.join(body)]
            default_partitions = self.authenticator.custom_config.get("default_partitions")
            to_add = []
            for entry in body:
                partition = re.search("[^,]+,([^,]+),[^,]+,[^,]+", entry).groups()[0]
                if partition in default_partitions.keys():
                    for value in default_partitions[partition]:
                        to_add.append(
                            entry.replace(
                                f",{partition},",
                                ",{},".format(value),
                            )
                        )
            body.extend(to_add)
            if body:
                auth_state["oauth_user"]["hpc_infos_attribute"] = body
            else:
                auth_state["oauth_user"]["hpc_infos_attribute"] = []
            await user.save_auth_state(auth_state)
        self.set_status(200)
        return