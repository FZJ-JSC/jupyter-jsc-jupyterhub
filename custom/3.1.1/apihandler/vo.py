from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.utils import token_authenticated
from tornado import web


class VOAPIHandler(APIHandler):
    @web.authenticated
    async def post(self, group):
        user = self.current_user
        # user = self.get_current_user_token()
        state = await user.get_auth_state()
        if group in state.get("vo_available", []):
            state["vo_active"] = group
            await user.save_auth_state(state)
        else:
            self.log.debug(
                "{} not part of list {}".format(group, state.get("vo_available", []))
            )
            self.set_status(403)
            return
        self.set_status(204)
        return


class VOTokenAPIHandler(APIHandler):
    @token_authenticated
    async def post(self, group):
        user = self.get_current_user_token()
        state = await user.get_auth_state()
        if group in state.get("vo_available", []):
            state["vo_active"] = group
            await user.save_auth_state(state)
        else:
            self.log.debug(
                "{} not part of list {}".format(group, state.get("vo_available", []))
            )
            self.set_status(403)
            return
        self.set_status(204)
        return
