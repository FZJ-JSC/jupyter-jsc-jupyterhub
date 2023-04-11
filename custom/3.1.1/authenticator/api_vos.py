from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.handlers import default_handlers
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.utils import token_authenticated
from tornado import web

from ..misc import get_custom_config
from .oauthenticator import get_vos


async def get_user_auth_state_with_vos(user):
    if not user:
        return {}
    auth_state = await user.get_auth_state()
    vo_active, vo_available = get_vos(auth_state, user.name, user.admin)
    auth_state["vo_active"] = vo_active
    auth_state["vo_available"] = vo_available
    await user.save_auth_state(auth_state)
    if "refresh_token" in auth_state.keys():
        del auth_state["refresh_token"]
    return auth_state


async def create_ns(user):
    ns = dict(user=user)
    if user:
        auth_state = await get_user_auth_state_with_vos(user)
        ns["auth_state"] = auth_state
    return ns


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


class VOHandler(BaseHandler):
    @web.authenticated
    async def get(self):
        user = self.current_user
        auth_state = await get_user_auth_state_with_vos(user)
        vo_details_config = get_custom_config().get("vos", {})
        vo_details = {}
        for vo_name in auth_state["vo_available"]:
            vo_details[vo_name] = vo_details_config.get(vo_name, {}).get(
                "description", "No description available"
            )

        html = await self.render_template(
            "vo_info.html",
            user=user,
            auth_state=auth_state,
            vo_active=auth_state["vo_active"],
            vo_details=auth_state["vo_available"],
        )
        self.finish(html)


default_handlers.append((r"/api/vo/([^/]+)", VOAPIHandler))
default_handlers.append((r"/api/votoken/([^/]+)", VOTokenAPIHandler))
default_handlers.append((r"/groups", VOHandler))
