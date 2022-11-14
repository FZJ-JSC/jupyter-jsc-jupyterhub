import os
from tornado import web
from custom_utils import get_vos
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.scopes import needs_scope


async def get_user_auth_state_with_vos(user):
    if not user:
        return {}
    auth_state = await user.get_auth_state()
    custom_config = user.authenticator.custom_config
    vo_active, vo_available = get_vos(auth_state, custom_config, user.name, user.admin)
    auth_state["vo_active"] = vo_active
    auth_state["vo_available"] = vo_available
    await user.save_auth_state(auth_state)
    if "refresh_token" in auth_state.keys():
        del auth_state["refresh_token"]

    return auth_state


async def _create_ns(user):
    ns = dict(user=user)
    if user:
        auth_state = await get_user_auth_state_with_vos(user)
        ns["auth_state"] = auth_state
    return ns


class LinksHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await _create_ns(user)
        html = await self.render_template("links.html", **ns)
        self.finish(html)

     
class TwoFAHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await _create_ns(user)
        html = await self.render_template("2FA.html", **ns)
        self.finish(html)


class ImprintHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await _create_ns(user)
        html = await self.render_template("imprint.html", **ns)
        self.finish(html)
    

class DPSHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await _create_ns(user)
        html = await self.render_template("dps.html", **ns)
        self.finish(html)


class ToSHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await _create_ns(user)
        html = await self.render_template("tos.html", **ns)
        self.finish(html)


class LoggingHandler(BaseHandler):
    @web.authenticated
    @needs_scope("access:services")
    async def get(self):
        user = self.current_user
        ns = await _create_ns(user)
        ns.update({'show_drf_logs': os.environ.get("SHOW_DRF_LOGS", "false").lower() in ["true", "1"]})
        html = await self.render_template("logging.html", **ns)
        self.finish(html)


class VOHandler(BaseHandler):
    @web.authenticated
    async def get(self):
        user = self.current_user
        auth_state = await get_user_auth_state_with_vos(user)
        vo_details_config = user.authenticator.custom_config.get("vos", {})
        vo_details = {}
        for vo_name in vo_available:
            vo_details[vo_name] = (
                vo_details_config.get(vo_name, {})
                .get("description", "No description available")
            )

        html = await self.render_template(
            "vo_info.html",
            user=user,
            auth_state=auth_state,
            vo_active=vo_active,
            vo_details=vo_details,
        )
        self.finish(html)
