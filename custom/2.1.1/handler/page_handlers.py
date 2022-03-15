import json
import os

from tornado import web

from jupyterhub.handlers.base import BaseHandler
from custom_utils import get_vos


async def get_user_auth_state_with_vos(user):
    auth_state = await user.get_auth_state()
    custom_config = user.authenticator.custom_config
    vo_active, vo_available = get_vos(auth_state, custom_config, user.name, user.admin)
    auth_state["vo_active"] = vo_active
    auth_state["vo_available"] = vo_available
    await user.save_auth_state(auth_state)
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


class VOHandler(BaseHandler):
    @web.authenticated
    async def get(self):
        user = self.current_user
        auth_state = await user.get_auth_state()
        custom_config = user.authenticator.custom_config
        vo_active, vo_available = get_vos(auth_state, custom_config, user.name, user.admin)
        auth_state["vo_active"] = vo_active
        auth_state["vo_available"] = vo_available
        await user.save_auth_state(auth_state)

        vo_details_config = custom_config.get("vos", {})
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