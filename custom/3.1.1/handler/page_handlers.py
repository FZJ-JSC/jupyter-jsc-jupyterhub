import json
import os

from jupyterhub.handlers import default_handlers
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.scopes import needs_scope
from tornado import web


async def _create_ns(user):
    ns = dict(user=user)
    if user:
        auth_state = await user.get_auth_state()
        if "refresh_token" in auth_state.keys():
            del auth_state["refresh_token"]
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
        ns.update(
            {
                "show_drf_logs": os.environ.get("SHOW_DRF_LOGS", "false").lower()
                in ["true", "1"]
            }
        )
        html = await self.render_template("logging.html", **ns)
        self.finish(html)


default_handlers.append((r"/links", LinksHandler))
default_handlers.append((r"/2FA", TwoFAHandler))
default_handlers.append((r"/imprint", ImprintHandler))
default_handlers.append((r"/privacy", DPSHandler))
default_handlers.append((r"/terms", ToSHandler))
default_handlers.append((r"/logging", LoggingHandler))
