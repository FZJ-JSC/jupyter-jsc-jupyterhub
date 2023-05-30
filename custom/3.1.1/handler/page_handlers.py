from jupyterhub.handlers import default_handlers
from jupyterhub.handlers.base import BaseHandler

from ..authenticator.api_services import create_ns


class LinksHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await create_ns(user)
        html = await self.render_template("links.html", **ns)
        self.finish(html)


class TwoFAHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await create_ns(user)
        html = await self.render_template("2FA.html", **ns)
        self.finish(html)


class ImprintHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await create_ns(user)
        html = await self.render_template("imprint.html", **ns)
        self.finish(html)


class DPSHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await create_ns(user)
        html = await self.render_template("dps.html", **ns)
        self.finish(html)


class ToSHandler(BaseHandler):
    async def get(self):
        user = self.current_user
        ns = await create_ns(user)
        html = await self.render_template("tos.html", **ns)
        self.finish(html)


default_handlers.append((r"/links", LinksHandler))
default_handlers.append((r"/2FA", TwoFAHandler))
default_handlers.append((r"/imprint", ImprintHandler))
default_handlers.append((r"/privacy", DPSHandler))
default_handlers.append((r"/terms", ToSHandler))
