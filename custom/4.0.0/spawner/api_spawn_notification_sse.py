import asyncio

from jupyterhub.apihandlers import default_handlers
from jupyterhub.apihandlers.users import SpawnProgressAPIHandler
from jupyterhub.scopes import needs_scope
from tornado import web

from .utils import get_spawner_events


class SpawnNotificationAPIHandler(SpawnProgressAPIHandler):
    """EventStream handler for active spawns"""

    @needs_scope("read:servers")
    async def get(self, user_name):
        self.set_header("Cache-Control", "no-cache")
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)

        # start sending keepalive to avoid proxies closing the connection
        asyncio.ensure_future(self.keepalive())

        events = get_spawner_events(user.id)
        await events["start"].wait()
        spawners = user.spawners.values()
        # Set active spawners as event data
        event_data = {s.name: s.pending for s in spawners if s.pending}
        await self.send_event(event_data)
        # Clear event after sending in case stream has been closed
        events["start"].clear()
        return


default_handlers.append(
    (r"/api/users/([^/]+)/notifications/spawners/spawn", SpawnNotificationAPIHandler)
)
