import asyncio

from jupyterhub.apihandlers.users import SpawnProgressAPIHandler
from jupyterhub.scopes import needs_scope
from tornado import web


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

        event = user.spawn_start_event  # asyncio.Event()
        await event.wait()
        spawners = user.spawners.values()
        # Set active spawners as event data
        event_data = {s.name: s.pending for s in spawners if s.pending}
        await self.send_event(event_data)
        # Clear event after sending in case stream has been closed
        event.clear()
        return


class SpawnStopNotificationAPIHandler(SpawnProgressAPIHandler):
    """EventStream handler for stopped servers"""

    @needs_scope("read:servers")
    async def get(self, user_name):
        self.set_header("Cache-Control", "no-cache")
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)

        # start sending keepalive to avoid proxies closing the connection
        asyncio.ensure_future(self.keepalive())

        event = user.spawn_stop_event  # asyncio.Event()
        await event.wait()
        spawners = user.spawners.values()
        # Send last event of stopping spawners only
        event_data = {s.name: s.latest_events[-1] for s in spawners 
            if s.pending == 'stop' and s.latest_events != []}
        await self.send_event(event_data)
        # Clear event after sending in case stream has been closed
        event.clear()
        return
