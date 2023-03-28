import json

from jupyterhub.apihandlers.base import APIHandler


class UserCountAPIHandler(APIHandler):
    """Return current user count"""

    async def get(self):
        self.write(json.dumps(self.authenticator.user_count))
        self.set_status(200)
        return
