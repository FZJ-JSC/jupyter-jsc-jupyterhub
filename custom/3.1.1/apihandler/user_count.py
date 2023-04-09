import json

from jupyterhub.apihandlers.base import APIHandler


class UserCountAPIHandler(APIHandler):
    async def get(self):
        ret = self.authenticator.get_user_count(self.db)
        self.write(json.dumps(self.authenticator.get_user_count(self.db)))
        self.set_status(200)
        return
