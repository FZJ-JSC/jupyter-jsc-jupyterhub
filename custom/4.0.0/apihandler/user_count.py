import json
import operator
import os
import time
from datetime import datetime
from datetime import timedelta

from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.app import app_log
from jupyterhub.handlers import default_handlers
from jupyterhub.orm import Spawner as orm_spawner
from jupyterhub.orm import User as orm_user

from ..misc import get_custom_config

_user_count_cache = {}
_user_count_last_update = 0
_user_count_cache_timeout = os.environ.get("USER_COUNT_CACHE_TIME", 60)


def get_user_count(db):
    global _user_count_cache
    global _user_count_last_update

    now = time.time()
    if now - _user_count_last_update > _user_count_cache_timeout:
        # app_log.debug("Update user_count via database ...")
        try:
            running_spawner = (
                db.query(orm_spawner).filter(orm_spawner.server_id.isnot(None)).all()
            )
            systems = [x.user_options.get("system") for x in running_spawner if x]
            systems_partitions = [
                f'{x.user_options.get("system")}:{x.user_options.get("partition", "N/A")}'
                for x in running_spawner
                if x
            ]
            unique_systems = set(systems)
            ret = {
                key: {
                    "total": operator.countOf(systems, key),
                    "partitions": {
                        partition_key: operator.countOf(
                            systems_partitions, f"{key}:{partition_key}"
                        )
                        for partition_key in [
                            x.split(":")[1]
                            for x in systems_partitions
                            if x.startswith(key)
                        ]
                    },
                }
                for key in unique_systems
            }
            active_minutes = (
                get_custom_config().get("user_count", {}).get("active_minutes", 60)
            )
            active_range = datetime.utcnow() - timedelta(minutes=active_minutes)
            active_users = (
                db.query(orm_user).filter(orm_user.last_activity > active_range).all()
            )
            ret["jupyterhub"] = len(active_users)
            # app_log.debug("Update user_count via database ... done", extra=ret)
        except:
            app_log.exception("Could not create user_count dict")
            ret = {}
        _user_count_cache = ret
        _user_count_last_update = now
    return _user_count_cache


class UserCountAPIHandler(APIHandler):
    async def get(self):
        self.write(json.dumps(get_user_count(self.db)))
        self.set_status(200)
        return


default_handlers.append((r"/api/usercount", UserCountAPIHandler))
