import ast
import os
import re
from datetime import datetime
from datetime import timezone

from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.handlers import default_handlers
from jupyterhub.orm import Base
from jupyterhub.scopes import needs_scope
from jupyterhub.utils import utcnow
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer

from ..misc import get_custom_config


class HPCAccountUpdatesORM(Base):
    """Information for hpc account updates."""

    __tablename__ = "hpc_account_updates"

    id = Column(Integer, primary_key=True)

    last_update = Column(DateTime, default=datetime.now(timezone.utc))

    @classmethod
    def update(cls, db):
        """Find a group by user_id.
        Returns None if not found.
        """
        ret = db.query(cls).filter(cls.id == 1).first()
        if ret is None:
            ret = HPCAccountUpdatesORM(id=1)
        else:
            ret.last_update = utcnow()
        db.add(ret)
        db.commit()


class HPCUpdateAPIHandler(APIHandler):
    def check_xsrf_cookie(self):
        pass

    # Might want to define a more restrictive custom scope once available
    async def post(self, username):
        try:
            shared_secret = os.environ.get("HPC_UPDATE_SECRET", None)
            auth_header = self.request.headers.get("Authorization", "").split()
            # Shared secret required
            # Authorization header in form 'token <shared_secret>' required
            if (
                not shared_secret
                or len(auth_header) < 2
                or auth_header[1] != shared_secret
                or auth_header[0] != "token"
            ):
                self.log.warning(
                    "Update HPC Infos not allowed, please check script and shared secret"
                )
                self.set_status(403)
                return
        except:
            self.log.exception(
                "Update HPC Infos not allowed, please check script and shared secret"
            )
            self.set_status(403)
            return
        # Update database whenever this is called
        # This way we can check, if the cronjob on UNICORE site is still running
        HPCAccountUpdatesORM.update(self.db)

        user = self.find_user(username)
        if user is None:
            self.set_status(404)
            return
        auth_state = await user.get_auth_state()
        if auth_state and "oauth_user" in auth_state.keys():
            # User is logged in
            body = self.get_json_body()
            if not body:
                body = {}
            if type(body) == str:
                body = ast.literal_eval(body)
            # test if it's just one string
            if len(body) > 0 and len(body[0]) == 1:
                body = ["".join(body)]
            default_partitions = get_custom_config().get("default_partitions")
            to_add = []
            for entry in body:
                partition = re.search("[^,]+,([^,]+),[^,]+,[^,]+", entry).groups()[0]
                if partition in default_partitions.keys():
                    for value in default_partitions[partition]:
                        to_add.append(
                            entry.replace(
                                f",{partition},",
                                ",{},".format(value),
                            )
                        )
            if to_add:
                body.extend(to_add)
            if body:
                auth_state["oauth_user"]["hpc_infos_attribute"] = body
            else:
                auth_state["oauth_user"]["hpc_infos_attribute"] = []
            await user.save_auth_state(auth_state)
        self.set_status(200)
        return


default_handlers.append((r"/api/refreshhpc/([^/]+)", HPCUpdateAPIHandler))
