# UserJobs allow users to connect to their running Slurm Jobs from JupyterLabs on the HDF-Cloud
# We want to limit the possible connections. 5 Forwards / JupyterLab . 5 Ports / Forward.
import json
import uuid

from custom_utils.backend_services import BackendException
from custom_utils.backend_services import drf_request
from custom_utils.backend_services import drf_request_properties
from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.orm import Base
from jupyterhub.orm import JSONDict
from jupyterhub.scopes import needs_scope
from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import Unicode
from tornado import web
from tornado.httpclient import HTTPRequest


class UserJobsORM(Base):
    """Information for userjobs code."""

    __tablename__ = "userjobs"
    id = Column(Integer, primary_key=True)

    userjobs_name = Column(Unicode(255), default="")
    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"))
    suffix = Column(Unicode(255), default="")

    def __repr__(self):
        return "<{} - UserJobs for {}>".format(self.id, self.server_id)

    @classmethod
    def find(cls, db, userjobs_name):
        """Find all user jobs for one server.
        Returns None if not found.
        """
        return db.query(cls).filter(cls.userjobs_name == userjobs_name).all()


class UserJobsForwardORM(Base):
    """Information for userjobs forwards."""

    __tablename__ = "userjobsforward"
    id = Column(Integer, primary_key=True)

    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"))
    suffix = Column(Unicode(255), default="")
    ports = Column(JSONDict)
    userjobs_id = Column(
        Integer, ForeignKey("userjobs.id", ondelete="CASCADE"), default=None
    )

    def __repr__(self):
        return "<{} - UserJobs for {}>".format(self.id, self.server_id)

    @classmethod
    def find(cls, db, server_id):
        """Find all user jobs forwards for one server.
        Returns None if not found.
        """
        return db.query(cls).filter(cls.server_id == server_id).all()


class UserJobsForwardAPIHandler(APIHandler):
    @needs_scope("access:servers")
    async def post(self, user_name, server_name=""):
        self.set_header("Cache-Control", "no-cache")
        if server_name is None:
            server_name = ""
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)
        if server_name not in user.spawners:
            # user has no such server
            raise web.HTTPError(404)
        body_req = self.request.body.decode("utf8")
        body = json.loads(body_req) if body_req else {}

        required_keys = ["target_ports", "hostname", "target_node"]
        for key in required_keys:
            if key not in body.keys():
                self.log.warning(f"Missing key: {key}")
                self.set_status(400)
                return

        # TODO: optional in body: userjobs name (or id or whatever?) ; delete on cascade

        user = self.find_user(user_name)
        spawner = user.spawners[server_name]
        body["service"] = spawner.name

        # If you start a userjobs including port forwarding, you will not communicate
        # with this endpoint directly. Therefore, you have to specify the suffix previously,
        # or you'll never know where you can expect your forward ports.
        if "suffix" not in body.keys():
            suffix = uuid.uuid4().hex[:8]
            body["suffix"] = suffix
        else:
            suffix = body["suffix"]

        try:
            await spawner.userjobsforward_create(body)
        except BackendException:
            self.set_status(400)
        else:
            ujfORM = UserJobsForwardORM(
                server_id=spawner.orm_spawner.server_id,
                suffix=suffix,
                ports=body.get("target_ports", {}),
            )
            self.db.add(ujfORM)
            self.db.commit()
            self.set_status(201)
            self.set_header("Location", f"{spawner.name}-{suffix}")
            self.write({"Service": f"{spawner.name}-{suffix}"})
            self.flush()

    @needs_scope("access:servers")
    async def delete(self, user_name, server_name_suffix):
        self.set_header("Cache-Control", "no-cache")
        server_name = server_name_suffix[:-9]
        suffix = server_name_suffix[-8:]
        if server_name is None:
            server_name = ""
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)
        if server_name not in user.spawners:
            # user has no such server
            raise web.HTTPError(404)
        user = self.find_user(user_name)
        spawner = user.spawners[server_name]
        ujfORM = (
            self.db.query(UserJobsForwardORM)
            .filter(UserJobsForwardORM.server_id == spawner.orm_spawner.server_id)
            .filter(UserJobsForwardORM.suffix == suffix)
            .first()
        )
        if ujfORM is None:
            self.set_status(404)
            return
        elif ujfORM.server_id != spawner.orm_spawner.server_id:
            self.log.warning("The UserJobForward belongs to a different server.")
            self.set_status(400)
            return
        await spawner.userjobsforward_delete(ujfORM)
        self.set_status(204)


class UserJobsAPIHandler(APIHandler):

    """
    Requirements for unicore job:
    env variables:
        JUPYTERHUB_API_TOKEN
        JUPYTERHUB_API_URL
        JUPYTERHUB_USERJOBSFORWARD_URL (optional)

    user_options service/system/blabla
    entrypoint.sh as b64
    body:
        input_files: {"file.sh": b64data}
        ports: {}

    add entrypoint.sh to input_files
    PORT_ENV ; json as string (json.dumps(body["ports"])), to be used within curl -d ' { "target_ports": $PORT_ENV }
    add orm stuff
    """

    @needs_scope("access:servers")
    async def post(self, user_name, server_name=""):
        self.set_header("Cache-Control", "no-cache")
        if server_name is None:
            server_name = ""
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)
        if server_name not in user.spawners:
            # user has no such server
            raise web.HTTPError(404)
        body_req = self.request.body.decode("utf8")
        body = json.loads(body_req) if body_req else {}

        user = self.find_user(user_name)
        spawner = user.spawners[server_name]

        suffix = uuid.uuid4().hex[:8]
        userjobs_name = f"{self.name[:21]}-uj{suffix}"
        try:
            await spawner.userjobs_create(body, userjobs_name, suffix)
        except BackendException:
            self.set_status(400)
        else:
            ujORM = UserJobsORM(
                userjobs_name=userjobs_name,
                server_id=spawner.orm_spawner.server_id,
                suffix=suffix,
            )
            self.db.add(ujORM)
            self.db.commit()
            self.set_status(201)
            self.set_header("Location", f"{ujORM.id}")
            self.write({"Service": f"{spawner.name}-{suffix}"})
            self.flush()

    @needs_scope("access:servers")
    async def get(self, user_name, server_name, id):
        self.set_header("Cache-Control", "no-cache")
        if server_name is None:
            server_name = ""
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)
        if server_name not in user.spawners:
            # user has no such server
            raise web.HTTPError(404)

        user = self.find_user(user_name)
        spawner = user.spawners[server_name]
        ujORM = self.db.query(UserJobsORM).filter(UserJobsORM.id == id).first()
        if ujORM is None:
            self.set_status(404)
            return
        ret = spawner.userjobs_get(ujORM.userjobs_name)
        self.write(ret)
        self.set_status(200)

    @needs_scope("access:servers")
    async def delete(self, user_name, server_name, id):
        self.set_header("Cache-Control", "no-cache")
        if server_name is None:
            server_name = ""
        user = self.find_user(user_name)
        if user is None:
            # no such user
            raise web.HTTPError(404)
        if server_name not in user.spawners:
            # user has no such server
            raise web.HTTPError(404)

        user = self.find_user(user_name)
        spawner = user.spawners[server_name]
        ujORM = self.db.query(UserJobsORM).filter(UserJobsORM.id == id).first()

        if ujORM is None:
            self.set_status(404)
            return
        try:
            spawner.userjobs_delete(ujORM.userjobs_name)
        except:
            self.log.exception(f"Could not delete userjob {ujORM.userjobs_name}")
            self.write(
                "Could not stop job. Please delete it with scancel on the system itself."
            )
            self.set_status(400)
        else:
            self.set_status(204)
        finally:
            self.db.delete(ujORM)
            self.db.commit()
