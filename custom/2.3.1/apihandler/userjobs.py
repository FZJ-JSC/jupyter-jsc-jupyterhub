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

    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"))

    def __repr__(self):
        return "<{} - UserJobs for {}>".format(self.id, self.server_id)

    @classmethod
    def find(cls, db, server_id):
        """Find all user jobs for one server.
        Returns None if not found.
        """
        return db.query(cls).filter(cls.server_id == server_id).all()


class UserJobsForwardORM(Base):
    """Information for userjobs forwards."""

    __tablename__ = "userjobsforward"
    id = Column(Integer, primary_key=True)

    server_id = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"))
    suffix = Column(Unicode(255), default="")
    ports = Column(JSONDict)

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

        user = self.find_user(user_name)
        spawner = user.spawners[server_name]
        body["service"] = spawner.name
        suffix = uuid.uuid4().hex[:8]
        body["suffix"] = suffix
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
        spawner.orm_spawner

        # req_prop = drf_request_properties(
        #     "tunnel", custom_config, self.log, uuidcode
        # )
        # req_prop["headers"]["labels"] = json.dumps(labels)  # Add labels to headers
        # service_url = req_prop.get("urls", {}).get("tunnel", "None")
        # req = HTTPRequest(
        #     service_url,
        #     method="POST",
        #     headers=req_prop["headers"],
        #     body=json.dumps(event["setup_tunnel"]),
        #     request_timeout=req_prop["request_timeout"],
        #     validate_cert=req_prop["validate_cert"],
        #     ca_certs=req_prop["ca_certs"],
        # )
        # try:
        #     await drf_request(
        #         req,
        #         self.log,
        #         user.authenticator.fetch,
        #         "setuptunnel",
        #         user.name,
        #         f"{user.name}::setuptunnel",
        #         parse_json=True,
        #         raise_exception=True,
        #     )
        # except BackendException as e:
        #     now = datetime.datetime.now().strftime("%Y_%m_%d %H:%M:%S.%f")[:-3]
        #     failed_event = {
        #         "progress": 100,
        #         "failed": True,
        #         "html_message": f"<details><summary>{now}: Could not setup tunnel</summary>{e.error_detail}</details>",
        #     }
        #     self.log.exception(
        #         f"Could not setup tunnel for {user_name}:{server_name}",
        #         extra={
        #             "uuidcode": uuidcode,
        #             "log_name": f"{user_name}:{server_name}",
        #             "user": user_name,
        #             "action": "tunnelfailed",
        #             "event": failed_event,
        #         },
        #     )
