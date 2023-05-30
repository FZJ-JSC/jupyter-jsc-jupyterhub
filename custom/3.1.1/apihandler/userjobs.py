# UserJobs allow users to connect to their running Slurm Jobs from JupyterLabs on the HDF-Cloud
# We want to limit the possible connections. 5 Forwards / JupyterLab . 5 Ports / Forward.
import json
import os
import random
import string
import uuid
from datetime import datetime

from jupyterhub.handlers import default_handlers
from jupyterhub.orm import Base
from jupyterhub.orm import JSONDict
from jupyterhub.scopes import needs_scope
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import Unicode
from tornado import web
from tornado.httpclient import HTTPRequest

from ..misc import get_custom_config
from .misc import RequestAPIHandler


class UserJobsORM(Base):
    """Information for userjobs code."""

    __tablename__ = "userjobs"
    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    system = Column(Unicode(255), default="")
    service = Column(Unicode(255), default="")
    suffix = Column(Unicode(255), default="")
    created = Column(DateTime, default=datetime.utcnow)
    running = Column(Boolean(create_constraint=False), default=True)
    bss_details = Column(JSONDict, default={})
    result = Column(JSONDict, default={})

    def __repr__(self):
        return "<{} - UserJobs for {}>".format(self.id, self.user_id)


class UserJobsForwardORM(Base):
    """Information for userjobs forwards."""

    __tablename__ = "userjobsforward"
    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    service = Column(Unicode(255), default="")
    ports = Column(JSONDict)
    system = Column(Unicode(255), default="")
    created = Column(DateTime, default=datetime.utcnow)
    userjobs_id = Column(
        Integer, ForeignKey("userjobs.id", ondelete="CASCADE"), default=None
    )

    def __repr__(self):
        return "<{} - UserJobsForwards for {}>".format(self.id, self.user_id)


class UserJobsForwardAPIHandler(RequestAPIHandler):
    @needs_scope("access:servers")
    async def post(self):
        user = self.current_user
        if user is None:
            self.set_status(403)
            return
        body_req = self.request.body.decode("utf8")
        body = json.loads(body_req) if body_req else {}

        required_keys = ["ports", "hostname", "target_node"]
        for key in required_keys:
            if key not in body.keys():
                self.log.warning(f"Missing key: {key}")
                self.write(f"Missing key: {key}")
                self.set_status(400)
                return

        if "service" not in body.keys():
            first_char_options = string.ascii_lowercase
            first_char = random.choice(first_char_options)
            body["service"] = f"{first_char}{uuid.uuid4().hex[:31]}"

        try:
            await self.userjobsforward_create(user, body)
        except Exception:
            self.set_status(400)
        else:
            ujfORM = UserJobsForwardORM(
                user_id=user.id,
                service=body["service"],
                ports=body.get("ports", {}),
                userjobs_id=body.get("userjobs_id", None),
                system=body["system"],
            )

            self.db.add(ujfORM)
            self.db.commit()
            self.set_status(200)
            ret = {
                "id": ujfORM.id,
                "service": ujfORM.service,
                "ports": ujfORM.ports,
                "userjobs_id": ujfORM.userjobs_id,
            }
            self.write(ret)
            self.flush()

    @needs_scope("access:servers")
    async def get(self, id=None):
        user = self.current_user
        if user is None:
            raise web.HTTPError(403)
        if id:
            ujfORM = (
                self.db.query(UserJobsForwardORM)
                .filter(UserJobsForwardORM.id == int(id))
                .first()
            )
            if ujfORM is None:
                self.set_status(404)
                return
            if ujfORM.user_id != user.id:
                self.set_status(403)
                return
            ret = {
                "id": ujfORM.id,
                "service": ujfORM.service,
                "ports": ujfORM.ports,
                "system": ujfORM.system,
                "userjobs_id": ujfORM.userjobs_id,
            }
            self.write(ret)
            self.set_status(200)
        else:
            ujfORMs = (
                self.db.query(UserJobsForwardORM)
                .filter(UserJobsForwardORM.user_id == user.id)
                .all()
            )
            if ujfORMs is None:
                self.set_status(404)
                return
            ret = {}
            for ujf in ujfORMs:
                ret[ujf.id] = {
                    "id": ujf.id,
                    "service": ujf.service,
                    "ports": ujf.ports,
                    "system": ujf.system,
                    "userjobs_id": ujf.userjobs_id,
                }
        self.write(ret)
        self.set_status(200)

    @needs_scope("access:servers")
    async def delete(self, id=None):
        user = self.current_user
        if user is None:
            self.set_status(403)
            return
        if id:
            ujfORM = (
                self.db.query(UserJobsForwardORM)
                .filter(UserJobsForwardORM.id == int(id))
                .first()
            )
            if ujfORM is None:
                self.set_status(404)
                return
            if ujfORM.user_id != user.id:
                self.set_status(403)
                return

            await self.userjobsforward_delete(user, ujfORM)
            self.set_status(204)
        else:
            # Delete all forwards older than x hours
            if not user.orm_user.admin:
                self.set_status(403)
                return
            custom_config = get_custom_config()
            threshold = custom_config.get("userjobsforward", {}).get(
                "cleanup_after_x_hours", 24
            )
            current_time = datetime.datetime.utcnow()
            x_hours_ago = current_time - datetime.timedelta(hours=threshold)
            ujfToDelete = (
                self.db.query(UserJobsForwardORM)
                .filter(UserJobsForwardORM.created < x_hours_ago)
                .all()
            )
            for ujf in ujfToDelete:
                await self.userjobsforward_delete(user, ujf)
            self.set_status(204)

    async def userjobsforward_delete(self, user, ujf):
        action = "userjobsforward_delete"
        self.log.info(
            "UserJobsForward delete ...",
            extra={
                "uuidcode": ujf.service,
                "username": user.name,
                "userid": user.id,
                "action": action,
            },
        )

        custom_config = get_custom_config()
        req_prop = self.get_req_prop_system(
            custom_config, ujf.system, uuidcode=ujf.service
        )
        service_url = req_prop.get("urls", {}).get("userjobs", "None")

        req = HTTPRequest(
            f"{service_url}{ujf.service}",
            method="DELETE",
            headers=req_prop.get("headers", {}),
            **req_prop.get("request_kwargs", {}),
        )

        try:
            resp_json = await self.send_request(req, action, ujf.service)
        except Exception as e:
            self.log.exception(
                "UserJobsForward delete ... failed.",
                extra={
                    "uuidcode": ujf.service,
                    "username": user.name,
                    "userid": user.id,
                    "action": "userjobsforward_delete_fail",
                    "user_msg": e.jupyterhub_html_message,
                },
            )
        else:
            self.log.info(
                "UserJobsForward delete ... done.",
                extra={
                    "uuidcode": ujf.service,
                    "username": user.name,
                    "userid": user.id,
                    "action": "userjobsforward_deleted",
                    "response": resp_json,
                },
            )
        finally:
            self.db.delete(ujf)
            self.db.commit()

    async def userjobsforward_create(self, user, body):
        action = "userjobsforward_create"
        uuidcode = body["service"]
        self.log.info(
            "UserJobsForward create ...",
            extra={
                "uuidcode": uuidcode,
                "username": user.name,
                "userid": user.id,
                "action": action,
                "options": body,
            },
        )

        custom_config = get_custom_config()
        auth_state = await user.get_auth_state()
        req_prop = self.get_req_prop_system(
            custom_config, body["system"], body["service"], auth_state
        )
        service_url = req_prop.get("urls", {}).get("userjobs", "None")

        req = HTTPRequest(
            service_url,
            method="POST",
            headers=req_prop.get("headers", {}),
            body=json.dumps(body),
            **req_prop.get("request_kwargs", {}),
        )

        try:
            resp_json = await self.send_request(req, action, uuidcode)
        except Exception as e:
            self.log.warning(
                "UserJobsForward create ... failed.",
                extra={
                    "uuidcode": body["service"],
                    "username": user.name,
                    "userid": user.id,
                    "action": "userjobsforward_fail",
                    "user_msg": str(e),
                },
            )
            raise e
        self.log.info(
            "UserJobsForward create ... done.",
            extra={
                "uuidcode": body["service"],
                "username": user.name,
                "userid": user.id,
                "action": "userjobsforward_created",
                "response": resp_json,
            },
        )


class UserJobsAPIHandler(RequestAPIHandler):

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
    PORT_ENV ; json as string (json.dumps(body["ports"])), to be used within curl -d ' { "ports": $PORT_ENV }
    add orm stuff
    """

    @needs_scope("access:servers")
    async def post(self):
        user = self.current_user
        if user is None:
            raise web.HTTPError(403)
        suffix = uuid.uuid4().hex[:8]

        first_char_options = string.ascii_lowercase
        first_char = random.choice(first_char_options)
        service = f"{first_char}{uuid.uuid4().hex[:31]}"

        body_req = self.request.body.decode("utf8")
        body = json.loads(body_req) if body_req else {}
        system = body["user_options"]["system"]

        try:
            await self.userjobs_create(user, body, service, suffix)
        except Exception:
            self.set_status(400)
        else:
            ujORM = UserJobsORM(
                user_id=user.id,
                system=system,
                service=service,
                suffix=suffix,
                result={},
            )

            self.db.add(ujORM)
            self.db.commit()
            self.set_status(200)
            self.write({"id": ujORM.id})
            self.flush()

    @needs_scope("access:servers")
    async def get(self, id=None):
        user = self.current_user
        if user is None:
            raise web.HTTPError(403)

        if id:
            ujORM = self.db.query(UserJobsORM).filter(UserJobsORM.id == int(id)).first()
            if ujORM is None:
                self.set_status(404)
                return
            if ujORM.user_id != user.id:
                self.set_status(403)
                return
            if ujORM.running:
                ret = await self.userjobs_get(user, ujORM)
            else:
                ret = {
                    "id": ujORM.id,
                    "running": ujORM.running,
                    "bss_details": ujORM.bss_details,
                    "result": ujORM.result,
                    "system": ujORM.system,
                }
        else:
            ujORMs = (
                self.db.query(UserJobsORM).filter(UserJobsORM.user_id == user.id).all()
            )
            if ujORMs is None:
                self.set_status(404)
                return
            ret = {}
            for uj in ujORMs:
                if uj.running:
                    ret[uj.id] = await self.userjobs_get(user, uj)
                else:
                    ret[uj.id] = {
                        "id": uj.id,
                        "running": uj.running,
                        "bss_details": uj.bss_details,
                        "result": uj.result,
                        "system": uj.system,
                    }
        self.write(ret)
        self.set_status(200)

    @needs_scope("access:servers")
    async def delete(self, id=None):
        user = self.current_user
        if user is None:
            raise web.HTTPError(403)

        if id:
            ujORM = self.db.query(UserJobsORM).filter(UserJobsORM.id == int(id)).first()

            if ujORM is None:
                self.set_status(404)
                return
            if ujORM.user_id != user.id:
                self.set_status(403)
                return
            try:
                await self.userjobs_delete(user, ujORM)
            except:
                self.log.exception(f"Could not delete userjob {ujORM.service}")
                self.write(
                    "Could not stop job. Please delete it with scancel on the system itself."
                )
                self.set_status(400)
            else:
                self.set_status(204)
            finally:
                if (
                    self.request.arguments.get("delete", [b""])[0].decode().lower()
                    == "true"
                ):
                    self.db.delete(ujORM)
                    self.db.commit()
        else:
            # Delete all userjobs older than x hours. We don't have to stop them,
            # they're stopped anyway after 24 hours max
            if not user.orm_user.admin:
                self.set_status(403)
                return
            custom_config = get_custom_config()
            threshold = custom_config.get("userjobs", {}).get(
                "cleanup_after_x_hours", 24
            )
            current_time = datetime.datetime.utcnow()
            x_hours_ago = current_time - datetime.timedelta(hours=threshold)
            ujToDelete = (
                self.db.query(UserJobsORM)
                .filter(UserJobsORM.created < x_hours_ago)
                .all()
            )
            for uj in ujToDelete:
                self.db.delete(uj)
                self.db.commit()
            self.set_status(204)

    async def userjobs_create(self, user, body, service, suffix):
        action = "userjobs_create"
        uuidcode = service
        auth_state = await user.get_auth_state()
        custom_config = get_custom_config()

        system = body["user_options"]["system"]

        req_prop = self.get_req_prop_system(custom_config, system, service, auth_state)
        service_url = req_prop.get("urls", {}).get("services", "None")

        self.log.info(
            "UserJobs create ...",
            extra={
                "uuidcode": uuidcode,
                "username": user.name,
                "userid": user.id,
                "start_id": suffix,
                "action": action,
                "options": body,
            },
        )

        env = body.get("env", {})
        env["JUPYTERHUB_STAGE"] = os.environ.get("JUPYTERHUB_STAGE", "")
        env["JUPYTERHUB_STATUS_URL"] = ""
        env["JUPYTERHUB_API_TOKEN"] = ""
        env["JUPYTERHUB_USER_ID"] = f"{user.id}"

        popen_kwargs = {
            "auth_state": auth_state,
            "env": env,
            "user_options": body["user_options"],
            "start_id": suffix,
        }

        if "input_files" in body.keys():
            popen_kwargs["input_files"] = body["input_files"]

        req = HTTPRequest(
            service_url,
            method="POST",
            headers=req_prop["headers"],
            body=json.dumps(popen_kwargs),
            **req_prop.get("request_kwargs", {}),
        )

        resp_json = await self.send_request(req, action, uuidcode)

        self.log.info(
            "UserJobs create ... done",
            extra={
                "uuidcode": service,
                "username": user.name,
                "userid": user.id,
                "start_id": suffix,
                "action": "userjobs_create",
                "options": body,
                "response": resp_json,
            },
        )

    async def userjobs_get(self, user, uj):
        uuidcode = uj.service
        action = "userjobs_poll"
        auth_state = await user.get_auth_state()
        custom_config = get_custom_config()

        req_prop = self.get_req_prop_system(
            custom_config, uj.system, uuidcode, auth_state
        )
        service_url = req_prop.get("urls", {}).get("services", "None")

        req = HTTPRequest(
            f"{service_url}{uj.service}/",
            method="GET",
            headers=req_prop["headers"],
            **req_prop.get("request_kwargs", {}),
        )
        resp_json = await self.send_request(
            req, action, uuidcode, raise_exception=False
        )

        ret = {
            "id": uj.id,
            "running": resp_json.get("running", False),
            "bss_details": resp_json.get("bss_details", uj.bss_details),
            "system": uj.system,
            "result": resp_json.get("details", uj.result),
        }
        if not ret["running"]:
            ret["result"] = resp_json.get("details", {})
            uj.running = False
            uj.result = ret["result"]

        uj.bss_details = ret["bss_details"]
        self.db.commit()
        return ret

    async def userjobs_delete(self, user, uj):
        uuidcode = uj.service
        action = "userjobs_stop"
        auth_state = await user.get_auth_state()
        custom_config = get_custom_config()

        req_prop = self.get_req_prop_system(
            custom_config, uj.system, uuidcode, auth_state
        )
        service_url = req_prop.get("urls", {}).get("services", "None")

        req = HTTPRequest(
            f"{service_url}{uj.service}/",
            method="DELETE",
            headers=req_prop["headers"],
            **req_prop.get("request_kwargs", {}),
        )
        await self.send_request(req, action, uuidcode, raise_exception=False)


default_handlers.append((r"/api/userjobs", UserJobsAPIHandler))
default_handlers.append((r"/api/userjobs/([^/]+)", UserJobsAPIHandler))
default_handlers.append((r"/api/userjobsforward", UserJobsForwardAPIHandler))
default_handlers.append((r"/api/userjobsforward/([^/]+)", UserJobsForwardAPIHandler))
