import copy
import json
import logging
import operator
import os
import re
import time
from datetime import datetime
from datetime import timedelta
from urllib.error import HTTPError
from urllib.parse import urlencode

from custom_utils import get_vos
from custom_utils import VoException
from jupyterhub.orm import Spawner as orm_spawner
from jupyterhub.orm import User as orm_user
from jupyterhub.utils import new_token
from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.oauth2 import OAuthLoginHandler
from oauthenticator.oauth2 import OAuthLogoutHandler
from oauthenticator.traitlets import Callable
from tornado.httpclient import HTTPClientError
from tornado.httpclient import HTTPRequest
from traitlets import Bool
from traitlets import Dict
from traitlets import Unicode
from traitlets import Union


class TimedCacheProperty(object):
    """decorator to create get only property; values are fetched once per `timeout`"""

    def __init__(self, timeout):
        self._timeout = timedelta(seconds=timeout)
        self._func = None
        self._values = {}

    def __get__(self, instance, cls):
        last_lookup, value = self._values.get(instance, (datetime.min, None))
        now = datetime.now()
        if self._timeout < now - last_lookup:
            value = self._func(instance)
            self._values[instance] = now, value
        return value

    def __call__(self, func):
        self._func = func
        return self


class CustomLogoutHandler(OAuthLogoutHandler):
    async def handle_logout(self):
        user = self.current_user
        if not user:
            self.log.debug("Could not retrieve current user for logout call.")
            return

        all_devices = self.get_argument("alldevices", "false").lower() == "true"
        stop_all = self.get_argument("stopall", "false").lower() == "true"
        # Stop all servers before revoking tokens
        if stop_all:
            await self._shutdown_servers(user)

        if user.authenticator.enable_auth_state:
            tokens = {}
            auth_state = await user.get_auth_state()
            if os.environ.get("LOGGING_METRICS_ENABLED", "false").lower() in [
                "true",
                "1",
            ]:
                metrics_logger = logging.getLogger("Metrics")
                metrics_extras = {
                    "action": "logout",
                    "userid": user.id,
                    "authenticator": auth_state.get("oauth_user", {}).get(
                        "used_authenticator_attr", "unknown"
                    ),
                    "stopall": stop_all,
                    "all_devices": all_devices,
                }
                metrics_logger.info(
                    f"action={metrics_extras['action']};userid={metrics_extras['userid']};authenticator={metrics_extras['authenticator']};stopall={metrics_extras['stopall']};all_devices={metrics_extras['all_devices']}"
                )
                self.log.info("logout", extra=metrics_extras)
            access_token = auth_state.get("access_token", None)
            if access_token:
                tokens["access_token"] = access_token
                auth_state["access_token"] = None
                auth_state["exp"] = "0"
            # Only revoke refresh token if we logout from all devices and stop all services
            if all_devices and (stop_all or not user.active):
                refresh_token = auth_state.get("refresh_token", None)
                if refresh_token:
                    tokens["refresh_token"] = refresh_token
                    auth_state["refresh_token"] = None

            unity_revoke_config = user.authenticator.custom_config.get("unity", {}).get(
                "revoke", {}
            )
            unity_revoke_url = unity_revoke_config.get("url", "")
            unity_revoke_certificate = unity_revoke_config.get(
                "certificate_path", False
            )
            unity_revoke_request_timeout = unity_revoke_config.get(
                "request_timeout", 10
            )
            unity_revoke_expected_status_code = unity_revoke_config.get(
                "expected_status_code", 200
            )
            client_id = unity_revoke_config.get("client_id", "oauth-client")

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            data = {"client_id": client_id, "logout": "true"}
            ca_certs = unity_revoke_certificate if unity_revoke_certificate else None
            validate_cert = True if ca_certs else False

            log_extras = {
                "unity_revoke_url": unity_revoke_url,
                "unity_revoke_certificate": unity_revoke_certificate,
                "unity_revoke_request_timeout": unity_revoke_request_timeout,
                "unity_revoke_expected_status_code": unity_revoke_expected_status_code,
                "data": copy.deepcopy(data),
            }

            for key, value in tokens.items():
                data["token_type_hint"] = key
                data["token"] = value
                log_extras["data"]["token_type_hint"] = key
                log_extras["data"]["token"] = "***"
                try:
                    req = HTTPRequest(
                        f"{unity_revoke_url}",
                        method="POST",
                        headers=headers,
                        body=urlencode(data),
                        request_timeout=unity_revoke_request_timeout,
                        validate_cert=validate_cert,
                        ca_certs=ca_certs,
                    )
                    resp = await user.authenticator.fetch(req)
                    if resp and resp.code != unity_revoke_expected_status_code:
                        raise Exception(
                            f"Received unexpected status code: {resp.code} != {unity_revoke_expected_status_code}"
                        )
                except (HTTPError, HTTPClientError):
                    self.log.critical(
                        "Could not revoke token", extra=log_extras, exc_info=True
                    )
                except:
                    self.log.critical(
                        "Could not revoke token.", extra=log_extras, exc_info=True
                    )
                else:
                    self.log.debug(
                        f"Unity revoke {key} call successful.", extra=log_extras
                    )
            await user.save_auth_state(auth_state)

        # Set new cookie_id to invalidate previous cookies
        if all_devices:
            orm_user = user.orm_user
            orm_user.cookie_id = new_token()
            self.db.commit()

    async def get(self):
        await self.handle_logout()
        await self.default_handle_logout()
        await self.render_logout_page()


class CustomLoginHandler(OAuthLoginHandler):
    def authorize_redirect(self, *args, **kwargs):
        extra_params = kwargs.setdefault("extra_params", {})
        if self.authenticator.extra_params_allowed_runtime:
            if callable(self.authenticator.extra_params_allowed_runtime):
                extra_params_allowed = self.authenticator.extra_params_allowed_runtime()
            else:
                extra_params_allowed = self.authenticator.extra_params_allowed_runtime
            extra_params.update(
                {
                    k[len("extra_param_") :]: "&".join([x.decode("utf-8") for x in v])
                    for k, v in self.request.arguments.items()
                    if k.startswith("extra_param_")
                    and set([x.decode("utf-8") for x in v]).issubset(
                        extra_params_allowed.get(k[len("extra_param_") :], [])
                    )
                }
            )
        return super().authorize_redirect(*args, **kwargs)


custom_config_timeout = os.environ.get("CUSTOM_CONFIG_CACHE_TIME", 60)
user_count_cache_timeout = os.environ.get("USER_COUNT_CACHE_TIME", 60)


class CustomGenericOAuthenticator(GenericOAuthenticator):
    login_handler = CustomLoginHandler
    logout_handler = CustomLogoutHandler

    custom_config_file = Unicode(
        "jupyterhub_custom_config.json", help="The custom config file to load"
    ).tag(config=True)
    tokeninfo_url = Unicode(
        config=True,
        help="""The url retrieving information about the access token""",
    )

    # Change default to True
    refresh_pre_spawn = Bool(
        True,
        config=True,
        help="""Force refresh of auth prior to spawn.

        This forces :meth:`.refresh_user` to be called prior to launching
        a server, to ensure that auth state is up-to-date.

        This can be important when e.g. auth tokens that may have expired
        are passed to the spawner via environment variables from auth_state.

        If refresh_user cannot refresh the user auth data,
        launch will fail until the user logs in again.
        """,
    )

    @TimedCacheProperty(timeout=custom_config_timeout)
    def custom_config(self):
        self.log.debug("Load custom config file.")
        try:
            with open(self.custom_config_file, "r") as f:
                ret = json.load(f)
        except:
            self.log.warning("Could not load custom config file.", exc_info=True)
            ret = {}
        return ret

    @TimedCacheProperty(timeout=user_count_cache_timeout)
    def user_count(self):
        self.log.debug("Update user_count via database ...")
        running_spawner = (
            self.db.query(orm_spawner).filter(orm_spawner.server_id.isnot(None)).all()
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
                        x.split(":")[1] for x in systems_partitions if x.startswith(key)
                    ]
                },
            }
            for key in unique_systems
        }
        active_minutes = self.custom_config.get("user_count", {}).get(
            "active_minutes", 60
        )
        active_range = datetime.utcnow() - timedelta(minutes=active_minutes)
        active_users = (
            self.db.query(orm_user).filter(orm_user.last_activity > active_range).all()
        )
        ret["jupyterhub"] = len(active_users)
        self.log.debug("Update user_count via database ... done", extra=ret)
        return ret

    extra_params_allowed_runtime = Union(
        [Dict(), Callable()],
        config=True,
        help="""Allowed extra GET params to send along with the initial OAuth request
        to the OAuth provider.
        Usage: GET to localhost:8000/hub/oauth_login?extra_param_<key>=<value>
        This argument defines the allowed keys and values.
        Example:
        ```
        {
            "key": ["value1", "value2"],
        }
        ```
        All accepted extra params will be forwarded without the `extra_param_` prefix.
        """,
    )

    def get_callback_url(self, handler=None):
        # Replace _host_ in callback_url with current request
        ret = super().get_callback_url(handler)
        if self.oauth_callback_url and handler and "_host_" in ret:
            ret = ret.replace("_host_", handler.request.host)
        return ret

    async def authenticate(self, handler, data=None):
        user_info = await super().authenticate(handler, data)
        safe_user_name = user_info["name"].replace("@", "_at_")
        user_info["name"] = safe_user_name
        return user_info

    async def refresh_user(self, user, handler=None):
        auth_state = await user.get_auth_state()
        if not auth_state:
            return False
        threshold = 2 * self.auth_refresh_age
        now = time.time()
        rest_time = int(auth_state.get("exp", now)) - now
        if threshold >= rest_time:
            try:
                refresh_token_save = auth_state.get("refresh_token", None)
                self.log.debug(
                    f"Refresh {user.name} authentication. Rest time: {rest_time}"
                )
                if not refresh_token_save:
                    self.log.debug("Auth state has no refresh token. Return False.")
                    return False
                params = {
                    "refresh_token": auth_state.get("refresh_token"),
                    "grant_type": "refresh_token",
                    "scope": " ".join(self.scope),
                }
                headers = self._get_headers()
                try:
                    token_resp_json = await self._get_token(headers, params)
                except HTTPClientError:
                    self.log.exception("Could not receive new access token.")
                    return False
                user_data_resp_json = await self._get_user_data(token_resp_json)
                if callable(self.username_key):
                    name = self.username_key(user_data_resp_json)
                else:
                    name = user_data_resp_json.get(self.username_key)
                    if not name:
                        self.log.error(
                            "OAuth user contains no key %s: %s",
                            self.username_key,
                            user_data_resp_json,
                        )
                        return

                    if not token_resp_json.get("refresh_token", None):
                        token_resp_json["refresh_token"] = refresh_token_save
                    authentication = {
                        "auth_state": self._create_auth_state(
                            token_resp_json, user_data_resp_json
                        )
                    }
                    ret = await self.run_post_auth_hook(handler, authentication)
            except:
                self.log.exception(
                    "Refresh of user's {name} access token failed".format(
                        name=user.name
                    )
                )
                ret = False
        else:
            ret = True
        return ret

    async def post_auth_hook(self, authenticator, handler, authentication):
        access_token = authentication["auth_state"]["access_token"]
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": f"Bearer {access_token}",
        }
        req = HTTPRequest(self.tokeninfo_url, method="GET", headers=headers)
        try:
            resp = await authenticator.fetch(req)
        except HTTPClientError as e:
            authenticator.log.warning(
                "Could not request user information - {}".format(e)
            )
            raise Exception(e)
        authentication["auth_state"]["exp"] = resp.get("exp")
        authentication["auth_state"]["last_login"] = datetime.now().strftime(
            "%H:%M:%S %Y-%m-%d"
        )

        used_authenticator = (
            authentication["auth_state"]
            .get("oauth_user", {})
            .get("used_authenticator_attr", "unknown")
        )
        hpc_list = (
            authentication.get("auth_state", {})
            .get("oauth_user", {})
            .get("hpc_infos_attribute", [])
        )
        hpc_infos_via_unity = str(len(hpc_list) > 0).lower()
        handler.statsd.incr(f"login.authenticator.{used_authenticator}")
        handler.statsd.incr(f"login.hpc_infos_via_unity.{hpc_infos_via_unity}")

        username = authentication.get("name", "unknown")
        admin = authentication.get("admin", False)

        try:
            vo_active, vo_available = get_vos(
                authentication["auth_state"], self.custom_config, username, admin=admin
            )
        except VoException as e:
            authenticator.log.warning("Could not get vo for user - {}".format(e))
            raise e
        authentication["auth_state"]["vo_active"] = vo_active
        authentication["auth_state"]["vo_available"] = vo_available

        default_partitions = self.custom_config.get("default_partitions")
        to_add = []
        if type(hpc_list) == str:
            hpc_list = [hpc_list]
        elif type(hpc_list) == list and len(hpc_list) > 0 and len(hpc_list[0]) == 1:
            hpc_list = ["".join(hpc_list)]
        for entry in hpc_list:
            try:
                partition = re.search("[^,]+,([^,]+),[^,]+,[^,]+", entry).groups()[0]
            except:
                authenticator.log.info(
                    f"----- {username} - Failed to check for defaults partitions: {entry} ---- {hpc_list}"
                )
                continue
            if partition in default_partitions.keys():
                for value in default_partitions[partition]:
                    to_add.append(entry.replace(f",{partition},", ",{},".format(value)))
        hpc_list.extend(to_add)
        if hpc_list:
            authentication["auth_state"]["oauth_user"]["hpc_infos_attribute"] = hpc_list
            authenticator.log.info(
                "Added hpc infos to auth_state",
                extra={
                    "action": "hpcaccounts",
                    "username": username,
                    "hpc_list": hpc_list,
                },
            )

        return authentication
