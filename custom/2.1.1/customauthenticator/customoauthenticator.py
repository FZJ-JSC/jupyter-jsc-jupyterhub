import copy
import json
import os
import re
from datetime import datetime
from datetime import timedelta

from custom_utils import get_vos, VoException
from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.oauth2 import OAuthLoginHandler, OAuthLogoutHandler
from oauthenticator.traitlets import Callable
from tornado.httpclient import HTTPClientError
from tornado.httpclient import HTTPRequest
from traitlets import Dict
from traitlets import Unicode
from traitlets import Union
from urllib.error import HTTPError
from urllib.parse import urlencode


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
    async def revoke_unity_tokens(self, all_devices=False, stop_all=False):
        user = self.current_user
        if not user:
            self.log.debug("Could not retrieve current user for logout call.")
            return

        if user.authenticator.enable_auth_state:
            auth_state = await user.get_auth_state()
            tokens = {}

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
            if stop_all:
                await self._shutdown_servers(user)

            custom_config = user.authenticator.custom_config
            unity_revoke_config = custom_config.get("unity", {}).get("revoke", {})

            unity_revoke_url = unity_revoke_config.get("url", "")
            unity_revoke_certificate = unity_revoke_config.get("certificate_path", False)
            unity_revoke_request_timeout = unity_revoke_config.get("request_timeout", 10)
            unity_revoke_expected_status_code = unity_revoke_config.get("expected_status_code", 200)
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
                    self.log.critical(f"Could not revoke token", extra=log_extras, exc_info=True)
                except:
                    self.log.critical("Could not revoke token.", extra=log_extras, exc_info=True)
                else:
                    self.log.debug(f"Unity revoke {key} call successful.", extra=log_extras)
        await user.save_auth_state(auth_state)

    async def get(self):
        all_devices = self.get_argument("alldevices", "false").lower() == "true"
        stop_all = self.get_argument("stopall", "false").lower() == "true"
        await self.revoke_unity_tokens(all_devices, stop_all)
        return await super().get()


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

    async def refresh_user(self, user, handler=None):
        return await super().refresh_user(user, handler)

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
            authenticator.log.warning(
                "Could not get vo for user - {}".format(e)
            )
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

        authenticator.log.info(authentication)
        return authentication