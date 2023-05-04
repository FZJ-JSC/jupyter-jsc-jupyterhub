import copy
import logging
import os
import re
import time
from datetime import datetime
from urllib.error import HTTPError
from urllib.parse import urlencode

from jupyterhub.utils import new_token
from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.oauth2 import OAuthLoginHandler
from oauthenticator.oauth2 import OAuthLogoutHandler
from oauthenticator.traitlets import Callable
from tornado.httpclient import HTTPClientError
from tornado.httpclient import HTTPRequest
from traitlets import Dict
from traitlets import Unicode
from traitlets import Union

from ..misc import _custom_config_file
from ..misc import _reservations_file
from ..misc import get_custom_config
from ..misc import get_incidents
from ..misc import get_reservations


def get_system_infos(
    log, custom_config, user_hpc_accounts, reservations_dict, incidents_list
):
    s = "^([^\,]+),([^\,]+),([^\,]+),([^\,]+)$"
    c = re.compile(s)

    def regroup(x):
        groups_ = list(c.match(x).groups())
        sys = custom_config.get("map_systems").get(groups_[1])
        if sys not in custom_config.get("systems", {}).keys():
            # If system is not in systems, we don't need these accounts
            return []
        if not sys:
            log.error(f"No system defined in custom config system map for {groups_[1]}")
        partition = custom_config.get("map_partitions").get(groups_[1])
        if not partition:
            log.error(
                f"No system defined in custom config partition map for {groups_[1]}"
            )
        groups = [
            groups_[0],
            sys,
            partition,
            groups_[2].lower(),
            groups_[3],
        ]
        return groups

    user_hpc_list_incl_empty = [regroup(x) for x in user_hpc_accounts]
    user_hpc_list = [x for x in user_hpc_list_incl_empty if x]

    systems_config = custom_config.get("systems")
    # Sort UNICORE systems first
    systems_all = list(
        sorted(
            {group[1] for group in user_hpc_list if group[1] is not None},
            key=lambda system: systems_config.get(system, {}).get("weight", 99),
        )
    )
    # Then add K8s systems
    for system, config in systems_config.items():
        if system not in systems_all and config.get("drf-service", "") != "unicoremgr":
            systems_all.append(system)

    # Remove systems which are in maintenance
    systems = [x for x in systems_all if x not in incidents_list]

    accounts = {
        system: sorted({group[0] for group in user_hpc_list if system == group[1]})
        for system in systems
    }

    projects = {
        system: {
            account: sorted(
                {
                    group[3]
                    for group in user_hpc_list
                    if system == group[1] and account == group[0]
                }
            )
            for account in accounts[system]
        }
        for system in systems
    }

    partitions = {
        system: {
            account: {
                project: systems_config.get(system, {}).get(
                    "interactive_partitions", []
                )
                + sorted(
                    list(
                        {
                            group[2]
                            for group in user_hpc_list
                            if system == group[1]
                            and account == group[0]
                            and project == group[3]
                            and group[2]
                            in custom_config.get("resources").get(system, {}).keys()
                        }
                    )
                )
                for project in projects[system][account]
            }
            for account in accounts[system]
        }
        for system in systems
    }

    reservations = {
        system: {
            account: {
                project: {
                    partition: ["None"]
                    + sorted(
                        [
                            x
                            for x in reservations_dict.get(system, [])
                            if (
                                (
                                    project in x.get("Accounts", "").split(",")
                                    or account in x.get("Users", "").split(",")
                                )
                                and (
                                    (not x.get("PartitionName", ""))
                                    or partition
                                    in x.get("PartitionName", "").split(",")
                                )
                            )
                        ],
                        key=lambda x: x["ReservationName"],
                    )
                    for partition in partitions[system][account][project]
                }
                for project in projects[system][account]
            }
            for account in accounts[system]
        }
        for system in systems
    }

    return systems, accounts, projects, partitions, reservations


async def get_options_form(auth_log, service, vo_active, user_hpc_accounts):
    custom_config = get_custom_config()
    vo_config = custom_config.get("vos")
    resources = custom_config.get("resources")

    incidents_list = get_incidents()
    reservations_dict = get_reservations()

    systems, accounts, projects, partitions, reservations = get_system_infos(
        auth_log,
        custom_config,
        user_hpc_accounts,
        reservations_dict,
        incidents_list,
    )

    def in_both_lists(list1, list2):
        return list(set(list1).intersection(set(list2)))

    # Need this to manually create set of list if the list contains a dict
    # since all elements of a set must be hashable and a dict is not
    def create_set(list):
        unique_list = []
        for entry in list:
            if entry not in unique_list:
                unique_list.append(entry)
        return unique_list

    required_partitions = {}
    options = {}

    service_info = custom_config.get("services", {}).get(service, {}).get("options", {})
    for option, infos in service_info.items():
        replace_allowed_lists = (
            vo_config.get(vo_active, {})
            .get("Services", {})
            .get(service, {})
            .get(option, {})
            .get("replace_allowed_lists", {})
            .keys()
        )

        # Check if the specific option is part of vo"s allowed services
        if (
            option
            not in vo_config.get(vo_active, {})
            .get("Services", {})
            .get(service, {})
            .keys()
        ):
            continue

        if "systems" in replace_allowed_lists:
            allowed_lists_systems = (
                vo_config.get(vo_active, {})
                .get("Services", {})
                .get(service, {})
                .get(option, {})
                .get("replace_allowed_lists", {})["systems"]
            )
        else:
            allowed_lists_systems = infos.get("allowed_lists", {}).get(
                "systems", systems
            )
        systems_used = in_both_lists(systems, allowed_lists_systems)

        for system in systems_used:
            # Maintenance -> Not allowed
            if system in incidents_list:
                continue

            if "accounts" in replace_allowed_lists:
                allowed_lists_accounts = (
                    vo_config.get(vo_active, {})
                    .get("Services", {})
                    .get(service, {})
                    .get(option, {})
                    .get("replace_allowed_lists", {})["accounts"]
                )
            else:
                allowed_lists_accounts = infos.get("allowed_lists", {}).get(
                    "accounts", accounts[system]
                )
            accounts_used = in_both_lists(accounts[system], allowed_lists_accounts)

            for account in accounts_used:
                if "projects" in replace_allowed_lists:
                    allowed_lists_projects = (
                        vo_config.get(vo_active, {})
                        .get("Services", {})
                        .get(service, {})
                        .get(option, {})
                        .get("replace_allowed_lists", {})["projects"]
                    )
                else:
                    allowed_lists_projects = infos.get("allowed_lists", {}).get(
                        "projects", projects[system][account]
                    )
                projects_used = in_both_lists(
                    projects[system][account], allowed_lists_projects
                )

                for project in projects_used:
                    if "partitions" in replace_allowed_lists:
                        allowed_lists_partitions = (
                            vo_config.get(vo_active, {})
                            .get("Services", {})
                            .get(service, {})
                            .get(option, {})
                            .get("replace_allowed_lists", {})["partitions"]
                        )
                    else:
                        allowed_lists_partitions = infos.get("allowed_lists", {}).get(
                            "partitions", partitions[system][account][project]
                        )
                    partitions_used = in_both_lists(
                        partitions[system][account][project], allowed_lists_partitions
                    )

                    for partition in partitions_used:
                        if "reservations" in replace_allowed_lists:
                            allowed_lists_reservations = (
                                vo_config.get(vo_active, {})
                                .get("Services", {})
                                .get(service, {})
                                .get(option, {})
                                .get("replace_allowed_lists", {})["reservations"]
                            )
                        else:
                            allowed_lists_reservations = infos.get(
                                "allowed_lists", {}
                            ).get(
                                "reservations",
                                reservations[system][account][project][partition],
                            )
                        reservations_used = [
                            value
                            for value in create_set(
                                reservations[system][account][project][partition]
                            )
                            if value in create_set(allowed_lists_reservations)
                        ]
                        if (
                            "reservations" in replace_allowed_lists
                            and len(reservations_used) == 0
                        ):
                            # Dashboards expects specific reservations which we don't have
                            continue

                        if option not in options.keys():
                            options[option] = {}
                        if system not in options[option].keys():
                            options[option][system] = {}
                        if account not in options[option][system].keys():
                            options[option][system][account] = {}
                        if project not in options[option][system][account].keys():
                            options[option][system][account][project] = {}
                        if system not in required_partitions.keys():
                            required_partitions[system] = []
                        if partition not in required_partitions[system]:
                            required_partitions[system].append(partition)
                        options[option][system][account][project][
                            partition
                        ] = reservations_used

        for system in systems_used:
            if option not in options.keys():
                options[option] = {}
            if system not in options[option].keys() and system not in incidents_list:
                options[option][system] = {}

    if not options:
        return {
            "options": {},
            "maintenance": incidents_list,
            "message": f"The {vo_active} group does not support {service} services.",
        }

    def replace_resource(option, system, partition, resource, key):
        value = resources[system][partition][resource][key]
        if type(value) is int or type(value) is list:
            if (
                resource
                in vo_config.get(vo_active, {})
                .get("Services", {})
                .get(service, {})
                .get(option, {})
                .get("replace_resources", {})
                .get(system, {})
                .get(partition, {})
                .keys()
            ):
                if key == "minmax":
                    value = (
                        vo_config.get(vo_active, {})
                        .get("Services", {})
                        .get(service, {})
                        .get(option, {})
                        .get("replace_resources", {})
                        .get(system, {})
                        .get(partition, {})[resource]
                    )
                    if (
                        type(value) == list
                        and len(value) > 0
                        and type(value[0]) == list
                    ):
                        value = value[0]
                elif key == "default":
                    value = (
                        vo_config.get(vo_active, {})
                        .get("Services", {})
                        .get(service, {})
                        .get(option, {})
                        .get("replace_resources", {})
                        .get(system, {})
                        .get(partition, {})[resource]
                    )
                    if (
                        type(value) == list
                        and len(value) > 0
                        and type(value[0]) == list
                    ):
                        value = value[1]
                    else:
                        value = value[0]
            return value
        else:
            if (
                resource
                in vo_config.get(vo_active, {})
                .get("Services", {})
                .get(service, {})
                .get(option, {})
                .get("replace_resources", {})
                .get(system, {})
                .get(partition, {})
                .keys()
            ):
                minmax = (
                    vo_config.get(vo_active, {})
                    .get("Services", {})
                    .get(service, {})
                    .get(option, {})
                    .get("replace_resources", {})
                    .get(system, {})
                    .get(partition, {})[resource]
                )
                if type(minmax) == list and len(minmax) > 0 and type(minmax[0]) == list:
                    minmax = minmax[0]
            else:
                minmax = resources[system][partition][resource]["minmax"]
            if type(value) == str:
                return value.replace("_min_", str(minmax[0])).replace(
                    "_max_", str(minmax[1])
                )
            else:
                return value

    resources_replaced = {
        option: {
            system: {
                partition: {
                    resource: {
                        key: replace_resource(option, system, partition, resource, key)
                        for key in resources[system][partition][resource].keys()
                    }
                    for resource in resources[system][partition].keys()
                }
                for partition in required_partitions.get(system, [])
            }
            for system, _partitions in _systems.items()
        }
        for option, _systems in options.items()
    }

    dropdown_lists = {
        "options": options,
    }

    return {
        "dropdown_lists": dropdown_lists,
        "reservations": reservations_dict,
        "resources": resources_replaced,
        "maintenance": incidents_list,
    }


class VoException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)


def get_vos(auth_state, username, admin):
    custom_config = get_custom_config()
    used_authenticator = auth_state.get("oauth_user", {}).get(
        "used_authenticator_attr", "unknown"
    )
    vo_config = custom_config.get("vos", {})

    vos_with_weight = []
    for vo_name, vo_infos in vo_config.items():
        if (
            used_authenticator in vo_infos.get("authenticators", [])
            or username in vo_infos.get("usernames", [])
            or (admin and vo_infos.get("admin", False))
        ):
            vos_with_weight.append((vo_name, vo_infos.get("weight", 99)))
    vos_with_weight.sort(key=lambda x: x[1])

    vo_available = []
    for x in vos_with_weight:
        vo_available.append(x[0])
        if vo_config.get(x[0], {}).get("exclusive", False):
            vo_available = [x[0]]
            break
    if len(vo_available) == 0:
        raise VoException(f"No vo available for user {username}")

    vo_active = auth_state.get("vo_active", None)
    if not vo_active or vo_active not in vo_available:
        vo_active = vo_available[0]
    return vo_active, vo_available


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

            unity_revoke_config = get_custom_config().get("unity", {}).get("revoke", {})
            unity_revoke_url = unity_revoke_config.get("url", "")
            unity_revoke_request_kwargs = unity_revoke_config.get("request_kwargs", {})
            unity_revoke_expected_status_code = unity_revoke_config.get(
                "expected_status_code", 200
            )
            client_id = unity_revoke_config.get("client_id", "oauth-client")

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            data = {"client_id": client_id, "logout": "true"}

            log_extras = {
                "unity_revoke_url": unity_revoke_url,
                "unity_revoke_request_kwargs": unity_revoke_request_kwargs,
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
                        **unity_revoke_request_kwargs,
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


class CustomGenericOAuthenticator(GenericOAuthenticator):
    login_handler = CustomLoginHandler
    logout_handler = CustomLogoutHandler

    tokeninfo_url = Unicode(
        config=True,
        help="""The url retrieving information about the access token""",
    )

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

    true_auth_refresh_age = 300

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.true_auth_refresh_age = self.auth_refresh_age
        self.auth_refresh_age = 1

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

    async def update_auth_state_custom_config(self, authentication, force=False):
        update_authentication = False
        last_change_reservation = os.path.getmtime(_reservations_file)
        if (
            force
            or authentication["auth_state"].get("reservation_update", 0)
            < last_change_reservation
        ):
            hpc_list = (
                authentication["auth_state"]
                .get("oauth_user", {})
                .get("hpc_infos_attribute", [])
            )
            authentication["auth_state"]["options_form"] = await get_options_form(
                auth_log=self.log,
                service="JupyterLab",
                vo_active=authentication["auth_state"]["vo_active"],
                user_hpc_accounts=hpc_list,
            )
            authentication["auth_state"]["reservation_update"] = last_change_reservation
            update_authentication = True

        last_change = os.path.getmtime(_custom_config_file)
        if (
            force
            or authentication["auth_state"].get("custom_config_update", 0) < last_change
        ):
            if "custom_config" not in authentication["auth_state"].keys():
                authentication["auth_state"]["custom_config"] = {}
            custom_config = get_custom_config()
            custom_config_auth_state_keys = custom_config.get(
                "auth_state_keys",
                [
                    "services",
                    "additional_spawn_options",
                    "announcement",
                    "vos",
                    "systems",
                ],
            )
            for key in custom_config_auth_state_keys:
                if key in custom_config.keys():
                    authentication["auth_state"]["custom_config"][key] = custom_config[
                        key
                    ]
            authentication["auth_state"]["custom_config_update"] = last_change
            update_authentication = True
        if update_authentication:
            return authentication
        else:
            return True

    async def refresh_user(self, user, handler=None):
        # We use refresh_user to update auth_state, even if
        # the access token is not outdated yet.
        auth_state = await user.get_auth_state()
        if not auth_state:
            return False
        authentication = {"auth_state": auth_state}
        threshold = 2 * self.true_auth_refresh_age
        now = time.time()
        rest_time = int(auth_state.get("exp", now)) - now
        if threshold > rest_time:
            ## New access token required
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
                    authentication["auth_state"] = self._create_auth_state(
                        token_resp_json, user_data_resp_json
                    )
                    ret = await self.run_post_auth_hook(handler, authentication)
            except:
                self.log.exception(
                    "Refresh of user's {name} access token failed".format(
                        name=user.name
                    )
                )
                ret = False
        else:
            # Update custom config, if neccessary
            ret = await self.update_auth_state_custom_config(authentication)
        return ret

    async def post_auth_hook(self, authenticator, handler, authentication):
        # After the user was authenticated we collect additional information
        #  - expiration of access token (so we can renew it before it expires)
        #  - last login (additional information for the user)
        #  - used authenticator (to classify user)
        #  - hpc_list (allowed systems, projects, partitions, etc.)
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

        # In this part we classify the user in specific VOs.
        # This has to be replaced with the official JHub RBAC feature

        username = authentication.get("name", "unknown")
        try:
            vo_active, vo_available = get_vos(
                authentication["auth_state"],
                username,
                authentication.get("admin", False),
            )
        except VoException as e:
            self.log.warning("Could not get vo for user - {}".format(e))
            raise e
        authentication["auth_state"]["vo_active"] = vo_active
        authentication["auth_state"]["vo_available"] = vo_available

        # Now we collect the hpc_list information and create a useful python dict from it
        ## First let's add some "default_partitions", that should be added to each user,
        ## even if it's listed in hpc_list
        custom_config = get_custom_config()
        default_partitions = custom_config.get("default_partitions")
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

        ## With this list we can now create the spawner.options_form value.
        ## We will store this in the auth_state instead of the Spawner:
        ##
        ## - We want to skip the spawn.html ("Server Options") page. The user should
        ##   configure the JupyterLab on /hub/home and we redirect directly to spawn_pending.
        ##   Spawner.get_options_form is an async function, so we cannot call it in Jinja.
        ##   We will start Spawner Objects via query_options/form_options, so no need for user_options
        ##   in the SpawnerClass.
        ##

        ## Currently we only support JupyterLab, we have to update this in the future
        ## if we want to support multiple services.
        last_change_reservation = os.path.getmtime(_reservations_file)
        authentication["auth_state"]["reservation_update"] = last_change_reservation
        authentication["auth_state"]["options_form"] = await get_options_form(
            auth_log=self.log,
            service="JupyterLab",
            vo_active=vo_active,
            user_hpc_accounts=hpc_list,
        )

        ## We have a few custom config features on the frontend. For this, we have to store
        ## (parts of) the custom_config in the user's auth state
        authentication = await self.update_auth_state_custom_config(
            authentication, force=True
        )

        return authentication
