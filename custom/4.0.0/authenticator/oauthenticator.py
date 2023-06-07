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


async def get_options_form(auth_log, service, groups, user_hpc_accounts):
    custom_config = get_custom_config()
    groups_config = custom_config.get("groups")
    resources = custom_config.get("resources")

    incidents_dict = get_incidents()
    threshold_health = incidents_dict.get("threshold", 0)
    systems_list = [*custom_config.get("systems", {})]
    incidents_list = [
        x
        for x in systems_list
        if incidents_dict.get(x, {}).get("health", threshold_health - 1)
        >= threshold_health
    ]
    reservations_dict = get_reservations()

    (
        systems_default,
        accounts_default,
        projects_default,
        partitions_default,
        reservations_default,
    ) = get_system_infos(
        auth_log,
        custom_config,
        user_hpc_accounts,
        reservations_dict,
        incidents_list,
    )

    def in_both_lists(list1, list2):
        try:
            return list(set(list1).intersection(set(list2)))
        except TypeError:
            return list(
                set([tuple(x) for x in list1]).intersection(
                    set([tuple(x) for x in list2])
                )
            )

    # Need this to manually create set of list if the list contains a dict
    # since all elements of a set must be hashable and a dict is not
    def unique_list(list):
        unique_list = []
        for entry in list:
            if entry not in unique_list:
                unique_list.append(entry)
        return unique_list

    required_partitions = {}
    options = {}

    def get_allowed_values(option_config, key, default_values=[]):
        values_via_service = []
        values_via_groups = []
        values_via_service += infos.get("allowed_lists", {}).get(key, default_values)
        values_via_service = unique_list(values_via_service)
        values_via_groups = [
            *option_config.get("replace_allowed_lists", {}).get(key, values_via_service)
        ]
        values_via_groups = unique_list(values_via_groups)
        return in_both_lists(values_via_service, values_via_groups)

    service_info = custom_config.get("services", {}).get(service, {}).get("options", {})
    for group in groups:
        for option, infos in service_info.items():
            option_config = (
                groups_config.get(group, {})
                .get("services", {})
                .get(service, {})
                .get(option, {})
            )
            if not option_config:
                continue
            # Collect the default systems for the service.
            # Collect the systems allowed for each group.
            # Combine them to the actual allowed systems list
            systems = get_allowed_values(option_config, "systems", systems_default)

            for system in systems:
                # Maintenance -> Not allowed
                if system in incidents_list:
                    continue

                # if not HPC system: add it
                if (
                    custom_config.get("systems", {})
                    .get(system, {})
                    .get("drf-service", "")
                    != "unicoremgr"
                ):
                    if option not in options.keys():
                        options[option] = {}
                    if system not in options[option].keys():
                        options[option][system] = {}

                # Do the same for accounts, what we did for the systems before
                accounts = get_allowed_values(
                    option_config, "accounts", accounts_default.get(system, [])
                )

                for account in accounts:
                    projects = get_allowed_values(
                        option_config, "projects", projects_default[system][account]
                    )

                    for project in projects:
                        partitions = get_allowed_values(
                            option_config,
                            "partitions",
                            partitions_default[system][account][project],
                        )

                        for partition in partitions:
                            reservations = reservations_default[system][account][
                                project
                            ][partition]

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
                            ] = reservations

    if not options:
        return {
            "message": f"The groups does not support {service} services.",
            "dropdown_list": {},
            "resources": {},
            "reservations": {},
        }

    def replace_resources(service, option, system, partition, resource, key):
        group_values = []
        default_resource_value = resources[system][partition][resource][key]
        for group in groups:
            group_specific_value = (
                groups_config.get(group, {})
                .get("services", {})
                .get(service, {})
                .get(option, {})
                .get("replace_resources", {})
                .get(system, {})
                .get(partition, {})
                .get(resource, {})
                .get(key, default_resource_value)
            )
            # for resources other than minmax we have to override the default with the first hit.
            # The groups are sorted by weight (ascending)
            if key != "minmax":
                if group_specific_value != default_resource_value:
                    return group_specific_value
            else:
                group_values.append(group_specific_value)
        if key == "minmax":
            group_values = unique_list(group_values)
            # minmax is a list within a list. We want to get the
            # lowest min and the highest max value
            min_ = [x[0] for x in group_values]
            max_ = [x[1] for x in group_values]
            return [min(min_), max(max_)]
        else:
            # use default value, since group_specific_value was always == default_resource_value
            return default_resource_value

    resources_replaced = {
        option: {
            system: {
                partition: {
                    resource: {
                        key: replace_resources(
                            service, option, system, partition, resource, key
                        )
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

    return {
        "dropdown_list": options,
        "reservations": reservations_dict,
        "resources": resources_replaced,
    }


class VoException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)


def get_groups(auth_state, admin):
    custom_config = get_custom_config()
    used_authenticator = auth_state.get("oauth_user", {}).get(
        "used_authenticator_attr", "unknown"
    )
    groups_config = custom_config.get("groups", {})
    username = auth_state["name"]
    groups_available = []
    for name, infos in groups_config.items():
        if (
            used_authenticator in infos.get("authenticators", [])
            or username in infos.get("usernames", [])
            or (admin and infos.get("admin", False))
        ):
            groups_available.append((name, infos.get("weight", 99)))
    groups_available.sort(key=lambda x: x[1])

    groups = []
    for x in groups_available:
        groups.append(x[0])
        if groups_config.get(x[0], {}).get("exclusive", False):
            groups = [x[0]]
            break
    if len(groups) == 0:
        raise VoException(f"No group available for user {username}")

    return groups


def get_services(auth_state, custom_config):
    ## We want to be able to offer multiple service types.
    ## We use all services listed in custom_config.groups.group
    services_available = []
    service_active = ""
    for group in auth_state["groups"]:
        # If a group sets a specific default_service we will use this one
        service_active = (
            custom_config.get("groups", {}).get(group, {}).get("default_service", "")
        )
        if service_active:
            break
        # otherwise we collect all available services
        services_available += [
            *custom_config.get("groups", {}).get(group, {}).get("services", {})
        ]
    if not service_active:
        # if no default service is set, we remove duplicated services
        services_available = list(set(services_available))
        # sort them by weight
        services_weight = [
            (x, custom_config.get("services", {}).get("weight", 99))
            for x in services_available
        ]
        services_weight.sort(key=lambda x: x[1])
        services_available = [x[0] for x in services_weight]
        if services_weight:
            # and use the first service by weight
            service_active = services_available[0]
        else:
            # if no services are defined in the specific groups, we just use JupyterLab.
            service_active = "JupyterLab"
    return service_active, services_available


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

    async def update_auth_state_custom_config(self, authentication, force=False):
        update_authentication = False
        try:
            last_change_reservation = os.path.getmtime(_reservations_file)
        except:
            last_change_reservation = 0
        try:
            last_change_custom_config = os.path.getmtime(_custom_config_file)
        except:
            last_change_custom_config = 0

        if (
            force
            or authentication["auth_state"].get("custom_config_update", 0)
            < last_change_custom_config
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
                    "groups",
                    "systems",
                ],
            )
            for key in custom_config_auth_state_keys:
                if key in custom_config.keys():
                    authentication["auth_state"]["custom_config"][key] = custom_config[
                        key
                    ]
            authentication["auth_state"][
                "custom_config_update"
            ] = last_change_custom_config
            authentication["auth_state"]["reservation_update"] = last_change_reservation

            # Custom config update may have changed the resources we want to offer
            hpc_list = (
                authentication["auth_state"]
                .get("oauth_user", {})
                .get("hpc_infos_attribute", [])
            )
            authentication["auth_state"]["groups"] = get_groups(
                authentication["auth_state"],
                authentication.get("admin", False),
            )
            authentication["groups"] = authentication["auth_state"]["groups"]
            service_active, services_available = get_services(
                authentication["auth_state"], custom_config
            )
            authentication["auth_state"]["service_active"] = service_active
            authentication["auth_state"]["services_available"] = services_available
            authentication["auth_state"]["options_form"] = await get_options_form(
                auth_log=self.log,
                service=authentication["auth_state"]["service_active"],
                groups=authentication["auth_state"]["groups"],
                user_hpc_accounts=hpc_list,
            )
            update_authentication = True
        elif (
            authentication["auth_state"].get("reservation_update", 0)
            < last_change_reservation
        ):
            hpc_list = (
                authentication["auth_state"]
                .get("oauth_user", {})
                .get("hpc_infos_attribute", [])
            )
            authentication["auth_state"]["options_form"] = await get_options_form(
                auth_log=self.log,
                service=authentication["auth_state"]["service_active"],
                groups=authentication["auth_state"]["groups"],
                user_hpc_accounts=hpc_list,
            )
            authentication["auth_state"]["reservation_update"] = last_change_reservation
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

                authentication["name"] = name
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
            try:
                ret = await self.update_auth_state_custom_config(authentication)
            except:
                self.log.exception("Could not update user auth_state, log out")
                ret = False
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

        authentication["auth_state"]["name"] = authentication["name"]
        # In this part we classify the user in specific groups.
        try:
            authentication["auth_state"]["groups"] = get_groups(
                authentication["auth_state"],
                authentication.get("admin", False),
            )
        except VoException as e:
            self.log.warning("Could not get groups for user - {}".format(e))
            raise e
        authentication["groups"] = authentication["auth_state"]["groups"]
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
                    f"----- {authentication['name']} - Failed to check for defaults partitions: {entry} ---- {hpc_list}"
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
                    "username": authentication["name"],
                    "hpc_list": hpc_list,
                },
            )

        service_active, services_available = get_services(
            authentication["auth_state"], custom_config
        )
        authentication["auth_state"]["service_active"] = service_active
        authentication["auth_state"]["services_available"] = services_available

        ## With this list we can now create the spawner.options_form value.
        ## We will store this in the auth_state instead of the Spawner:
        ##
        ## - We want to skip the spawn.html ("Server Options") page. The user should
        ##   configure the JupyterLab on /hub/home and we redirect directly to spawn_pending.
        ##   Spawner.get_options_form is an async function, so we cannot call it in Jinja.
        ##   We will start Spawner Objects via query_options/form_options, so no need for user_options
        ##   in the SpawnerClass.
        ##

        try:
            last_change_reservation = os.path.getmtime(_reservations_file)
        except:
            last_change_reservation = 0
        authentication["auth_state"]["reservation_update"] = last_change_reservation
        authentication["auth_state"]["options_form"] = await get_options_form(
            auth_log=self.log,
            service=authentication["auth_state"]["service_active"],
            groups=authentication["auth_state"]["groups"],
            user_hpc_accounts=hpc_list,
        )

        ## We have a few custom config features on the frontend. For this, we have to store
        ## (parts of) the custom_config in the user's auth state
        authentication = await self.update_auth_state_custom_config(
            authentication, force=True
        )

        return authentication
