import re
from .config import get_reservations, get_maintenance_list


def get_system_infos(log, custom_config, user_hpc_accounts, reservations_list):
    s = "^([^\,]+),([^\,]+),([^\,]+),([^\,]+)$"
    c = re.compile(s)

    def regroup(x):
        groups_ = list(c.match(x).groups())
        sys = custom_config.get("map_systems").get(groups_[1])
        if not sys:
            log.error(
                f"No system defined in custom config system map for {groups_[1]}"
            )
        partition = custom_config.get("map_partitions").get(groups_[1])
        if not partition:
            log.error(
                f"No system defined in custom config partition map for {groups_[1]}"
            )
        groups = [
            groups_[0], sys, partition, groups_[2].lower(), groups_[3],
        ]
        return groups

    user_hpc_list = [regroup(x) for x in user_hpc_accounts]

    systems_config = custom_config.get("systems")
    unicore_systems = list(sorted(
        {group[1] for group in user_hpc_list},
        key=lambda system: systems_config.get(
            "UNICORE", {}).get(system, {}).get("weight", 99)
    ))
    k8s_systems = list(systems_config.get("K8s", {}).keys())
    systems = unicore_systems + k8s_systems

    accounts = {
        system: sorted(
            {
                group[0] for group in user_hpc_list if system == group[1]
            }
        )
        for system in systems
    }

    projects = {
        system: {
            account: sorted(
                {
                    group[3] for group in user_hpc_list
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
                project: systems_config.get("UNICORE", {}).get(system, {}).get("interactive_partitions", []) + sorted(list(
                    {
                        group[2] for group in user_hpc_list
                        if system == group[1]
                        and account == group[0]
                        and project == group[3]
                        and group[2] in custom_config.get("resources").get(system, {}).keys()
                    })
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
                    partition: ["None"] + sorted(
                        [
                            x[0]
                            for x in reservations_list.get(system, [])
                            if (
                                (
                                    project in x[12].split(",")
                                    or account in x[11].split(",")
                                )
                                and ((not x[8]) or partition in x[8].split(","))
                            )
                        ]
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


async def get_options_form(spawner, service, service_info):
    auth_state = await spawner.user.get_auth_state()
    user_hpc_accounts = auth_state.get("oauth_user", {}).get(
        "hpc_infos_attribute", []
    )
    vo_active = auth_state.get("vo_active", None)

    custom_config = spawner.user.authenticator.custom_config
    vo_config = custom_config.get("vos")
    systems_config = custom_config.get("systems")
    resources = custom_config.get("resources")

    maintenance_list = get_maintenance_list()
    reservations_dict = get_reservations()
    reservations_list = {
        system: list(x.split(";") for x in reservations_dict.get(system, []))
        for system in reservations_dict.keys()
    }

    systems, accounts, projects, partitions, reservations = get_system_infos(
        spawner.log, custom_config, user_hpc_accounts, reservations_list)

    def in_both_lists(list1, list2):
        return list(set(list1).intersection(set(list2)))

    required_partitions = {}
    options = {}

    for option, infos in service_info.items():
        replace_allowed_lists = vo_config.get(vo_active, {}).get("Services", {}).get(
            service, {}).get(option, {}).get("replace_allowed_lists", {}).keys()

        # Check if the specific option is part of vo"s allowed services
        if option not in vo_config.get(vo_active, {}).get("Services", {}).get(service, {}).keys():
            continue

        # HPC systems
        if "systems" in replace_allowed_lists:
            allowed_lists_systems = vo_config.get(vo_active, {}).get("Services", {}).get(
                service, {}).get(option, {}).get("replace_allowed_lists", {})["systems"]
        else:
            allowed_lists_systems = infos.get(
                "allowed_lists", {}).get("systems", systems)
        systems_used = in_both_lists(systems, allowed_lists_systems)

        for system in systems_used:
            # Maintenance -> Not allowed
            if system in maintenance_list:
                continue

            if "accounts" in replace_allowed_lists:
                allowed_lists_accounts = vo_config.get(vo_active, {}).get("Services", {}).get(
                    service, {}).get(option, {}).get("replace_allowed_lists", {})["accounts"]
            else:
                allowed_lists_accounts = infos.get(
                    "allowed_lists", {}).get("accounts", accounts[system])
            accounts_used = in_both_lists(
                accounts[system], allowed_lists_accounts)

            for account in accounts_used:
                if "projects" in replace_allowed_lists:
                    allowed_lists_projects = vo_config.get(vo_active, {}).get("Services", {}).get(
                        service, {}).get(option, {}).get("replace_allowed_lists", {})["projects"]
                else:
                    allowed_lists_projects = infos.get("allowed_lists", {}).get(
                        "projects", projects[system][account])
                projects_used = in_both_lists(
                    projects[system][account], allowed_lists_projects)

                for project in projects_used:
                    if "partitions" in replace_allowed_lists:
                        allowed_lists_partitions = vo_config.get(vo_active, {}).get("Services", {}).get(
                            service, {}).get(option, {}).get("replace_allowed_lists", {})["partitions"]
                    else:
                        allowed_lists_partitions = infos.get("allowed_lists", {}).get(
                            "partitions", partitions[system][account][project])
                    partitions_used = in_both_lists(
                        partitions[system][account][project], allowed_lists_partitions)

                    for partition in partitions_used:
                        if "reservations" in replace_allowed_lists:
                            allowed_lists_reservations = vo_config.get(vo_active, {}).get("Services", {}).get(
                                service, {}).get(option, {}).get("replace_allowed_lists", {})["reservations"]
                        else:
                            allowed_lists_reservations = infos.get("allowed_lists", {}).get(
                                "reservations", reservations[system][account][project][partition])
                        reservations_used = in_both_lists(
                            reservations[system][account][project][partition], allowed_lists_reservations)
                        if "reservations" in replace_allowed_lists and len(reservations_used) == 0:
                            # Dashboards expects specific reservations which we don"t have
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
                        options[option][system][account][project][partition] = reservations_used

        # Cloud systems
        if "systems" in replace_allowed_lists:
            allowed_lists_systems = vo_config.get(vo_active, {}).get("Services", {}).get(
                service, {}).get(option, {}).get("replace_allowed_lists", {})["systems"]
        else:
            allowed_lists_systems = infos.get("allowed_lists", {}).get(
                "systems", systems_config.get("K8s", {}).keys())
        systems_used = in_both_lists(systems_config.get(
            "K8s", {}).keys(), allowed_lists_systems)

        for system in systems_used:
            if option not in options.keys():
                options[option] = {}
            if system not in options[option].keys():
                options[option][system] = {}

    if not options:
        return {
            "options": {},
            "maintenance": maintenance_list,
            "message": f"The {vo_active} group does not support {service} services."
        }

    def replace_resource(option, system, partition, resource, key):
        value = resources[system][partition][resource][key]
        if type(value) is int or type(value) is list:
            if resource in vo_config.get(vo_active, {}).get("Services", {}).get(service, {}).get(option, {}).get("replace_resources", {}).get(system, {}).get(partition, {}).keys():
                if key == "minmax":
                    value = vo_config.get(vo_active, {}).get("Services", {}).get(service, {}).get(
                        option, {}).get("replace_resources", {}).get(system, {}).get(partition, {})[resource]
                    if type(value) == list and len(value) > 0 and type(value[0]) == list:
                        value = value[0]
                elif key == "default":
                    value = vo_config.get(vo_active, {}).get("Services", {}).get(service, {}).get(
                        option, {}).get("replace_resources", {}).get(system, {}).get(partition, {})[resource]
                    if type(value) == list and len(value) > 0 and type(value[0]) == list:
                        value = value[1]
                    else:
                        value = value[0]
            return value
        else:
            if resource in vo_config.get(vo_active, {}).get("Services", {}).get(service, {}).get(option, {}).get("replace_resources", {}).get(system, {}).get(partition, {}).keys():
                minmax = vo_config.get(vo_active, {}).get("Services", {}).get(service, {}).get(
                    option, {}).get("replace_resources", {}).get(system, {}).get(partition, {})[resource]
                if type(minmax) == list and len(minmax) > 0 and type(minmax[0]) == list:
                    minmax = minmax[0]
            else:
                minmax = resources[system][partition][resource]["minmax"]
            return value.replace("_min_", str(minmax[0])).replace("_max_", str(minmax[1]))

    resources_replaced = {
        option: {
            system: {
                partition: {
                    resource: {
                        key: replace_resource(
                            option, system, partition, resource, key)
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
        "systems": systems,
        "accounts": accounts,
        "projects": projects,
        "partitions": partitions,
        "reservations": reservations,
    }

    return {
        "dropdown_lists": dropdown_lists,
        "reservations": reservations_list,
        "resources": resources_replaced,
        "maintenance": maintenance_list
    }


async def get_options_from_form(formdata, custom_config):
    systems_config = custom_config.get("systems")
    resources = custom_config.get("resources")

    def skip_resources(key, value):
        system = formdata.get("system_input")[0]
        partition = formdata.get("partition_input")[0]
        if key.startswith("resource_"):
            if system not in systems_config.get("UNICORE", {}).keys():
                return True
            elif partition in systems_config.get("UNICORE", {}).get(system, {}).get("interactive_partitions", []):
                return True
            else:
                resource_name = key[len("resource_"):]
                if (
                    resource_name not in resources.get(
                        system.upper()).get(partition).keys()
                ):
                    return True
        else:
            if value in ["undefined", "None"]:
                return True
        return False

    def runtime_update(key, value_list):
        if key == "resource_runtime":
            return int(value_list[0]) * 60
        return value_list[0]

    return {
        key: runtime_update(key, value)
        for key, value in formdata.items()
        if not skip_resources(key, value[0])
    }