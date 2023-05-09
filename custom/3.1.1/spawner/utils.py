import asyncio

from ..misc import get_custom_config

_spawner_events = {}


def get_spawner_events(user_id):
    global _spawner_events
    if user_id not in _spawner_events.keys():
        _spawner_events[user_id] = {
            "start": asyncio.Event(),
        }
    return _spawner_events[user_id]


def check_formdata_keys(data):
    keys = data.keys()
    systems_config = get_custom_config().get("systems")
    unicore_systems = [
        system
        for system in systems_config
        if systems_config[system].get("drf-service", None) == "unicoremgr"
    ]
    required_keys = {"name", "service", "system"}
    if data.get("system") in unicore_systems:
        required_keys = required_keys | {"account", "project", "partition"}
    allowed_keys = required_keys | {
        "reservation",
        "nodes",
        "gpus",
        "runtime",
        "xserver",
        "additional_spawn_options",
    }

    if not required_keys <= keys:
        raise KeyError(f"Keys must include {required_keys}, but got {keys}.")
    if not keys <= allowed_keys:
        raise KeyError(f"Got keys {keys}, but only {allowed_keys} are allowed.")


async def get_options_from_form(formdata):
    check_formdata_keys(formdata)

    custom_config = get_custom_config()
    systems_config = custom_config.get("systems")
    resources = custom_config.get("resources")

    def skip_resources(key, value):
        system = formdata.get("system")[0]
        partition = formdata.get("partition")[0]
        resource_keys = ["nodes", "gpus", "runtime"]
        if key in resource_keys:
            if partition in systems_config.get(system, {}).get(
                "interactive_partitions", []
            ):
                return True
            else:
                if key not in resources.get(system.upper()).get(partition).keys():
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
