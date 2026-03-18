import asyncio
import copy
import hashlib
import json
import logging
import os
import re
import shutil
import sys

import aiohttp
import yaml
from dateutil import parser
from subprocess import check_output
from subprocess import STDOUT

log = logging.getLogger()
log.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
console_handler.setFormatter(formatter)

log.addHandler(console_handler)

_custom_config_file = os.environ.get("CUSTOM_CONFIG_PATH", "/mnt/custom-config/jupyterhub_custom_config.yaml")

with open(_custom_config_file, "r") as f:
    custom_config = yaml.full_load(f)

_incidents_path = os.environ.get("INCIDENTS_PATH", "/mnt/shared-data/incidents.json")
_reservations_path = os.environ.get("RESERVATIONS_PATH", "/mnt/shared-data/reservations.json")

global_incidents = {}
global_reservations = {}

async def update_incidents():
    global custom_config
    global global_incidents
    global _incidents_path

    prev_incident_hash = hashlib.sha256(
        json.dumps(global_incidents, sort_keys=True).encode("utf-8")
    ).hexdigest()
    static_dir = "/mnt/shared-data/share/jupyterhub/static/images/footer"

    log.info("Run IncidentCheck")

    def update_status_image(system, health):
        image_path = f"{static_dir}/systems/{system.lower()}.svg"
        # 0: Healthy, 10: Annotation, 20: Minor, 30: Medium, 40: Major, 50: Critical
        template_path = f"{static_dir}/templates/{health}.svg"
        try:
            log.debug(f"IncidentCheck - Copy {template_path} to {image_path}")
            shutil.copyfile(template_path, image_path)
        except:
            log.exception(
                f"IncidentCheck - Could not copy {template_path} to {image_path}"
            )

    def filter_and_sort_incidents(incidents_list):
        def _sort(incidents):
            incidents.sort(key=lambda x: x.get("incident_severity", 0), reverse=True)
            return incidents

        # FAIL > DEG > MAINT > ANNOT
        failures = [x for x in incidents_list if x.get("incident_type") == "FAIL"]
        if failures:
            return _sort(failures)
        degradations = [x for x in incidents_list if x.get("incident_type") == "DEG"]
        if degradations:
            return _sort(degradations)
        maintenances = [x for x in incidents_list if x.get("incident_type") == "MAINT"]
        if maintenances:
            return _sort(maintenances)
        # Do not return annotations as their short description is mostly unhelpful
        return []

    def get_info_msg(incidents_list):
        if len(incidents_list) > 1:
            log.warning(
                "IncidentCheck - Multiple active incidents of the same type. Use the highest severity one."
            )
        incident = incidents_list[0]
        short_description = incident["short_description"]
        if short_description:
            description = short_description
        else:
            description = incident["description"]
        start_time = incident["start_time"]
        if incident["end_time"]:
            end_time = incident["end_time"]
        else:
            end_time = "unknown"
        info_msg = f"{start_time} - {end_time}:\n{description}"
        return info_msg

    def _update_incidents(system, svc, active_svc_incidents, incidents):
        if not incidents.get(system, {}):
            incidents[system] = {}

        # Service has active incidents
        if active_svc_incidents:
            log.debug(f"IncidentCheck - Found active incidents for {system}.")
            incidents[system]["incident"] = get_info_msg(active_svc_incidents)
        elif svc["next_maintenance"]:
            next_maintenance_incidents = [
                x
                for x in active_svc_incidents
                if parser.parse(x["start_time"])
                == parser.parse(svc["next_maintenance"])
            ]
            if len(next_maintenance_incidents) == 0:
                raise Exception(
                    f"IncidentCheck - Could not find matching start time in incidents for maintenance for {system}."
                )
            log.debug(f"IncidentCheck - Found announced maintenance(s) for {system}.")
            incidents[system]["incident"] = get_info_msg(next_maintenance_incidents)
        else:
            incidents[system]["incident"] = ""

        # Set initial status image if no health status exists yet
        if "health" not in incidents.get(system):
            update_status_image(system, svc["health"])
        # Change status image if service has a new health status
        elif svc["health"] != incidents.get(system).get("health", 0):
            update_status_image(system, svc["health"])
        incidents.get(system)["health"] = svc["health"]

    config = custom_config.get("incidentCheck", {})
    incidents = global_incidents.copy()

    api_url = config.get("url", "https://status.jsc.fz-juelich.de/api")
    timeout = config.get("timeout", 5)
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            # Fetch all incidents
            async with session.get(f"{api_url}/incidents") as all_incidents_r:
                all_incidents_r.raise_for_status()
                all_incidents = await all_incidents_r.json()

            # Fetch each service
            for name, id in config["services"].items():
                try:
                    async with session.get(f"{api_url}/services/{id}") as svc_r:
                        svc_r.raise_for_status()
                        svc = await svc_r.json()
                    active_svc_incidents = [
                        x
                        for x in all_incidents
                        if int(id) in x.get("affected_services", [])
                        and not x.get("resolved", "")
                    ]
                    active_svc_incidents = filter_and_sort_incidents(
                        active_svc_incidents
                    )
                    _update_incidents(name, svc, active_svc_incidents, incidents)
                except:
                    log.exception(
                        f"IncidentCheck - Could not check for incidents for {name}"
                    )
    except:
        log.exception("IncidentCheck - Could not check for incidents")

    new_incident_hash = hashlib.sha256(
        json.dumps(incidents, sort_keys=True).encode("utf-8")
    ).hexdigest()
    if new_incident_hash != prev_incident_hash:
        global_incidents = incidents
        with open(_incidents_path, 'w') as f:
            json.dump(global_incidents, f, indent=4)


async def update_reservations():
    global custom_config
    global global_reservations
    global _reservations_path

    reservation_key = os.environ.get(
        "RESERVATION_KEY_PATH", "/mnt/shared-data/reservation_key/ssh-privatekey"
    )
    regex_pattern = "([\\S]+)=([\\S]+)"

    log.info("Run ReservationCheck")
    prev_reservations_hash = hashlib.sha256(
        json.dumps(global_reservations, sort_keys=True).encode("utf-8")
    ).hexdigest()
    reservation_timeout = custom_config.get("reservationCheck", {}).get("timeout", 3)
    try:
        previous_dict = global_reservations.copy()
    except:
        previous_dict = {}
    output_dict = {}
    add_debug_users = custom_config.get("reservationCheck", {}).get("addUsers", [])
    setAllActive = custom_config.get("reservationCheck", {}).get("setAllActive", False)
    for system, infos in (
        custom_config.get("reservationCheck", {}).get("systems", {}).items()
    ):
        if system not in output_dict.keys():
            output_dict[system] = []
        li = [
            "ssh",
            "-i",
            reservation_key,
            "-oLogLevel=ERROR",
            "-oStrictHostKeyChecking=no",
            "-oUserKnownHostsFile=/dev/null",
            "{}@{}".format(infos.get("user", "ljupyter"), infos.get("host", "")),
            "-T",
        ]

        def null_to_empty(key, value, infos):
            if key in infos.get(
                "nullReplaceKeys", ["Accounts", "Users", "PartitionName"]
            ) and value == infos.get("nullString", "(null)"):
                return ""
            return value

        try:
            log.debug(f"ReservationCheck - Run {' '.join(li)}")
            output = (
                check_output(li, stderr=STDOUT, timeout=reservation_timeout)
                .decode("utf8")
                .rstrip()
            )
            system_list_n = output.split("\n\n")
            system_list = [x.replace("\n", "") for x in system_list_n]
        except:
            log.exception(
                f"ReservationCheck - Could not check reservation for {system}. Use previous values."
            )
            if system in previous_dict.keys():
                output_dict[system] = previous_dict[system]
        else:
            for reservation_string in system_list:
                reservation_key_values_list = re.findall(
                    regex_pattern, reservation_string
                )
                reservation_key_values_dict = {
                    x[0]: null_to_empty(x[0], x[1], infos)
                    for x in reservation_key_values_list
                }
                if "ReservationName" in reservation_key_values_dict.keys():
                    output_dict[system].append(
                        copy.deepcopy(reservation_key_values_dict)
                    )
                    if add_debug_users:
                        users = output_dict[system][-1]["Users"]
                        if users:
                            users += ","
                        users += ",".join(add_debug_users)
                        output_dict[system][-1]["Users"] = users
                    if setAllActive:
                        output_dict[system][-1]["State"] = "ACTIVE"

    new_reservations_hash = hashlib.sha256(
        json.dumps(output_dict, sort_keys=True).encode("utf-8")
    ).hexdigest()
    if prev_reservations_hash != new_reservations_hash:
        global_reservations = output_dict
        with open(_reservations_path, 'w') as f:
            json.dump(global_reservations, f, indent=4)

async def main(delay):
    if delay <= 0:
        with open(_reservations_path, 'w') as f:
            json.dump({}, f, indent=4)
        with open(_incidents_path, 'w') as f:
            json.dump({}, f, indent=4)
    await asyncio.sleep(delay)
    while True:
        log.info(f"Update incidents and reservations - Interval: {delay}")
        try:
            await update_incidents()
        except:
            log.exception("Could not update incidents")
        try:
            await update_reservations()
        except:
            log.exception("Could not update reservations")

        if delay <= 0:
            break

        await asyncio.sleep(delay)

if __name__ == "__main__":
    delay = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    asyncio.run(main(delay))
