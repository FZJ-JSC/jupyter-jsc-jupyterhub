def named_server_limit_per_user_exceeded(user, options):
    custom_config = user.authenticator.custom_config
    named_spawners = list(user.all_spawners(include_default=False))

    vo = options["vo"]
    service = options["service"]
    service_type = service.split("/")[0]
    service_option = service.split("/")[1]
    system = options["system"]

    vo_config = custom_config.get("vos").get(vo)

    service_limit = (
        vo_config.get("Services")
        .get(service_type)
        .get(service_option)
        .get("max_per_user")
    )
    if service_limit:
        current = 0
        for spawner in named_spawners:
            if (
                spawner
                and spawner.user_options
                and spawner.user_options.get("service", "") == service
                and spawner.active
            ):
                current += 1
        if current >= service_limit:
            return "service", service, service_limit

    system_limit = vo_config.get("Systems", {}).get("max_per_user", {}).get(system)
    if system_limit:
        current = 0
        for spawner in named_spawners:
            if (
                spawner
                and spawner.user_options
                and spawner.user_options.get("system", "") == system
                and spawner.active
            ):
                current += 1
        if current >= system_limit:
            return "system", system, system_limit

    return
