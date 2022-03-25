c = get_config()
c.ServerApp.ip = "0.0.0.0"
c.ServerApp.root_dir = "_home_"
# c.ServerApp.default_url = "/lab/workspaces/_servername_"
c.ContentsManager.allow_hidden = True
c.ServerApp.port = int("_port_")
c.ServerApp.terminado_settings = {"shell_command": ["/bin/bash"]}
c.SingleUserNotebookAppMixin.hub_api_url = (
    "http://jupyterhub-<ID>.<NAMESPACE>.svc/hub/api"
)
c.SingleUserNotebookAppMixin.hub_activity_url = (
    "http://jupyterhub-<ID>.<NAMESPACE>.svc/hub/api/users/_username_/activity"
)
c.ServerApp.tornado_settings = {"websocket_max_message_size": 1024 * 1024 * 1024}
c.ServerApp.max_buffer_size = 1024 * 1024 * 1024
c.ServerApp.max_body_size = 1024 * 1024 * 1024