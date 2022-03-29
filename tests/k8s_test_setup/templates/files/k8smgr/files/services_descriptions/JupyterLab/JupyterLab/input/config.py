c = get_config()
c.ServerApp.ip = "0.0.0.0"
c.ServerApp.root_dir = "/home/jovyan"
c.ContentsManager.allow_hidden = True
c.ServerApp.port = 8443
c.ServerApp.terminado_settings = {"shell_command": ["/bin/bash"]}
c.ServerApp.tornado_settings = {"websocket_max_message_size": 1024 * 1024 * 1024}
c.ServerApp.max_buffer_size = 1024 * 1024 * 1024
c.ServerApp.max_body_size = 1024 * 1024 * 1024
c.ServerApp.quit_button = False