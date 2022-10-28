import json
import os

from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.orm import APIToken
from jupyterhub.scopes import needs_scope
from jupyterhub.utils import url_path_join
from tornado import web
from tornado.httpclient import AsyncHTTPClient
from tornado.httpclient import HTTPClientError
from tornado.httpclient import HTTPRequest

## TODO: documentation
## inline and notebook for jupyter-jsc/sample documentation
class TemplateServerAPIHandler(APIHandler):
    @needs_scope("access:servers")
    async def post(self, user_name, server_name=""):
        self.set_header("Cache-Control", "no-cache")
        if server_name is None:
            server_name = ""
        user = self.find_user(user_name)
        if user is None:
            raise web.HTTPError(404)
        if server_name not in user.spawners:
            raise web.HTTPError(404)

        spawner = user.spawners[server_name]
        if not spawner.ready:
            raise web.HTTPError(400)

        new_token_generated = False
        if spawner.api_token:
            token = spawner.api_token
        else:
            note = "Notebook Template Server for %s" % server_name
            token = user.new_api_token(note=note, roles=["server"])
            orm_api_token = APIToken.find(self.db, token=token)
            new_token_generated = True

        if self.request.body:
            body = json.loads(self.request.body.decode())
        else:
            raise web.HTTPError(400, log_message="Missing body in request.")

        notebook_template = body.get("template", "")
        if not notebook_template:
            raise web.HTTPError(400, log_message="Missing key 'template' in body.")

        notebook_templates_base_path = os.environ.get("NOTEBOOK_TEMPLATES_PATH").rstrip(
            "/"
        )
        notebook_templates_path = f"{notebook_templates_base_path}/{notebook_template}"

        with open(notebook_templates_path, "r") as f:
            notebook = json.load(f)

        if notebook.get("metadata", {}).get("replace_in_all_cells", False):
            self.replace_parameters(notebook, body.get("params", {}))

        if notebook.get("metadata", {}).get("insert_paramater_cell", True):
            self.insert_parameters(notebook, body.get("params", {}))

        api_url = f"{spawner.server.bind_url.rstrip('/')}/api"

        if hasattr(user.authenticator, "custom_config"):
            custom_config = user.authenticator.custom_config
        else:
            custom_config = {}

        if spawner.user_options and custom_config:
            home_path, base_path = self.get_config_pathes(
                spawner.user_options, custom_config
            )
        else:
            home_path, base_path = f"/home/{user.name}", "notebook_template_server"

        dir_url = f"{api_url}/contents{home_path}"

        if hasattr(user.authenticator, "fetch"):
            fetch_func = user.authenticator.fetch
        else:
            fetch_func = self.fetch
        
        if dir_url.startswith("https://"):
            request_kwargs = {
                "client_key": user.settings.get('internal_ssl_key'),
                "client_cert": user.settings.get('internal_ssl_cert'),
                "ca_certs": user.settings.get('internal_ssl_ca')
            }
        else:
            request_kwargs = {}



        # Receive correct notebook name and create directories on the way
        notebook_name = await self.get_notebook_name(fetch_func, request_kwargs, dir_url, token, f"{base_path}/{notebook_template}")
        await self.create_directories(fetch_func, request_kwargs, token, dir_url, notebook_name)
        

        # Upload notebook
        req = HTTPRequest(
            url=f"{dir_url}/{notebook_name}",
            method="PUT",
            headers={"Authorization": f"token {token}"},
            body=json.dumps(
                {"content": notebook, "format": "json", "type": "notebook"}
            ),
            **request_kwargs
        )

        try:
            await fetch_func(req)
        finally:
            if new_token_generated:
                self.db.delete(orm_api_token)
                self.db.commit()
        


        host = self.request.host
        scheme = self.request.protocol
        if server_name:
            userlab_url = f"{scheme}://{host}" + url_path_join(
                self.base_url, f"/user/{user_name}/{server_name}"
            )
        else:
            userlab_url = f"{scheme}://{host}" + url_path_join(
                self.base_url, f"/user/{user_name}"
            )

        redirect_url = f"{userlab_url}/lab/tree{home_path}/{notebook_name}"
        self.write(redirect_url)
        self.set_status(200)

    async def create_directories(self, fetch, request_kwargs, token, api_url, full_notebook_name):
        directories = full_notebook_name.lstrip("/").rstrip("/").split("/")[:-1]
        for i in range(len(directories) + 1):
            req = HTTPRequest(
                url=f"{api_url}/{'/'.join(directories[:i])}",
                method="GET",
                headers={"Authorization": f"token {token}"},
                **request_kwargs
            )
            try:
                await fetch(req)
            except HTTPClientError as e:
                if e.code == 404:
                    req = HTTPRequest(
                        url=f"{api_url}/{'/'.join(directories[:i])}",
                        method="PUT",
                        headers={"Authorization": f"token {token}"},
                        body=json.dumps({"type": "directory"}),
                        **request_kwargs
                    )
                    await fetch(req)
            except Exception as e:
                x = e
                self.log.exception("No")
                x = 0

    def get_config_pathes(self, user_options, custom_config):
        try:
            home_account = custom_config["notebook_template_server"][
                "home_paths_per_system"
            ][user_options["system"]]
            home = home_account.replace("<account>", user_options["account"])
            base_path = custom_config["notebook_template_server"].get(
                "base_path", "notebook_templates_server"
            )
            return home, base_path
        except:
            raise web.HTTPError(400, log_message="Could not guess $HOME.")

    async def get_notebook_name(self, fetch, request_kwargs, dir_url, api_token, notebook_template):
        """
        Do not override files.
        """
        dirname = os.path.dirname(notebook_template)
        filename_ext = os.path.basename(notebook_template)
        first_dot = filename_ext.index(".")
        filename = filename_ext[:first_dot]
        ext = filename_ext[first_dot:]

        dir_path = os.path.dirname(notebook_template).lstrip("/").rstrip("/")

        req = HTTPRequest(
            method="GET",
            headers={"Authorization": f"token {api_token}"},
            url=f"{dir_url}/{dir_path}/",
            **request_kwargs
        )
        try:
            body = await fetch(req)
        except Exception as e:
            body = {}
        i = 1
        notebook_name = filename_ext
        all_filenames = [x.get("name", "") for x in body.get("content", [])]
        while True:
            if not notebook_name in all_filenames:
                break
            notebook_name = f"{filename}{i}{ext}"
            i += 1
        return f"{dirname}/{notebook_name}"

    def replace_parameters(self, notebook, params):
        """
        Replace parameter in all cells.
        Must be enabled in notebook metadata: {"metadata": {"replace_in_all_cells": true} }.

        Replace indicators (default: << >>) may be configured in notebook metadata: {"metadata": {"replace_indicators": ["<<", ">>"]} }

        :param notebook: the Jupyter notebook
        :param params: the parameter mapping
        """
        if not params:
            return
        replace_indicators = notebook.get("metadata", {}).get(
            "replace_indicators", ["<<", ">>"]
        )
        for cell_i in range(0, len(notebook.get("cells", []))):
            for source_i in range(0, len(notebook["cells"][cell_i].get("source", []))):
                for key, value in params.items():
                    if (
                        f"{replace_indicators[0]}{key}{replace_indicators[1]}"
                        in notebook["cells"][cell_i]["source"][source_i]
                    ):
                        notebook["cells"][cell_i]["source"][source_i] = notebook[
                            "cells"
                        ][cell_i]["source"][source_i].replace(
                            f"{replace_indicators[0]}{key}{replace_indicators[1]}",
                            str(value),
                        )

    def insert_parameters(self, notebook, params):
        """
        Insert the given parameters into a Jupyter notebook.

        The parameters are inserted as a new cell, which is placed behind the
        first cell. If there are no parameters, no new cell will be created.

        Currently, only the following languages are supported:

        - Python
        - Julia
        - C

        For all other languages, a fallback implementation is used that might create incorrect results.

        :param notebook: the Jupyter notebook
        :param params: the parameter mapping
        """
        if not params:
            return

        metadata = notebook.get("metadata", {})
        kernelspec = metadata.get("kernelspec", {})
        language = kernelspec.get("language", "").lower()

        source = []
        for key, value in params.items():
            if value is None:
                if language == "python":
                    source.append(f"{key} = None # not set\n")
                elif language == "julia":
                    source.append(f"{key} = nothing # not set\n")
                elif language == "c":
                    source.append(f"int {key} = 0; /* not set */\n")
                else:
                    source.append(f"{key} = 0\n")
            else:
                if language == "c":
                    if isinstance(value, str):
                        source.append(f"const char *{key} = {json.dumps(value)};\n")
                    elif isinstance(value, int):
                        source.append(f"int {key} = {json.dumps(value)};\n")
                    elif isinstance(value, float):
                        source.append(f"double {key} = {json.dumps(value)};\n")
                    elif isinstance(value, bool):
                        source.append(f"int {key} = {1 if value else 0};\n")
                    else:
                        source.append(f"{key} = {json.dumps(value)};\n")
                else:
                    source.append(f"{key} = {json.dumps(value)}\n")

        params_cell = {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": source,
        }
        notebook["cells"].insert(1, params_cell)

    async def fetch(self, req, parse_json=True):
        try:
            if self.http_client is None:
                self.http_client = AsyncHTTPClient()
            resp = await self.http_client.fetch(req)
        except HTTPClientError as e:
            if e.response:
                # Log failed response message for debugging purposes
                message = e.response.body.decode("utf8", "replace")
                try:
                    # guess json, reformat for readability
                    json_message = json.loads(message)
                except ValueError:
                    # not json
                    pass
                else:
                    # reformat json log message for readability
                    message = json.dumps(json_message, sort_keys=True, indent=1)
            else:
                # didn't get a response, e.g. connection error
                message = str(e)
            raise web.HTTPError(e.code, str(e))
        except Exception as e:
            raise web.HTTPError(400, str(e))
        else:
            if parse_json:
                if resp.body:
                    return json.loads(resp.body.decode('utf8', 'replace'))
                else:
                    # empty body is None
                    return None
            else:
                return resp
