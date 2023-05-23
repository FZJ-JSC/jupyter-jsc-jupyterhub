import copy
import json

from jupyterhub import orm
from jupyterhub import scopes
from jupyterhub.apihandlers.base import APIHandler
from jupyterhub.handlers import default_handlers
from tornado import web

from ..misc import get_custom_config


class SelfAPIHandlerOAuth(APIHandler):
    """Return the authenticated user's model

    Based on the authentication info. Acts as a 'whoami' for auth tokens.
    Add additional oauth access token and information
    """

    def check_xsrf_cookie(self):
        pass

    async def get(self):
        user = self.current_user
        if user is None:
            raise web.HTTPError(403)

        _added_scopes = set()
        if isinstance(user, orm.Service):
            # ensure we have the minimal 'identify' scopes for the token owner
            identify_scopes = scopes.identify_scopes(user)
            get_model = self.service_model
        else:
            identify_scopes = scopes.identify_scopes(user.orm_user)
            get_model = self.user_model

        # ensure we have permission to identify ourselves
        # all tokens can do this on this endpoint
        for scope in identify_scopes:
            if scope not in self.expanded_scopes:
                _added_scopes.add(scope)
                self.expanded_scopes |= {scope}
        if _added_scopes:
            # re-parse with new scopes
            self.parsed_scopes = scopes.parse_scopes(self.expanded_scopes)

        model = get_model(user)

        # add session_id associated with token
        # added in 2.0
        token = self.get_token()
        if token:
            model["session_id"] = token.session_id
        else:
            model["session_id"] = None

        # add scopes to identify model,
        # but not the scopes we added to ensure we could read our own model
        model["scopes"] = sorted(self.expanded_scopes.difference(_added_scopes))

        # Users should be able to receive their access_token,
        # but not the refresh token.
        auth_state = await user.get_auth_state()
        model_auth_state = {}
        allowed_auth_state_keys = (
            get_custom_config()
            .get("selfapihandler", {})
            .get("allowed_auth_state_keys", ["access_token"])
        )
        for key, value in auth_state.items():
            if key in allowed_auth_state_keys:
                model_auth_state[key] = copy.deepcopy(value)
        model["auth_state"] = model_auth_state

        self.write(json.dumps(model))


default_handlers.append((r"/api/user_oauth", SelfAPIHandlerOAuth))
