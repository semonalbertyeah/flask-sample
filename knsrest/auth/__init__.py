# -*- coding:utf-8 -*-

"""
    User(authentication):
        current_user (refer to user.User)
    RBAC(authorization):
        @policy.allow('admin')    # allow all operation for admin
        @policy.allow(['guest', 'guest2'], methods=['GET']) # only GET for guests
        @policy.route(r'/test/', methods=['GET', 'POST'])
        def test():
            return 'test'

    the default rule:
        user with role "admin" has all permissions.
"""

from flask import request, session

#from nms.app.wrappers import (
#    json_response, abort, jabort
#)
from knsrest.wrappers import (
    json_response, abort, jabort
)

from .rbac import RBAC
from . import user

from .user import (
    init_user,
    UserError, User,
    current_user
)


_login_check_exempts = []
def login_exempt(view):
    """
        skip over authentication and authorization.
    """
    global _login_check_exempts
    _login_check_exempts.append(view)
    return view


################
# the RBAC
################
policy = RBAC(strict=False)

def init_auth(app, db_engine, strict=False):
    global policy
    policy.strict=strict
    init_user(app, db_engine)

    @app.before_request
    def check_permission():
        # 1. check user login
        global _login_check_exempts
        view = app.view_functions.get(request.endpoint)
        if view in _login_check_exempts:
            return

        if not current_user.logged_in():
            jabort({'msg': 'need to login'}, 401)

        # pre-defined role "admin" is assigned all permissions.
        if not 'admin' in current_user.assigned_roles:
            if not policy.allowed(current_user, view, request.method):
                jabort({'msg': 'not allowed'}, 401)

        #
        # refresh session timeout
        #
        if request.headers.get("Flask-Auth-Policy", 'none').lower() != "no-refresh":
            session.refresh()   # specific method in NewKVSession


