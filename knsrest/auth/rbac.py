# -*- coding:utf-8 -*-

"""
    Authorization

    role based access control
    roles assignment:
        roles are created when assigned to a resource operation

    sample:
        @auth.allow('admin')    # allow all operation for admin
        @auth.allow(['guest', 'guest2'], methods=['GET']) # only GET for guests
        @app.route(r'/test/', methods=['GET', 'POST'])
        def test():
            return 'test'

        predefined role 'all':
            permissions granted on role 'all' are granted to all other roles.
"""

import types


class RBAC(object):
    """
        RBAC is exactly a rule container.
        containing maps from role to permission (HTTP request on endpoint)
    """
    # all http methods -> all operations
    all_methods = [
        'GET', 'HEAD', 'POST', 
        'PUT', 'DELETE', 'TRACE', 
        'OPTION', 'CONNECT', 'PATCH']

    def __init__(self, strict=False):
        #     rules = {
        #         'role1': {
        #             view_func1: set(['GET', 'POST']),
        #             view_func2: set(['GET'])
        #         },
        #         'role2': {
        #             ...
        #         },
        #         ...
        #     }
        self.rules = {}

        # monitored resource
        self.resources = set()

        # strict
        #   When enabled, unregistered resources are not accessible.
        #   When disabled, permissions to access unregistered resources are not restricted.
        self.strict = strict


    def allowed(self, user, view_func, methods):
        """
            check if user has permission to request(methods) a resource(view_func)
        """
        if view_func not in self.resources:
            if self.strict:
                return False
            else:
                return True

        if not isinstance(methods, set):
            if isinstance(methods, (tuple, list)):
                methods = set(methods)
            else:
                methods = set([methods])

        # check role "all":
        #   role "all" means any user with any roles is granted permission on 
        #   requesting(methods) on resource(view_func)
        rule_all = self.rules.get('all', {})
        if view_func in rule_all:
            if methods.issubset( rule_all[view_func] ):
                return True

        for role in user.assigned_roles:
            if role in self.rules:
                if view_func in self.rules[role]:
                    if methods.issubset( self.rules[role][view_func] ):
                        return True
        else:
            return False

    def add_rule(self, roles, view_func, methods=None):
        self.resources.add(view_func)
        if methods is None:
            methods = self.all_methods

        if isinstance(roles, types.StringTypes):
            roles = [roles]

        for role in roles:
            self.rules.setdefault(
                role, 
                {}
            ).setdefault(
                view_func, 
                set()
            ).update(methods)

    def allow(self, roles, methods=None):
        def decorator(view_func):
            self.add_rule(roles, view_func, methods)
            return view_func

        return decorator




import unittest

class TestRBAC(unittest.TestCase):
    class TestUser(object):
        def __init__(self, name, assigned_roles=set()):
            if not isinstance(assigned_roles, set):
                if isinstance(assigned_roles, (tuple, list)):
                    assigned_roles = set(assigned_roles)
                else:
                    assigned_roles = set([assigned_roles])
            self.name = name
            self.assigned_roles = assigned_roles


    def test_basic(self):

        admin = TestRBAC.TestUser('admin', ['admin'])
        guest = TestRBAC.TestUser('guest', ['guest'])
        rbac = RBAC(strict=True)

        @rbac.allow('admin')
        def admin_view1():
            pass

        @rbac.allow(['admin', 'guest'])
        def common_view1():
            pass

        @rbac.allow('admin')
        @rbac.allow('guest', methods=['GET'])
        def common_view2():
            pass

        @rbac.allow('all')
        def common_view3():
            pass

        def unregistered_view():
            pass

        self.assertTrue(rbac.allowed(admin, admin_view1, ['POST', 'GET']))

        self.assertFalse(rbac.allowed(guest, admin_view1, 'POST'))

        self.assertTrue(rbac.allowed(guest, common_view2, 'GET'))

        self.assertFalse(rbac.allowed(guest, common_view2, 'POST'))

        self.assertTrue(rbac.allowed(guest, common_view3, ['DELETE', 'GET', 'POST', 'PUT', 'PATCH', 'HEAD']))

        self.assertFalse(rbac.allowed(guest, unregistered_view, ['GET']))

    def test__non_strict(self):
        def unregistered_view():
            pass

        rbac = RBAC()

        guest = TestRBAC.TestUser('guest', ['guest'])

        self.assertTrue(rbac.allowed(guest, unregistered_view, ['GET']))


    def test__strict(self):
        def unregistered_view():
            pass

        rbac = RBAC(strict=True)

        guest = TestRBAC.TestUser('guest', ['guest'])

        self.assertFalse(rbac.allowed(guest, unregistered_view, ['GET']))



if __name__ == '__main__':
    unittest.main()

