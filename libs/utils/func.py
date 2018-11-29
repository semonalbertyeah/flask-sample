# -*- coding:utf-8 -*-


def proxy_method(member, method):
    """
        call method on self.member or member() instead of self
        member: 
            a callable which has a member named method
            or a string indicate the name of a member on self
        method:
            proxied method


        usage:
            class A(object):
                def __init__(self, list_value):
                    self.value = list_value

                __getitem__ = proxy_method('value', '__getitem__')

            a = A([1,2,3])
            print a[0]  # 1
    """
    members = [member]
    def proxy(self, *args, **kwargs):
        member = members[0]
        if callable(member):
            member = member()
        else:
            member = getattr(self, member)
        return getattr(member, method)(*args, **kwargs)
    return proxy

