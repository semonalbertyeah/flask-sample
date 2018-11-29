# -*- coding:utf-8 -*-

import types
import json
from flask import make_response, abort as flask_abort

from zjsonrpc2 import RPCClient

from kns.db import ThreadSession
from kns.entry import ENTRIES


def json_response(data, status=200, headers={}):
    status = int(status)
    __headers = {'Content-Type': 'application/json'}
    __headers.update(headers)

    if not isinstance(data, types.StringTypes):
        data = json.dumps(dict(data))
    return make_response(data, status, __headers)

def empty_response(status=204, headers={}):
    if headers:
        return make_response('', status, headers)
    else:
        return make_response('', status)


def abort(*args, **kwargs):
    # rollback db operation if any
    if ThreadSession.registry.has():
        ThreadSession.rollback()

    flask_abort(*args,**kwargs)


def jabort(data, status=400, headers={}):
    """
        abort with json data
    """
    abort(json_response(data, status, headers))


def knmp_client():
    """
        get a RPCClient to communicate with KNMP service
        with timeout set to 30 seconds
    """
    # raise NotImplementedError, "find a way to get knmp service info"
    host, port = ENTRIES['knmp_proxy']
    return RPCClient("tcp://%s:%d" % (host, int(port)), timeout=30000)

def snmp_client():
    """
        get a RPCClient to communicate with SNMP proxy.
    """
    host, port = ENTRIES['snmp_proxy']
    return RPCClient("tcp://%s:%d" % (host, int(port)), timeout=30000)

