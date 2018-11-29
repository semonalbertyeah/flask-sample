# -*- coding:utf-8 -*-

import pytest
import json

from flask import request
import flask

from knsrest.event_poller import *


#
# pytest fixture scope
# scope "module": create for each module
# scope "function": create for each function
# scope "session": for the whole session
#


@pytest.fixture(scope="function")
def app():
    return flask.Flask("test")

@pytest.fixture(scope="function")
def client(app):
    return app.test_client()



@pytest.fixture(scope="function")
def poller(app):
    url = r"/event/"
    poller = EventPoller(url=url, methods=["GET", "POST"])
    poller.init_app(app)

    return poller

def test_event_poller(app, poller, client):

    @poller.on(name="test_event1")
    def event1():
        return {"val": 3}

    r = client.get(r"/event/")
    assert r.status_code == 200
    assert r.json["test_event1"] == {"val": 3}


def test_none_value(app, poller, client):

    @poller.on()
    def event2():
        return None

    r = client.get(r"/event/")
    assert r.status_code == 200
    assert r.json["event2"] == None

def test_parm(app, poller, client):

    @poller.on(name="echo")
    def echo():
        return request.args

    r = client.get(r'/event/', query_string={'a': 'val1', 'b': 'val2'})
    assert r.status_code == 200
    assert r.json['echo'] == {'a': 'val1', 'b': 'val2'}


def test_post_json(app, poller, client):
    @poller.on(name="echo_json")
    def echo_json():
        return request.json

    r = client.post(r'/event/', json={'a':1, 'b':2})
    assert r.status_code == 200
    assert r.json['echo_json'] == {'a':1, 'b':2}


def test_add_handler_first(app, client):
    poller = EventPoller()

    @poller.on()
    def test():
        return 3

    poller.init_app(app, url=r"/event2/", endpoint="poller2")

    r = client.get(r'/event2/')
    assert r.status_code == 200
    assert r.json['test'] == 3

def test_stop_propagation(poller, app, client):

    @poller.on(name="first")
    def first():
        return 1, StopEvent()

    @poller.on(name="second")
    def second():
        return 2

    r = client.get(r"/event/")
    assert r.status_code == 200
    assert r.json['first'] == 1
    assert 'second' not in r.json, poller._event_handlers


def test_priority(poller, app, client):

    @poller.on(name="second", priority=2)
    def second():
        return 2

    @poller.on(name="first", priority=1)
    def first():
        return 1, StopEvent()

    r = client.get(r'/event/')
    assert r.status_code == 200
    assert r.json['first'] == 1
    assert 'second' not in r.json


def test_methods(app, client):

    poller = EventPoller()

    @poller.on()
    def test():
        return 3

    poller.init_app(
        app, 
        url=r"/events", 
        endpoint="event_poller", 
        methods=["POST"]
    )

    r = client.post(r'/events')
    assert r.status_code == 200
    assert 'test' in r.json, poller._event_handlers
    assert r.json['test'] == 3

    r = client.get(r'/events')
    assert r.status_code == 405


def test_methods_on_event(app, client):
    poller = EventPoller(url=r"/event", methods=["GET", "POST"], endpoint="event_poller")

    @poller.on(name="first", methods=["post"])
    def first_event():
        return 1

    @poller.on(name="second")
    def second_event():
        return 2

    poller.init_app(app)

    r = client.post(r'/event')
    assert r.status_code == 200
    assert r.json['first'] == 1
    assert r.json['second'] == 2

    r = client.get(r'/event')
    assert r.status_code == 200
    assert r.json['second'] == 2
    assert 'first' not in r.json


