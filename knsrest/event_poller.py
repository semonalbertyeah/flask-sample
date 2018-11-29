# -*- coding:utf-8 -*-

from flask import request

from .wrappers import *

class StopEvent(object):
    pass

class EventPoller(object):
    def __init__(self, app=None, url=r"/event", endpoint="event_poller", methods=["GET"]):
        self.url = url
        self.app = app
        self.endpoint = endpoint
        self.methods = methods

        #
        # [
        #   (event_name1, event_handler1, priority, methods),
        #   (event_name2, event_handler2, priority, methods),
        #   ......
        # ]
        #
        self._event_handlers = []

        if self.app:
            self.app.route(self.url, methods=self.methods, endpoint=self.endpoint)(self._handler)

    def init_app(self, app, url=None, endpoint=None, methods=None):
        self.app = app

        if url:
            self.url = url

        if endpoint:
            self.endpoint = endpoint

        if methods:
            self.methods = methods

        self.app.route(self.url, methods=self.methods, endpoint=self.endpoint)(self._handler)

    def _handler(self):
        resp = {}
        stop = False
        for name, handler, priority, methods in self._event_handlers:
            if methods and request.method not in methods:
                continue

            val = r = handler()
            if isinstance(r, tuple):
                val = r[0]
                if len(r) >= 2:
                    stop = isinstance(r[1], StopEvent)

            resp[name] = val
            if stop:
                break
        return json_response(resp, 200)

    @property
    def handler(self):
        return self._handler

    def on(self, **options):
        """
            kwargs:
                name: event name, handler function name will be used if not specified
                priority: int, default priority is 10.
                    e.g.: an event with priority 1 is executed before an event with priority 2
        """
        def decorator(func):
            assert callable(func)
            name = str(options.get('name', func.__name__))
            priority = int(options.get('priority', 10))
            methods = options.get("methods", None)  # None, which means all methods
            if methods:
                if not isinstance(methods, (list, tuple, set)):
                    methods = [methods]

                methods = [str(m).upper() for m in methods]

            for idx, (per_name, per_func, per_priority, per_methods) in enumerate(self._event_handlers):
                if per_priority > priority:
                    self._event_handlers.insert(idx, (name, func, priority, methods))
                    break
            else:
                self._event_handlers.append((name, func, priority, methods))

            return func

        return decorator


