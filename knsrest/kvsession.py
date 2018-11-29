# -*- coding:utf-8 -*-

"""
    extended flask-kvsession.
    added features:
        when destroyed, cookie whould be deleted

    eidt: 2018-07-23
    author: lwb
    description:
        add a built-in field __session_last_touch__,
        this field is used for session expiration.
        the "created" date in session_id is kept, but no long checked,
        as session_id should not be updated if session expiration is refreshed.

        if regenerating session_id for every request, then each request must be processed
        in receiving order to ensure data consistency.
"""

import time

from simplekv.db.sql import SQLAlchemyStore
from itsdangerous import Signer, BadSignature

from flask import current_app
from flask_kvsession import (
    KVSessionExtension, 
    KVSessionInterface, 
    KVSession,
)

class NewKVSession(KVSession):
    destroyed = False
    timeout_field_name = "__session_last_touch__"

    def __init__(self, initial=None):
        if not initial:
            # new session, containing deadline
            initial = {}

        # initial[self.timeout_field_name] = time.time()

        super(NewKVSession, self).__init__(initial)

    @property
    def last_touch(self):
        return self.get(self.timeout_field_name, 0)

    def has_expired(self, lifetime, now=None):
        """
            check if session is expiring after lifetime
        """
        now = now or time.time()
        if not self.last_touch:
            # no created time, suck session will never expire.
            return False

        if self.last_touch + lifetime < now:
            return True
        else:
            return False

    def destroy(self):
        super(NewKVSession, self).destroy()
        self.destroyed = True

    def refresh(self, now=None):
        now = now or time.time()
        # this will make updated = True
        self[self.timeout_field_name] = now
        # self.modified = True


class NewKVSessionInterface(KVSessionInterface):
    session_class = NewKVSession

    def open_session(self, app, request):
        key = app.secret_key

        if key is not None:
            session_cookie = request.cookies.get(
                app.config['SESSION_COOKIE_NAME'], None)

            s = None

            if session_cookie:
                try:
                    # restore the cookie, if it has been manipulated,
                    # we will find out here
                    sid_s = Signer(app.secret_key).unsign(
                        session_cookie).decode('ascii')

                    # retrieve from store
                    s = self.session_class(self.serialization_method.loads(
                        current_app.kvsession_store.get(sid_s)))
                    s.sid_s = sid_s

                    now = time.time()
                    if s.has_expired(app.permanent_session_lifetime.seconds, now):
                        current_app.kvsession_store.delete(sid_s)
                        s = None
                        raise KeyError
                except (BadSignature, KeyError):
                    # either the cookie was manipulated or we did not find the
                    # session in the backend.
                    pass

            if s is None:
                s = self.session_class()  # create an empty session
                s.refresh()
                s.new = True

            return s

    def save_session(self, app, session, response):
        super(NewKVSessionInterface, self).save_session(
            app, session, response
        )
        if session.destroyed:
            response.delete_cookie(key=app.config['SESSION_COOKIE_NAME'])

class NewKVSessionExtension(KVSessionExtension):
    def init_app(self, app, session_kvstore=None):
        super(NewKVSessionExtension, self).init_app(app, session_kvstore)
        app.session_interface = NewKVSessionInterface()

    def cleanup_sessions(self, app=None):
        """
            refactor to clean sessions whose __session_last_touch__ expires
            instead of using date in session_id
        """
        if not app:
            app = current_app

        now = time.time()
        for key in app.kvsession_store.keys():
            m = self.key_regex.match(key)   # session id format is specificed
            if m:
                sess = NewKVSession(
                    NewKVSessionInterface.serialization_method.loads(
                        current_app.kvsession_store.get(key)
                    )
                )
                sess.sid_s = key    # sid_s is used inside session obj, but need assigned manually
                if sess.has_expired(app.permanent_session_lifetime.seconds, now):
                    sess.destroy()




def init_session(app, engine, metadata) :
    """
        init flask-kvsession
        export:
            app.kvsession_ext
            app.kvsession_store
    """
    store = SQLAlchemyStore(engine, metadata, app.config['KVSESSION_TABLE'])
    app.kvsession_ext = NewKVSessionExtension(store, app)
    metadata.create_all()

    @app.before_request
    def cleanup_expired_sessions():
        """
            clear expired sessions at a fixed period.
            note:
                when open_session, if current session outdated,
                new session will created.
        """
        interval = app.config['KVSESSION_CLEANUP_PERIOD']

        try:
            # use the same store to keep deadline.
            # note: 
            #   the key name "session_cleanup_deadline" should not match KVSessionExtension.key_regex,
            #   as data with a key mathcing KVSessionExtension.key_regex is treated as session data,
            #   and will be handled in KVSessionExtension.cleanup_sessions
            deadline = float(app.kvsession_store.get('session_cleanup_deadline'))
        except KeyError as e:
            deadline = time.time()

        if time.time() > deadline or \
           deadline - time.time() > interval:
            print 'do cleaning up sessions'
            app.kvsession_ext.cleanup_sessions(app)
            deadline = time.time() + interval
            app.kvsession_store.put('session_cleanup_deadline', str(deadline))



