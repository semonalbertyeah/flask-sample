# -*- coding:utf-8 -*-

import os, time, json
from flask import Flask, request, redirect

from kns.db import ThreadSession, engine, metadata
from kns.logger import logger as root_logger

from .event_poller import StopEvent
from .globals import event_poller

from .config import Config
from .kvsession import init_session
from .auth import init_auth, login_exempt, current_user, UserError, policy
# from . import logic
from . import knms

from .wrappers import (
    json_response, empty_response, abort, jabort
)


CUR_DIR = os.path.dirname(os.path.abspath(__file__))


logger = root_logger.getChild('rest')

def create_app():
    app = Flask(__name__, static_url_path=None, static_folder=None)
    app.config.from_object(Config)

    init_session(app, engine, metadata)
    init_auth(app, engine, strict=True)

    event_poller.init_app(app, url=r"/events", methods=["POST"])
    login_exempt(event_poller.handler)

    app.register_blueprint(knms.mod, url_prefix='/knms')


    @app.teardown_request
    def close_db_session(exc):
        """
            in case there is any dirty data in db session.
        """
        if ThreadSession.registry.has():
            try:
                if exc:
                    ThreadSession.rollback()
                else:
                    ThreadSession.commit()
            finally:
                ThreadSession.rollback()
                ThreadSession.remove() # remove current thread-local session

    return app


app = create_app()




######################
# auth: login, logout
######################
@login_exempt
@app.route(r'/auth/login', methods=['POST'])
def login():
    """
        post request:
            Content-Type: application/json
            {
                'login': {
                    'username': xxx,
                    'password': xxx,
                    'remember': if_any
                }
            }

        response:
            success: 200, user_info {'user': {xxx}}
            error: 403 (no user, wrong password)
    """
    if request.json is None:
        jabort({'msg': 'invalid request: not json message.'}, 400)
    try:
        login_info = request.json['login']
        username = login_info['username']
        password = login_info['password']
        remember = login_info.get('remember', False)
    except KeyError as e:
        jabort({'msg': 'invalid request'}, 400)

    try:
        current_user.login(username, password, remember)
        return json_response({
            "user": {
                'username': username
            }
        })
    except UserError as e:
        if e.errno == UserError.ERR_NO_SUCH:
            jabort({'msg': 'no such user'}, 403)
        elif e.errno == UserError.ERR_WRONG_PASS:
            jabort({'msg': 'wrong password'}, 403)
        else:
            raise


@policy.allow('all', methods=['POST'])
@app.route(r'/auth/logout', methods=['POST'])
def logout():
    current_user.logout()
    return empty_response()


@event_poller.on(name="logged_in", priority=0)
def login_state():
    """
        login state is invoked first (priority 0).
        if no user login, other events will not be invoked.
    """
    logged_in = current_user.logged_in()
    resp = {
        'state': logged_in
    }
    if logged_in:
        resp['user'] = {
            'username': current_user.username
        }

    if logged_in:
        return resp
    else:
        return resp, StopEvent()


@login_exempt
@app.route(r'/auth/logged_in', methods=['GET'])
def logged_in():
    resp = {
        'logged_in': current_user.logged_in()
    }
    if resp['logged_in']:
        resp['user'] = {
            'username': current_user.username
        }

    return json_response(resp)


@app.route(r'/auth/change_password', methods=["POST"])
def change_password():
    """
        post request:
            Content-Type: application/json
            {
                'change_password': {
                    'old_password': xxx,
                    'new_password': xxx
                }
            }

        response:
            success: 200
            error: 403 (wrong password)
    """

    req = request.json['change_password']

    try:
        current_user.change_password(req['old_password'], req['new_password'])
    except UserError as e:
        jabort({'msg': e.msg}, 403)

    return empty_response()









####################
# tests
####################
from flask import session, jsonify


@login_exempt
@app.route(r'/test/custom_abort', methods=["GET"])
def test_custom_abort():
    jabort({'msg': 'manually aborted '}, 409)

@login_exempt
@app.route('/test/exc/', methods=['GET'])
def test_exc():
    raise Exception, 'this is a test exception.'

@login_exempt
@app.route(r'/test/block/<int:period>/')
def block(period):
    time.sleep(period)
    session['block'] = period
    return 'done.'

@login_exempt
@app.route(r'/test/dump/', methods=['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])
def test_dump():
    print 'method:', request.method
    print 'headers:', json.dumps(dict(request.headers), indent=4)
    print 'cookies:', json.dumps(dict(request.cookies), indent=4)
    print 'query string:', json.dumps(dict(request.args), indent=4)
    print 'form data:', request.form
    print 'json data:', request.json
    print 'body:'
    print repr(request.data)
    
    return jsonify({
        'headers': dict(request.headers),
        'cookies': dict(request.cookies),
        'query_string': dict(request.args),
        'body': repr(request.data)
    })



##################
# session tests
##################
@login_exempt
@app.route(r'/test/read_session/', methods=['GET'])
def test_read_session():
    return jsonify(dict(session))

@login_exempt
@app.route(r'/test/write_session/', methods=['GET'])
def test_write_session():
    session['key1'] = 'value1'
    session['key2'] = 'value2'
    session['key3'] = 3
    return 'ok'

@login_exempt
@app.route(r'/test/delete_session/', methods=['GET'])
def delete_session():
    session.destroy()
    return 'ok'



##################
# user tests
##################


@login_exempt
@app.route(r'/test/login', methods=['POST'])
def test_login():
    """
        input:
            values: username, password
    """
    try:
        current_user.login(
            request.values['username'], 
            request.values['password']
        )
        return 'ok'
    except UserError as e:
        if e.errno == UserError.ERR_NO_SUCH:
            abort(403, 'no such user')
        elif e.errno == UserError.ERR_WRONG_PASS:
            abort(403, 'wrong password')
        else:
            raise




@login_exempt
@app.route(r'/test/dump_user', methods=['GET'])
def dump_user():
    print 'session:', dict(current_user.session)
    print 'username:', current_user.username
    print 'password_hash:', repr(current_user.password_hash)
    print 'db_info:', current_user.db_info
    print 'is_valid:', current_user.is_valid()
    print 'logged_in:', current_user.logged_in()

    return 'in console.'




###############
# DB tests
###############
from kns.db.model_device import Test
from kns.db import db_session

@login_exempt
@app.route(r'/test/db/', methods=['GET', 'POST'])
def test_db_all():
    try:
        if request.method == 'GET':
            recs = db_session.query(Test).all()
            return json_response({'records': [rec.to_dict() for rec in recs]})
        elif request.method == 'POST':
            info = request.json['record']
            rec = Test(val=info['val'])
            db_session.add(rec)
            db_session.commit()

            return json_response({'record': rec.to_dict()})
    finally:
        db_session.remove()


@login_exempt
@app.route(r'/test/db/<int:rec_id>', methods=['DELETE', 'PATCH'])
def test_db_rec(rec_id):
    """
        delete a record:
            DELETE /test/db/33

        update a record:
            PATCH /test/db/22
            {
                "record": {
                    "value": "new_value"
                }
            }
    """
    try:
        rec = db_session.query(Test).filter(Test.id==rec_id).scalar()
        if rec is None:
            return json_response({'msg': 'no such record'}, 404)

        if request.method == 'DELETE':
            db_session.delete(rec)
            return empty_response()

        elif request.method == 'PATCH':
            info = request.json['record']
            rec.val = info['val']
            db_session.commit()

            return json_response({'record': rec.to_dict()})

    finally:
        db_session.remove()


@login_exempt
@app.route(r'/test/', methods=['GET'])
def test():
    return "test url handler. ehh!!"







import waitress
import logging

from kns.logger import init_logger

def serve():
    init_logger(
        logging.getLogger('waitress')
    )
    waitress.serve(app, listen='*:8771')


if __name__ == "__main__":
    serve()



