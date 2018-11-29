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

    # app.register_blueprint(logic.mod, url_prefix='/knms')
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

ADMIN_URL_PRODUCT = r'/static/site/workspace/build/production/Admin'
LOGIN_URL_PRODUCT = r'/static/site/workspace/build/production/Login'

ADMIN_URL_TEST = r'/static/site/workspace/build/testing/Admin'
LOGIN_URL_TEST = r'/static/site/workspace/build/testing/Login'

# @login_exempt
# @app.route(r"/", methods=['GET'])
# def index():
#     # login_url = r"/site/product/Login"
#     # admin_url = r"/site/product/Admin"
#     if current_user.logged_in():
#         return redirect(ADMIN_URL_TEST)
#     else:
#         return redirect(LOGIN_URL_TEST)


# @login_exempt
# @app.route(r'/site/dev/<app_name>/', methods=['GET'])
# def redirect_site_dev(app_name):
#     # /home/admin/work/new_kema_nms/static/site/workspace/build
#     return redirect(r'/static/site/workspace/build/development/%s' % app_name)


# @login_exempt
# @app.route(r'/site/test/<app_name>/', methods=['GET'])
# def redirect_site_test(app_name):
#     # /home/admin/work/new_kema_nms/static/site/workspace/build
#     return redirect(r'/static/site/workspace/build/testing/%s' % app_name)


# @login_exempt
# @app.route(r'/site/product/<app_name>/', methods=['GET'])
# def redirect_site_product(app_name):
#     # /home/admin/work/new_kema_nms/static/site/workspace/build
#     # static/site/workspace/build/production
#     return redirect(r'/static/site/workspace/build/production/%s' % app_name)


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









# ####################
# # tests
# ####################
# from flask import session, jsonify


@login_exempt
@app.route(r'/test/custom_abort', methods=["GET"])
def test_custom_abort():
    jabort({'msg': 'manually aborted '}, 409)

# @login_exempt
# @app.route('/test/dump_db_session/', methods=['GET'])
# def print_db_session():
#     return ('%s' % (repr(app.db_session_factory())))

# @login_exempt
# @app.route('/test/exc/', methods=['GET'])
# def test_exc():
#     raise Exception, 'this is a test exception.'

# @login_exempt
# @app.route(r'/test/block/<int:period>/')
# def block(period):
#     time.sleep(period)
#     session['block'] = period
#     return 'done.'

# @login_exempt
# @app.route(r'/test/dump/', methods=['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])
# def test_dump():
#     print 'method:', request.method
#     print 'headers:', json.dumps(dict(request.headers), indent=4)
#     print 'cookies:', json.dumps(dict(request.cookies), indent=4)
#     print 'query string:', json.dumps(dict(request.args), indent=4)
#     print 'form data:', request.form
#     print 'json data:', request.json
#     print 'body:'
#     print repr(request.data)
    
#     return jsonify({
#         'headers': dict(request.headers),
#         'cookies': dict(request.cookies),
#         'query_string': dict(request.args),
#         'body': repr(request.data)
#     })



# ##################
# # session tests
# ##################
# @login_exempt
# @app.route(r'/test/read_session/', methods=['GET'])
# def test_read_session():
#     return jsonify(dict(session))

# @login_exempt
# @app.route(r'/test/write_session/', methods=['GET'])
# def test_write_session():
#     session['key1'] = 'value1'
#     session['key2'] = 'value2'
#     session['key3'] = 3
#     return 'ok'

# @login_exempt
# @app.route(r'/test/delete_session/', methods=['GET'])
# def delete_session():
#     session.destroy()
#     return 'ok'



# ##################
# # user tests
# ##################


# @login_exempt
# @app.route(r'/test/login', methods=['POST'])
# def test_login():
#     """
#         input:
#             values: username, password
#     """
#     try:
#         current_user.login(
#             request.values['username'], 
#             request.values['password']
#         )
#         return 'ok'
#     except UserError as e:
#         if e.errno == UserError.ERR_NO_SUCH:
#             abort(403, 'no such user')
#         elif e.errno == UserError.ERR_WRONG_PASS:
#             abort(403, 'wrong password')
#         else:
#             raise


# @rbac.allow('admin')
# @app.route(r'/test/logout', methods=['POST'])
# def test_logout():
#     current_user.logout()
#     return 'ok'


# @login_exempt
# @app.route(r'/test/dump_user', methods=['GET'])
# def dump_user():
#     print 'session:', dict(current_user.session)
#     print 'username:', current_user.username
#     print 'password_hash:', repr(current_user.password_hash)
#     print 'db_info:', current_user.db_info
#     print 'is_valid:', current_user.is_valid()
#     print 'logged_in:', current_user.logged_in()

#     return 'in console.'




# ###############
# #  RBAC tests
# ###############
# @rbac.allow('admin')
# @app.route(r'/test/admin_view/', methods=['GET'])
# def test_admin_view():
#     return 'admin user permitted.'


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



@login_exempt
@app.route(r'/test/data/d3force.json', methods=['GET'])
def test_d3_force_data():
    # test_json = {
    #   "nodes": [
    #     {"id": "Myriel", "group": 1},
    #     {"id": "Napoleon", "group": 1},
    #     {"id": "Mlle.Baptistine", "group": 1},
    #     {"id": "Mme.Magloire", "group": 1},
    #     {"id": "CountessdeLo", "group": 1},
    #     {"id": "Geborand", "group": 1},
    #     {"id": "Champtercier", "group": 1},
    #     {"id": "Cravatte", "group": 1},
    #     {"id": "Count", "group": 1},
    #     {"id": "OldMan", "group": 1},
    #     {"id": "Labarre", "group": 2},
    #     {"id": "Valjean", "group": 2},
    #     {"id": "Marguerite", "group": 3},
    #     {"id": "Mme.deR", "group": 2},
    #     {"id": "Isabeau", "group": 2},
    #     {"id": "Gervais", "group": 2},
    #     {"id": "Tholomyes", "group": 3},
    #     {"id": "Listolier", "group": 3},
    #     {"id": "Fameuil", "group": 3},
    #     {"id": "Blacheville", "group": 3},
    #     {"id": "Favourite", "group": 3},
    #     {"id": "Dahlia", "group": 3},
    #     {"id": "Zephine", "group": 3},
    #     {"id": "Fantine", "group": 3},
    #     {"id": "Mme.Thenardier", "group": 4},
    #     {"id": "Thenardier", "group": 4},
    #     {"id": "Cosette", "group": 5},
    #     {"id": "Javert", "group": 4},
    #     {"id": "Fauchelevent", "group": 0},
    #     {"id": "Bamatabois", "group": 2},
    #     {"id": "Perpetue", "group": 3},
    #     {"id": "Simplice", "group": 2},
    #     {"id": "Scaufflaire", "group": 2},
    #     {"id": "Woman1", "group": 2},
    #     {"id": "Judge", "group": 2},
    #     {"id": "Champmathieu", "group": 2},
    #     {"id": "Brevet", "group": 2},
    #     {"id": "Chenildieu", "group": 2},
    #     {"id": "Cochepaille", "group": 2},
    #     {"id": "Pontmercy", "group": 4},
    #     {"id": "Boulatruelle", "group": 6},
    #     {"id": "Eponine", "group": 4},
    #     {"id": "Anzelma", "group": 4},
    #     {"id": "Woman2", "group": 5},
    #     {"id": "MotherInnocent", "group": 0},
    #     {"id": "Gribier", "group": 0},
    #     {"id": "Jondrette", "group": 7},
    #     {"id": "Mme.Burgon", "group": 7},
    #     {"id": "Gavroche", "group": 8},
    #     {"id": "Gillenormand", "group": 5},
    #     {"id": "Magnon", "group": 5},
    #     {"id": "Mlle.Gillenormand", "group": 5},
    #     {"id": "Mme.Pontmercy", "group": 5},
    #     {"id": "Mlle.Vaubois", "group": 5},
    #     {"id": "Lt.Gillenormand", "group": 5},
    #     {"id": "Marius", "group": 8},
    #     {"id": "BaronessT", "group": 5},
    #     {"id": "Mabeuf", "group": 8},
    #     {"id": "Enjolras", "group": 8},
    #     {"id": "Combeferre", "group": 8},
    #     {"id": "Prouvaire", "group": 8},
    #     {"id": "Feuilly", "group": 8},
    #     {"id": "Courfeyrac", "group": 8},
    #     {"id": "Bahorel", "group": 8},
    #     {"id": "Bossuet", "group": 8},
    #     {"id": "Joly", "group": 8},
    #     {"id": "Grantaire", "group": 8},
    #     {"id": "MotherPlutarch", "group": 9},
    #     {"id": "Gueulemer", "group": 4},
    #     {"id": "Babet", "group": 4},
    #     {"id": "Claquesous", "group": 4},
    #     {"id": "Montparnasse", "group": 4},
    #     {"id": "Toussaint", "group": 5},
    #     {"id": "Child1", "group": 10},
    #     {"id": "Child2", "group": 10},
    #     {"id": "Brujon", "group": 4},
    #     {"id": "Mme.Hucheloup", "group": 8}
    #   ],
    #   "links": [
    #     {"source": "Napoleon", "target": "Myriel", "value": 1},
    #     {"source": "Mlle.Baptistine", "target": "Myriel", "value": 8},
    #     {"source": "Mme.Magloire", "target": "Myriel", "value": 10},
    #     {"source": "Mme.Magloire", "target": "Mlle.Baptistine", "value": 6},
    #     {"source": "CountessdeLo", "target": "Myriel", "value": 1},
    #     {"source": "Geborand", "target": "Myriel", "value": 1},
    #     {"source": "Champtercier", "target": "Myriel", "value": 1},
    #     {"source": "Cravatte", "target": "Myriel", "value": 1},
    #     {"source": "Count", "target": "Myriel", "value": 2},
    #     {"source": "OldMan", "target": "Myriel", "value": 1},
    #     {"source": "Valjean", "target": "Labarre", "value": 1},
    #     {"source": "Valjean", "target": "Mme.Magloire", "value": 3},
    #     {"source": "Valjean", "target": "Mlle.Baptistine", "value": 3},
    #     {"source": "Valjean", "target": "Myriel", "value": 5},
    #     {"source": "Marguerite", "target": "Valjean", "value": 1},
    #     {"source": "Mme.deR", "target": "Valjean", "value": 1},
    #     {"source": "Isabeau", "target": "Valjean", "value": 1},
    #     {"source": "Gervais", "target": "Valjean", "value": 1},
    #     {"source": "Listolier", "target": "Tholomyes", "value": 4},
    #     {"source": "Fameuil", "target": "Tholomyes", "value": 4},
    #     {"source": "Fameuil", "target": "Listolier", "value": 4},
    #     {"source": "Blacheville", "target": "Tholomyes", "value": 4},
    #     {"source": "Blacheville", "target": "Listolier", "value": 4},
    #     {"source": "Blacheville", "target": "Fameuil", "value": 4},
    #     {"source": "Favourite", "target": "Tholomyes", "value": 3},
    #     {"source": "Favourite", "target": "Listolier", "value": 3},
    #     {"source": "Favourite", "target": "Fameuil", "value": 3},
    #     {"source": "Favourite", "target": "Blacheville", "value": 4},
    #     {"source": "Dahlia", "target": "Tholomyes", "value": 3},
    #     {"source": "Dahlia", "target": "Listolier", "value": 3},
    #     {"source": "Dahlia", "target": "Fameuil", "value": 3},
    #     {"source": "Dahlia", "target": "Blacheville", "value": 3},
    #     {"source": "Dahlia", "target": "Favourite", "value": 5},
    #     {"source": "Zephine", "target": "Tholomyes", "value": 3},
    #     {"source": "Zephine", "target": "Listolier", "value": 3},
    #     {"source": "Zephine", "target": "Fameuil", "value": 3},
    #     {"source": "Zephine", "target": "Blacheville", "value": 3},
    #     {"source": "Zephine", "target": "Favourite", "value": 4},
    #     {"source": "Zephine", "target": "Dahlia", "value": 4},
    #     {"source": "Fantine", "target": "Tholomyes", "value": 3},
    #     {"source": "Fantine", "target": "Listolier", "value": 3},
    #     {"source": "Fantine", "target": "Fameuil", "value": 3},
    #     {"source": "Fantine", "target": "Blacheville", "value": 3},
    #     {"source": "Fantine", "target": "Favourite", "value": 4},
    #     {"source": "Fantine", "target": "Dahlia", "value": 4},
    #     {"source": "Fantine", "target": "Zephine", "value": 4},
    #     {"source": "Fantine", "target": "Marguerite", "value": 2},
    #     {"source": "Fantine", "target": "Valjean", "value": 9},
    #     {"source": "Mme.Thenardier", "target": "Fantine", "value": 2},
    #     {"source": "Mme.Thenardier", "target": "Valjean", "value": 7},
    #     {"source": "Thenardier", "target": "Mme.Thenardier", "value": 13},
    #     {"source": "Thenardier", "target": "Fantine", "value": 1},
    #     {"source": "Thenardier", "target": "Valjean", "value": 12},
    #     {"source": "Cosette", "target": "Mme.Thenardier", "value": 4},
    #     {"source": "Cosette", "target": "Valjean", "value": 31},
    #     {"source": "Cosette", "target": "Tholomyes", "value": 1},
    #     {"source": "Cosette", "target": "Thenardier", "value": 1},
    #     {"source": "Javert", "target": "Valjean", "value": 17},
    #     {"source": "Javert", "target": "Fantine", "value": 5},
    #     {"source": "Javert", "target": "Thenardier", "value": 5},
    #     {"source": "Javert", "target": "Mme.Thenardier", "value": 1},
    #     {"source": "Javert", "target": "Cosette", "value": 1},
    #     {"source": "Fauchelevent", "target": "Valjean", "value": 8},
    #     {"source": "Fauchelevent", "target": "Javert", "value": 1},
    #     {"source": "Bamatabois", "target": "Fantine", "value": 1},
    #     {"source": "Bamatabois", "target": "Javert", "value": 1},
    #     {"source": "Bamatabois", "target": "Valjean", "value": 2},
    #     {"source": "Perpetue", "target": "Fantine", "value": 1},
    #     {"source": "Perpetue", "target": "Fantine", "value": 30},
    #     {"source": "Simplice", "target": "Perpetue", "value": 2},
    #     {"source": "Simplice", "target": "Valjean", "value": 3},
    #     {"source": "Simplice", "target": "Fantine", "value": 2},
    #     {"source": "Simplice", "target": "Javert", "value": 1},
    #     {"source": "Scaufflaire", "target": "Valjean", "value": 1},
    #     {"source": "Woman1", "target": "Valjean", "value": 2},
    #     {"source": "Woman1", "target": "Javert", "value": 1},
    #     {"source": "Judge", "target": "Valjean", "value": 3},
    #     {"source": "Judge", "target": "Bamatabois", "value": 2},
    #     {"source": "Champmathieu", "target": "Valjean", "value": 3},
    #     {"source": "Champmathieu", "target": "Judge", "value": 3},
    #     {"source": "Champmathieu", "target": "Bamatabois", "value": 2},
    #     {"source": "Brevet", "target": "Judge", "value": 2},
    #     {"source": "Brevet", "target": "Champmathieu", "value": 2},
    #     {"source": "Brevet", "target": "Valjean", "value": 2},
    #     {"source": "Brevet", "target": "Bamatabois", "value": 1},
    #     {"source": "Chenildieu", "target": "Judge", "value": 2},
    #     {"source": "Chenildieu", "target": "Champmathieu", "value": 2},
    #     {"source": "Chenildieu", "target": "Brevet", "value": 2},
    #     {"source": "Chenildieu", "target": "Valjean", "value": 2},
    #     {"source": "Chenildieu", "target": "Bamatabois", "value": 1},
    #     {"source": "Cochepaille", "target": "Judge", "value": 2},
    #     {"source": "Cochepaille", "target": "Champmathieu", "value": 2},
    #     {"source": "Cochepaille", "target": "Brevet", "value": 2},
    #     {"source": "Cochepaille", "target": "Chenildieu", "value": 2},
    #     {"source": "Cochepaille", "target": "Valjean", "value": 2},
    #     {"source": "Cochepaille", "target": "Bamatabois", "value": 1},
    #     {"source": "Pontmercy", "target": "Thenardier", "value": 1},
    #     {"source": "Boulatruelle", "target": "Thenardier", "value": 1},
    #     {"source": "Eponine", "target": "Mme.Thenardier", "value": 2},
    #     {"source": "Eponine", "target": "Thenardier", "value": 3},
    #     {"source": "Anzelma", "target": "Eponine", "value": 2},
    #     {"source": "Anzelma", "target": "Thenardier", "value": 2},
    #     {"source": "Anzelma", "target": "Mme.Thenardier", "value": 1},
    #     {"source": "Woman2", "target": "Valjean", "value": 3},
    #     {"source": "Woman2", "target": "Cosette", "value": 1},
    #     {"source": "Woman2", "target": "Javert", "value": 1},
    #     {"source": "MotherInnocent", "target": "Fauchelevent", "value": 3},
    #     {"source": "MotherInnocent", "target": "Valjean", "value": 1},
    #     {"source": "Gribier", "target": "Fauchelevent", "value": 2},
    #     {"source": "Mme.Burgon", "target": "Jondrette", "value": 1},
    #     {"source": "Gavroche", "target": "Mme.Burgon", "value": 2},
    #     {"source": "Gavroche", "target": "Thenardier", "value": 1},
    #     {"source": "Gavroche", "target": "Javert", "value": 1},
    #     {"source": "Gavroche", "target": "Valjean", "value": 1},
    #     {"source": "Gillenormand", "target": "Cosette", "value": 3},
    #     {"source": "Gillenormand", "target": "Valjean", "value": 2},
    #     {"source": "Magnon", "target": "Gillenormand", "value": 1},
    #     {"source": "Magnon", "target": "Mme.Thenardier", "value": 1},
    #     {"source": "Mlle.Gillenormand", "target": "Gillenormand", "value": 9},
    #     {"source": "Mlle.Gillenormand", "target": "Cosette", "value": 2},
    #     {"source": "Mlle.Gillenormand", "target": "Valjean", "value": 2},
    #     {"source": "Mme.Pontmercy", "target": "Mlle.Gillenormand", "value": 1},
    #     {"source": "Mme.Pontmercy", "target": "Pontmercy", "value": 1},
    #     {"source": "Mlle.Vaubois", "target": "Mlle.Gillenormand", "value": 1},
    #     {"source": "Lt.Gillenormand", "target": "Mlle.Gillenormand", "value": 2},
    #     {"source": "Lt.Gillenormand", "target": "Gillenormand", "value": 1},
    #     {"source": "Lt.Gillenormand", "target": "Cosette", "value": 1},
    #     {"source": "Marius", "target": "Mlle.Gillenormand", "value": 6},
    #     {"source": "Marius", "target": "Gillenormand", "value": 12},
    #     {"source": "Marius", "target": "Pontmercy", "value": 1},
    #     {"source": "Marius", "target": "Lt.Gillenormand", "value": 1},
    #     {"source": "Marius", "target": "Cosette", "value": 21},
    #     {"source": "Marius", "target": "Valjean", "value": 19},
    #     {"source": "Marius", "target": "Tholomyes", "value": 1},
    #     {"source": "Marius", "target": "Thenardier", "value": 2},
    #     {"source": "Marius", "target": "Eponine", "value": 5},
    #     {"source": "Marius", "target": "Gavroche", "value": 4},
    #     {"source": "BaronessT", "target": "Gillenormand", "value": 1},
    #     {"source": "BaronessT", "target": "Marius", "value": 1},
    #     {"source": "Mabeuf", "target": "Marius", "value": 1},
    #     {"source": "Mabeuf", "target": "Eponine", "value": 1},
    #     {"source": "Mabeuf", "target": "Gavroche", "value": 1},
    #     {"source": "Enjolras", "target": "Marius", "value": 7},
    #     {"source": "Enjolras", "target": "Gavroche", "value": 7},
    #     {"source": "Enjolras", "target": "Javert", "value": 6},
    #     {"source": "Enjolras", "target": "Mabeuf", "value": 1},
    #     {"source": "Enjolras", "target": "Valjean", "value": 4},
    #     {"source": "Combeferre", "target": "Enjolras", "value": 15},
    #     {"source": "Combeferre", "target": "Marius", "value": 5},
    #     {"source": "Combeferre", "target": "Gavroche", "value": 6},
    #     {"source": "Combeferre", "target": "Mabeuf", "value": 2},
    #     {"source": "Prouvaire", "target": "Gavroche", "value": 1},
    #     {"source": "Prouvaire", "target": "Enjolras", "value": 4},
    #     {"source": "Prouvaire", "target": "Combeferre", "value": 2},
    #     {"source": "Feuilly", "target": "Gavroche", "value": 2},
    #     {"source": "Feuilly", "target": "Enjolras", "value": 6},
    #     {"source": "Feuilly", "target": "Prouvaire", "value": 2},
    #     {"source": "Feuilly", "target": "Combeferre", "value": 5},
    #     {"source": "Feuilly", "target": "Mabeuf", "value": 1},
    #     {"source": "Feuilly", "target": "Marius", "value": 1},
    #     {"source": "Courfeyrac", "target": "Marius", "value": 9},
    #     {"source": "Courfeyrac", "target": "Enjolras", "value": 17},
    #     {"source": "Courfeyrac", "target": "Combeferre", "value": 13},
    #     {"source": "Courfeyrac", "target": "Gavroche", "value": 7},
    #     {"source": "Courfeyrac", "target": "Mabeuf", "value": 2},
    #     {"source": "Courfeyrac", "target": "Eponine", "value": 1},
    #     {"source": "Courfeyrac", "target": "Feuilly", "value": 6},
    #     {"source": "Courfeyrac", "target": "Prouvaire", "value": 3},
    #     {"source": "Bahorel", "target": "Combeferre", "value": 5},
    #     {"source": "Bahorel", "target": "Gavroche", "value": 5},
    #     {"source": "Bahorel", "target": "Courfeyrac", "value": 6},
    #     {"source": "Bahorel", "target": "Mabeuf", "value": 2},
    #     {"source": "Bahorel", "target": "Enjolras", "value": 4},
    #     {"source": "Bahorel", "target": "Feuilly", "value": 3},
    #     {"source": "Bahorel", "target": "Prouvaire", "value": 2},
    #     {"source": "Bahorel", "target": "Marius", "value": 1},
    #     {"source": "Bossuet", "target": "Marius", "value": 5},
    #     {"source": "Bossuet", "target": "Courfeyrac", "value": 12},
    #     {"source": "Bossuet", "target": "Gavroche", "value": 5},
    #     {"source": "Bossuet", "target": "Bahorel", "value": 4},
    #     {"source": "Bossuet", "target": "Enjolras", "value": 10},
    #     {"source": "Bossuet", "target": "Feuilly", "value": 6},
    #     {"source": "Bossuet", "target": "Prouvaire", "value": 2},
    #     {"source": "Bossuet", "target": "Combeferre", "value": 9},
    #     {"source": "Bossuet", "target": "Mabeuf", "value": 1},
    #     {"source": "Bossuet", "target": "Valjean", "value": 1},
    #     {"source": "Joly", "target": "Bahorel", "value": 5},
    #     {"source": "Joly", "target": "Bossuet", "value": 7},
    #     {"source": "Joly", "target": "Gavroche", "value": 3},
    #     {"source": "Joly", "target": "Courfeyrac", "value": 5},
    #     {"source": "Joly", "target": "Enjolras", "value": 5},
    #     {"source": "Joly", "target": "Feuilly", "value": 5},
    #     {"source": "Joly", "target": "Prouvaire", "value": 2},
    #     {"source": "Joly", "target": "Combeferre", "value": 5},
    #     {"source": "Joly", "target": "Mabeuf", "value": 1},
    #     {"source": "Joly", "target": "Marius", "value": 2},
    #     {"source": "Grantaire", "target": "Bossuet", "value": 3},
    #     {"source": "Grantaire", "target": "Enjolras", "value": 3},
    #     {"source": "Grantaire", "target": "Combeferre", "value": 1},
    #     {"source": "Grantaire", "target": "Courfeyrac", "value": 2},
    #     {"source": "Grantaire", "target": "Joly", "value": 2},
    #     {"source": "Grantaire", "target": "Gavroche", "value": 1},
    #     {"source": "Grantaire", "target": "Bahorel", "value": 1},
    #     {"source": "Grantaire", "target": "Feuilly", "value": 1},
    #     {"source": "Grantaire", "target": "Prouvaire", "value": 1},
    #     {"source": "MotherPlutarch", "target": "Mabeuf", "value": 3},
    #     {"source": "Gueulemer", "target": "Thenardier", "value": 5},
    #     {"source": "Gueulemer", "target": "Valjean", "value": 1},
    #     {"source": "Gueulemer", "target": "Mme.Thenardier", "value": 1},
    #     {"source": "Gueulemer", "target": "Javert", "value": 1},
    #     {"source": "Gueulemer", "target": "Gavroche", "value": 1},
    #     {"source": "Gueulemer", "target": "Eponine", "value": 1},
    #     {"source": "Babet", "target": "Thenardier", "value": 6},
    #     {"source": "Babet", "target": "Gueulemer", "value": 6},
    #     {"source": "Babet", "target": "Valjean", "value": 1},
    #     {"source": "Babet", "target": "Mme.Thenardier", "value": 1},
    #     {"source": "Babet", "target": "Javert", "value": 2},
    #     {"source": "Babet", "target": "Gavroche", "value": 1},
    #     {"source": "Babet", "target": "Eponine", "value": 1},
    #     {"source": "Claquesous", "target": "Thenardier", "value": 4},
    #     {"source": "Claquesous", "target": "Babet", "value": 4},
    #     {"source": "Claquesous", "target": "Gueulemer", "value": 4},
    #     {"source": "Claquesous", "target": "Valjean", "value": 1},
    #     {"source": "Claquesous", "target": "Mme.Thenardier", "value": 1},
    #     {"source": "Claquesous", "target": "Javert", "value": 1},
    #     {"source": "Claquesous", "target": "Eponine", "value": 1},
    #     {"source": "Claquesous", "target": "Enjolras", "value": 1},
    #     {"source": "Montparnasse", "target": "Javert", "value": 1},
    #     {"source": "Montparnasse", "target": "Babet", "value": 2},
    #     {"source": "Montparnasse", "target": "Gueulemer", "value": 2},
    #     {"source": "Montparnasse", "target": "Claquesous", "value": 2},
    #     {"source": "Montparnasse", "target": "Valjean", "value": 1},
    #     {"source": "Montparnasse", "target": "Gavroche", "value": 1},
    #     {"source": "Montparnasse", "target": "Eponine", "value": 1},
    #     {"source": "Montparnasse", "target": "Thenardier", "value": 1},
    #     {"source": "Toussaint", "target": "Cosette", "value": 2},
    #     {"source": "Toussaint", "target": "Javert", "value": 1},
    #     {"source": "Toussaint", "target": "Valjean", "value": 1},
    #     {"source": "Child1", "target": "Gavroche", "value": 2},
    #     {"source": "Child2", "target": "Gavroche", "value": 2},
    #     {"source": "Child2", "target": "Child1", "value": 3},
    #     {"source": "Brujon", "target": "Babet", "value": 3},
    #     {"source": "Brujon", "target": "Gueulemer", "value": 3},
    #     {"source": "Brujon", "target": "Thenardier", "value": 3},
    #     {"source": "Brujon", "target": "Gavroche", "value": 1},
    #     {"source": "Brujon", "target": "Eponine", "value": 1},
    #     {"source": "Brujon", "target": "Claquesous", "value": 1},
    #     {"source": "Brujon", "target": "Montparnasse", "value": 1},
    #     {"source": "Mme.Hucheloup", "target": "Bossuet", "value": 1},
    #     {"source": "Mme.Hucheloup", "target": "Joly", "value": 1},
    #     {"source": "Mme.Hucheloup", "target": "Grantaire", "value": 1},
    #     {"source": "Mme.Hucheloup", "target": "Bahorel", "value": 1},
    #     {"source": "Mme.Hucheloup", "target": "Courfeyrac", "value": 1},
    #     {"source": "Mme.Hucheloup", "target": "Gavroche", "value": 1},
    #     {"source": "Mme.Hucheloup", "target": "Enjolras", "value": 1}
    #   ]
    # }

    test_json = {
        'nodes': [
            {'id': 'b1', 'desc': 'switch 1'},
            {'id': 'b2', 'desc': 'switch 2'},
            {'id': 'b3', 'desc': 'switch 3'},
            {'id': 'b4', 'desc': 'switch 4'},
            {'id': 'b5', 'desc': 'switch 5'},
            {'id': 'b6', 'desc': 'switch 6'},
            {'id': 'b7', 'desc': 'switch 7'},
            {'id': 'b8', 'desc': 'switch 8'},
            {'id': 'b9', 'desc': 'switch 9'},
            {'id': 'b10', 'desc': 'switch 10'}
        ],
        'links': [
            # b1 -- b2
            {'source': 'b1', 'target': 'b2', 'desc': 'b1-b2'},
            {'source': 'b2', 'target': 'b1', 'desc': 'b2-b1'},

            # b2 -- b3
            {'source': 'b2', 'target': 'b3', 'desc': 'b2-b3'},
            {'source': 'b3', 'target': 'b2', 'desc': 'b3-b2'},

            # b3 -- b4
            {'source': 'b3', 'target': 'b4', 'desc': 'b3-b4'},
            {'source': 'b4', 'target': 'b3', 'desc': 'b4-b3'},

            # b4 -- b5
            {'source': 'b4', 'target': 'b5', 'desc': 'b4-b5'},
            {'source': 'b5', 'target': 'b4', 'desc': 'b5-b4'},

            # b5 -- b6
            {'source': 'b5', 'target': 'b6', 'desc': 'b5-b6'},
            {'source': 'b6', 'target': 'b5', 'desc': 'b6-b5'},

            # b6 -- b7
            {'source': 'b6', 'target': 'b7', 'desc': 'b6-b7'},
            {'source': 'b7', 'target': 'b6', 'desc': 'b7-b6'},

            # b7 -- b8
            {'source': 'b7', 'target': 'b8', 'desc': 'b7-b8'},
            {'source': 'b8', 'target': 'b7', 'desc': 'b8-b7'},

            # b8 -- b9
            {'source': 'b8', 'target': 'b9', 'desc': 'b8-b9'},
            {'source': 'b9', 'target': 'b8', 'desc': 'b9-b8'},

            # b3 -- b7
            {'source': 'b3', 'target': 'b7', 'desc': 'b3-b7'},
            {'source': 'b7', 'target': 'b3', 'desc': 'b7-b3'},

            # b8 -- b10
            {'source': 'b8', 'target': 'b10', 'desc': 'b8-b10'},
            {'source': 'b10', 'target': 'b8', 'desc': 'b10-b8'}
        ]
    }


    # test_json = {
    #     "nodes": [
    #         {"id": "Myriel", "group": 1},
    #         {"id": "Napoleon", "group": 1}
    #     ],
    #     "links": [
    #         {'source': 'Myriel', 'target': 'Napoleon', 'value': 2},
    #         {'source': 'Napoleon', 'target': 'Myriel', 'value': 2},
    #         {'source': 'Myriel', 'target': 'Napoleon', 'value': 1}
    #     ]
    # }

    return json_response(test_json)





import waitress
import logging

from kns.logger import init_logger
from kns.entry import ENTRIES

# maybe it's not necessary to register an entry for rest service.
@ENTRIES.at(8771)
def serve():
    init_logger(
        logging.getLogger('waitress')
    )
    waitress.serve(app, listen='*:8771')


if __name__ == "__main__":
    serve()



