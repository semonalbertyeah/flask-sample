# -*- coding:utf-8 -*-
import types

from werkzeug.local import LocalProxy
from flask import current_app, session, _request_ctx_stack, request

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import Column, String

try:
    import cPickle as pickle
except ImportError as e:
    import pickle


DBSession = sessionmaker()

Base = declarative_base()
class UserInfo(Base):
    """
        sqlalchemy mapper for user
    """
    __tablename__ = 'users'
    username = Column(String(100), primary_key=True)
    password_hash = Column(String(100))
    roles = Column(String(512), default=pickle.dumps(set())) # value: pickle.dumps(set('admin', 'super'))

    @property
    def assigned_roles(self):
        roles = self.roles
        if isinstance(roles, unicode):
            roles = roles.encode('utf-8')
        return pickle.loads(roles)

    def __cast_roles_type(self, roles):
        """
            cast to proper roles type
        """
        if not isinstance(roles, set):
            if isinstance(roles, (list, tuple)):
                roles = set(roles)
            else:
                roles = set([roles])

        return roles


    def set_roles(self, roles):
        roles = self.__cast_roles_type(roles)
        self.roles = pickle.dumps(roles)

    def add_roles(self, roles):
        roles = self.__cast_roles_type(roles)
        new_roles = self.assigned_roles.union(roles)
        self.set_roles(new_roles)

    def delete_roles(self, roles):
        roles = self.__cast_roles_type(roles)
        new_roles = self.assigned_roles.difference(roles)
        self.set_roles(new_roles)


    def to_dict(self):
        return {
            'username': self.username,
            'password_hash': self.password_hash,
            'assigned_roles': self.assigned_roles
        }



import hashlib

class UserError(Exception):
    """
        desc:
            Corresponding to CFSUser.
            Exception info should be visible to end user.
    """

    # errno
    ERR_NO_SUCH = -1
    ERR_WRONG_PASS = -2
    ERR_NOT_LOGIN = -3

    def __init__(self, errno=None, msg=None):
        self.errno = errno
        self.msg = msg

    def __str__(self):
        return '<CFSUserException: {"errno": %d, "msg": "%s"}>' % \
                (self.errno, self.msg)


class User(object):
    """
        represent current user:
            just a wrapper of session.

        self.session    -> flask session
    """
    def __init__(self, session):
        """
            session: flask session
            db_session_factory: sqlalchemy session factory
        """

        self.session = session
        # self.db_session_factory = db_session_factory

        if not hasattr(session, 'destroy'):
            def destroy_session():
                # clear method of dict (or dict mixin: CallbackDict)
                self.session.clear()
            self.session.destroy = destroy_session

    # make it dict-like
    def __getitem__(self, key):
        return self.session[key]

    def __setitem__(self, key, value):
        self.session[key] = value

    def __delitem__(self, key):
        del self.session[key]

    def __contains__(self, key):
        return key in self.session

    @staticmethod
    def make_password_hash(password):
        return hashlib.md5(str(password)).digest()

    ######################
    # user properties
    ######################

    @staticmethod
    def get_db_info(username):
        # session = self.db_session_factory()
        session = DBSession()
        user_info = session.query(UserInfo).filter(UserInfo.username == username).scalar()
        session.close()
        if user_info is None:
            return None
        else:
            return user_info.to_dict()


    @property
    def db_info(self):
        """
            corresponding db info for current user.
        """
        username = self.session.get('username', None)
        if username is None:
            return None

        return self.get_db_info(username)


    @property
    def username(self):
        return self.session.get('username', None)


    @property
    def password_hash(self):
        return self.session.get('password_hash', None)

    @property
    def assigned_roles(self):
        db_info = self.db_info
        if db_info is None:
            return set()
        else:
            return self.db_info['assigned_roles']


    def login(self, username, password, remember_me=False):
        """
            login current user
                remember_me: if permanent
        """
        user_info = self.get_db_info(username)
        if user_info is None:
            raise UserError(
                errno=UserError.ERR_NO_SUCH,
                msg='login failed: no such user.'
            )

        password_hash = self.make_password_hash(password)
        if user_info['password_hash'] != password_hash:
            raise UserError(
                errno=UserError.ERR_WRONG_PASS,
                msg='login failed: wrong password.'
            )

        # update current user info
        self.session['username'] = username
        self.session['password_hash'] = password_hash
        self.session.permanent = bool(remember_me)



    def logout(self):
        """
            logout current user. just delete session.
        """

        self.session.destroy()


    def is_valid(self):
        return self.session.get('username', None) is not None and \
                self.session.get('password_hash', None) is not None


    def logged_in(self):
        # valid user
        if not self.is_valid():
            return False

        # consistent password
        if self.db_info is None:
            return False
        return self.password_hash == self.db_info['password_hash']

    def change_password(self, old_passwd, new_passwd):
        """
            change password
        """
        if not self.logged_in():
            raise UserError(
                errno=UserError.ERR_NOT_LOGIN,
                msg="need logging in."
            )

        if self.make_password_hash(old_passwd) != self.password_hash:
            raise UserError(
                errno=UserError.ERR_WRONG_PASS,
                msg="wrong old password."
            )

        db_session = DBSession()

        rec = db_session.query(UserInfo).filter(
            UserInfo.username == self.username
        ).first()

        rec.password_hash = self.make_password_hash(new_passwd)
        db_session.commit()

        db_session.close()











###########################################
# apply user authentication to a flask app
# it does:
#   1. initiate user db (sqlalchemy): create table
#   2. create a default user "admin", with role "admin"
#   3. add before_request handler: create a user instance with session info
###########################################
def init_user(app, db_engine):
    """
        apply session user to app.
        before any requests: spawn user instance, check user validity(logged in).
        input:
            app: flask application
            db_engine: sqlalchemy engine
            session_factory: sqlalchemy session_factory
    """

    Base.metadata.bind = db_engine
    Base.metadata.create_all()  # create user table if not exists.

    DBSession.configure(bind=db_engine)


    @app.before_request
    def get_user():
        """
            1. get user
            # 2. check user: logged in
        """
        default_err_msg = 'user check failed'

        user = User(session)
        _request_ctx_stack.top.user = user

        # global _login_check_exempts
        # view = current_app.view_functions.get(request.endpoint)
        # if not view in _login_check_exempts:
        #     if not user.logged_in():
        #         abort(404, 'need to log in')

    # add admin user (admin:123456)
    @app.before_first_request
    def add_default_user():
        session = DBSession()
        if not session.query(UserInfo).filter(UserInfo.username=='admin').scalar():
            user_info = UserInfo(
                username='admin', 
                password_hash=User.make_password_hash('123456'),
                roles=pickle.dumps(['admin'])
            )
            session.add(user_info)
            session.commit()

        session.close()


def _get_user():
    return getattr(_request_ctx_stack.top, 'user', None)


#########################################
# current user
#   generated before handling a request
#########################################
current_user = LocalProxy(_get_user)



####################
# test cases
####################

import unittest

class TestUserInfo(unittest.TestCase):
    def setUp(self):
        from sqlalchemy import create_engine
        db_engine = create_engine('mysql+pymysql://test_admin:123456@localhost/test_db')
        self.db_engine = db_engine
        Base.metadata.bind = db_engine
        Base.metadata.create_all()  # create user table if not exists.
        DBSession.configure(bind=db_engine)

        self.db_session = DBSession()

        # clear all records if any
        self.db_session.query(UserInfo).delete()
        self.db_session.commit()

        # create a test user
        self.user_info = UserInfo(
            username='user', 
            password_hash=User.make_password_hash('123456'),
            roles = pickle.dumps(set())
        )
        self.db_session.add(self.user_info)
        self.db_session.commit()



    def test__assigned_roles(self):
        # @property
        # def assigned_roles(self):

        print 'test: assigned_roles'
        self.assertEqual(self.user_info.assigned_roles, set())


    def test__set_roles(self):
        # def set_roles(self, roles):

        print 'test: set_roles'
        self.user_info.set_roles('admin')
        self.assertEqual(self.user_info.assigned_roles, set(['admin']))
        self.user_info.set_roles(['user1', 'user2'])
        self.assertEqual(self.user_info.assigned_roles, set(['user1', 'user2']))

    def test__add_roles(self):

        # def add_roles(self, roles):
        print 'test: add_roles'
        self.user_info.set_roles(set())

        self.user_info.add_roles('admin')
        self.assertEqual(self.user_info.assigned_roles, set(['admin']))

        self.user_info.add_roles(['user1', 'user2'])
        self.assertEqual(self.user_info.assigned_roles, set(['admin', 'user1', 'user2']))


    def test__delete_roles(self):
        # def delete_roles(self, roles):
        print 'test: delete_roles'
        self.user_info.set_roles(['admin', 'user1', 'user2'])

        self.user_info.delete_roles('admin')
        self.assertEqual(self.user_info.assigned_roles, set(['user1', 'user2']))

        self.user_info.delete_roles(['user1'])
        self.assertEqual(self.user_info.assigned_roles, set(['user2']))


    def test__to_dict(self):

        # def to_dict(self):
        print 'test: to_dict'
        self.user_info.set_roles(['admin', 'guest'])
        self.assertEqual(
            self.user_info.to_dict(), 
            {
                'username': 'user',
                'password_hash': User.make_password_hash('123456'),
                'assigned_roles': {'admin', 'guest'}
            }
        )


    def tearDown(self):
        Base.metadata.bind = None

        self.db_session.close()
        self.db_engine.dispose()

        del self.db_session
        del self.db_engine


class TestUser(unittest.TestCase):
    class TestSession(dict):
        permanent = False

    def prepare_db(self):
        from sqlalchemy import create_engine

        db_engine = create_engine('mysql+pymysql://test_admin:123456@localhost/test_db')
        self.db_engine = db_engine
        Base.metadata.bind = db_engine
        Base.metadata.create_all() 
        DBSession.configure(bind=db_engine)

        self.db_session = DBSession()


    def setUp(self):
        self.prepare_db()

        # clear all records if any
        self.db_session.query(UserInfo).delete()
        self.db_session.commit()

        # create a test user_info
        self.user_info = UserInfo(
            username='guest', 
            password_hash=User.make_password_hash('123456'),
            roles = pickle.dumps(set(['guest']))
        )
        self.db_session.add(self.user_info)
        self.db_session.commit()


    def test__existing_user(self):
        guest = User(TestUser.TestSession(
            username='guest',
            password_hash=User.make_password_hash('123456')
            ))

        self.assertEqual(
            guest.db_info,
            {
                'username': 'guest',
                'password_hash': User.make_password_hash('123456'),
                'assigned_roles': set(['guest'])
            }
        )
        self.assertEqual(guest.is_valid(), True)
        self.assertEqual(guest.logged_in(), True)

        self.assertEqual(guest.username, 'guest')
        self.assertEqual(guest.password_hash, User.make_password_hash('123456'))
        self.assertEqual(guest.assigned_roles, set(['guest']))

    def test__non_exising_user(self):
        non_existing_user = User(TestUser.TestSession(
            username='whatever',
            password_hash=User.make_password_hash('whatever_password')
            ))

        self.assertEqual(non_existing_user.db_info, None)
        self.assertEqual(non_existing_user.is_valid(), True)
        self.assertEqual(non_existing_user.logged_in(), False)

        self.assertEqual(non_existing_user.username, 'whatever')
        self.assertEqual(non_existing_user.password_hash, User.make_password_hash('whatever_password'))
        self.assertEqual(non_existing_user.assigned_roles, set())


    def test__empty_session(self):

        user = User(TestUser.TestSession())

        self.assertEqual(user.db_info, None)
        self.assertEqual(user.is_valid(), False)
        self.assertEqual(user.logged_in(), False)

        self.assertEqual(user.username, None)
        self.assertEqual(user.password_hash, None)
        self.assertEqual(user.assigned_roles, set())


    def test__login(self):
        user = User(TestUser.TestSession())
        user.login('guest', '123456', True)

        self.assertEqual(user.session.permanent, True)
        self.assertEqual(
            user.db_info,
            {
                'username': 'guest',
                'password_hash': User.make_password_hash('123456'),
                'assigned_roles': set(['guest'])
            }
        )
        self.assertEqual(user.is_valid(), True)
        self.assertEqual(user.logged_in(), True)

        self.assertEqual(user.username, 'guest')
        self.assertEqual(user.password_hash, User.make_password_hash('123456'))
        self.assertEqual(user.assigned_roles, set(['guest']))

    def test__logout(self):
        user = User(TestUser.TestSession())
        user.login('guest', '123456', True)

        user.logout()

        self.assertEqual(user.db_info, None)
        self.assertEqual(user.is_valid(), False)
        self.assertEqual(user.logged_in(), False)

        self.assertEqual(user.db_info, None)
        self.assertEqual(user.is_valid(), False)
        self.assertEqual(user.logged_in(), False)



    def release_db(self):
        self.db_session.close()
        self.db_engine.dispose()

        Base.metadata.bind = None

        del self.db_session
        del self.db_engine


    def tearDown(self):
        self.release_db()




if __name__ == '__main__':
    unittest.main()

