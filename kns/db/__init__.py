# -*- coding:utf-8 -*-

"""
    Database interfaces.

        session management in web app
        Web Server          Web Framework        SQLAlchemy ORM Code
        --------------      --------------       ------------------------------
        startup        ->   Web framework        # Session registry is established
                            initializes          Session = scoped_session(sessionmaker())

        incoming
        web request    ->   web request     ->   # The registry is *optionally*
                            starts               # called upon explicitly to create
                                                 # a Session local to the thread and/or request
                                                 Session()

                                                 # the Session registry can otherwise
                                                 # be used at any time, creating the
                                                 # request-local Session() if not present,
                                                 # or returning the existing one
                                                 Session.query(MyClass) # ...

                                                 Session.add(some_object) # ...

                                                 # if data was modified, commit the
                                                 # transaction
                                                 Session.commit()

                            web request ends  -> # the registry is instructed to
                                                 # remove the Session
                                                 Session.remove()

                            sends output      <-
        outgoing web    <-
        response

"""

import importlib, os, sys
from sqlalchemy import create_engine, bindparam
from sqlalchemy.sql import text
from sqlalchemy import exc, event, select

from .extension import *
from ..entry import ENTRIES
from .common import Base, ThreadSession


CUR_DIR = os.path.dirname(os.path.abspath(__file__))



##################################
# import all models:
#   py files start with model_
#   such as model_device.py
##################################
for fn in os.listdir(CUR_DIR):
    if fn.endswith('.py') and fn.startswith('model_'):
        mod_name = '.%s' % fn.rstrip('.py')
        importlib.import_module(mod_name, __package__)

metadata = Base.metadata

engine = None

def init_db():
    global engine
    if engine:
        engine.dispose()
    # db_host, db_port = ENTRIES['knsdb']
    entry = ENTRIES.get('knsdb', wait_timeout=5)
    if entry is None:
        print "Timeout waiting database entry."
        sys.exit(-2)

    db_host, db_port = entry
    engine = create_engine(
        # "mysql+pymysql://nms_admin:123qwe@knsdb/nms",
        # "mysql+pymysql://nms_admin:123qwe@172.17.0.2:3306/nms",

        # "mysql+pymysql://nms_admin:123qwe@%s:%s/nms" % (db_host, db_port),
        "mysql+pymysql://root:123456@%s:%s/nms" % (db_host, db_port),  # this is for testing: to set wait_timeout

        # echo=True,
        isolation_level='READ_COMMITTED',
        # paramstyle='pyformat',
        pool_pre_ping=True,
        pool_timeout=5,         # timeout to wait
        pool_recycle=3600       # mysql db default is 8 hours
        # pool_recycle=1       # mysql db default is 8 hours
    )

    try:
        engine.execute('select 1;')
    except Exception as e:
        # print u"failed to connect database, error message: %s" % unicode(e)
        print u"wait database..."

        sys.exit(-2)

    # for debugging:
    #   to reproduce the exception: ""
    # engine.execute('SET wait_timeout=2;')

    # @event.listens_for(engine, "engine_connect")
    # def ping_connection(connection, branch):
    #     print '\n============ check db connection'
    #     if branch:
    #         print "========== branch."
    #         # "branch" refers to a sub-connection of a connection,
    #         # we don't want to bother pinging on these.
    #         return

    #     try:
    #         print '============ ping.'
    #         # run a SELECT 1.   use a core select() so that
    #         # the SELECT of a scalar value without a table is
    #         # appropriately formatted for the backend
    #         connection.scalar(select([1]))
    #         print '============ success.'
    #     except exc.DBAPIError as err:
    #         # catch SQLAlchemy's DBAPIError, which is a wrapper
    #         # for the DBAPI's exception.  It includes a .connection_invalidated
    #         # attribute which specifies if this connection is a "disconnect"
    #         # condition, which is based on inspection of the original exception
    #         # by the dialect in use.
    #         if err.connection_invalidated:
    #             # run the same SELECT again - the connection will re-validate
    #             # itself and establish a new connection.  The disconnect detection
    #             # here also causes the whole connection pool to be invalidated
    #             # so that all stale connections are discarded.
    #             print '============ second success.'
    #             connection.scalar(select([1]))
    #         else:
    #             print '============ failure .'
    #             raise
    #     finally:
    #         print '\n'


    ThreadSession.configure(bind=engine)

    metadata.bind = engine
    metadata.create_all(checkfirst=True)    # checkfirst=True not working

    return engine, ThreadSession


init_db()

db_session = ThreadSession



def insert_or_update(table, *fields):
    """
        return sqlalchemy.sql.text of INSERT ... ON DUPLICATE KEY UPDATE
        input:
            table --> sqlalchemy.sql.schema.Table
            kw --> value fields
    """
    sql = ["INSERT INTO %s " % table.name]
    sql.append("(" + ",".join(fields) + ") ")
    sql.append("VALUES (" + ",".join(":%s" % fname for fname in fields) + ") ")
    sql.append("ON DUPLICATE KEY UPDATE " + ",".join("%s=VALUES(%s)" % (fname, fname) for fname in fields) + ";")

    return text(
        ''.join(sql)
    ).bindparams(
        *[bindparam(fname, table.columns[fname].type) for fname in fields]
    )



def insert_with_check_foreignkey(table, *fields):
    """
        return sqlalchemy.sql.text of insertion with checking foreignkeys constraint
        if foreignkey records do not exist, no record will be inserted.

        insert_with_check_foreignkey(DeviceBaseInfo.__table__, 'device_mac', 'id')
        will generate:
            INSERT INTO mib_basic_info (device_mac,id) 
            SELECT :device_mac AS device_mac,:id AS id 
            FROM devices 
            WHERE devices.mac=:device_mac;
    """
    fkeys = []
    for fkey in table.foreign_keys:
        if fkey.parent.name in fields:
            fkeys.append(fkey)
    sql = ["INSERT INTO %s " % table.name]
    sql.append("(" + ",".join(fields) + ") ")
    if fkeys:
        sql.append("SELECT " + ",".join(":%s AS %s" % (f, f) for f in fields) + " ")
        sql.append("FROM " + ",".join(fk.column.table.name for fk in fkeys) + " ")
        sql.append("WHERE " + " AND ".join("%s=:%s" % (str(fk.column), fk.parent.name) for fk in fkeys) + ";")
    else:
        sql.append("VALUES (" + ",".join(":%s" % f for f in fields) + ");")
    return text(
        "".join(sql)
    ).bindparams(
        *[bindparam(f, table.columns[f].type) for f in fields]
    )





