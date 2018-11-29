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

    username = "root"
    password = "123456"
    db_host = "127.0.0.1"
    db_port = "3306"

    engine = create_engine(
        "mysql+pymysql://%s:%s@%s:%s/flasktestdb" % (username, password, db_host, db_port),
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
        print u"database connection failed, exiting ...."

        sys.exit(-2)

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





