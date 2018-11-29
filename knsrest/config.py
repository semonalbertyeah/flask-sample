# -*- coding:utf-8 -*-

from datetime import timedelta


class KVSessionConfig:
    """
        flask-kvsession configuration
    """

    # {custom} interval between each action to cleaning up outdated sessions.
    KVSESSION_CLEANUP_PERIOD = 60*60*24
    # KVSESSION_CLEANUP_PERIOD = 1    # test: 1 seconds,

    # {custom} flask-kvsession table
    KVSESSION_TABLE = 'kvsessions'

    # {custom} db table used to store app running state
    STATUS_TABLE = 'status'


class AppConfig:
    """
        Flask app configuration
    """

    DEBUG = True
    PRESERVE_CONTEXT_ON_EXCEPTION = False   # do not keep request context in debug mode

    # DEBUG = False
    SECRET_KEY = u'\xf2\xb1;n#\xa1p\x88\xc1\xf4v'\
                 u'\xb6r\x19\xceK5L;m\xfe{G\xa8'

    # session
    SESSION_COOKIE_NAME = 'session_id'
    SESSION_COOKIE_HTTPONLY = True  # default: True
    # SESSION_COOKIE_HTTPONLY = False   # default: True
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=300)



class Config(AppConfig, KVSessionConfig):
    """
        all configuration
    """



