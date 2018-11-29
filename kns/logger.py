# -*- coding:utf-8 -*-

"""
    Root logger for all kns services.
    Just send messages to stdout.
"""

import sys, logging

def init_logger(logger=None):
    logger = logger or logging.getLogger('kns')
    logger.setLevel(logging.DEBUG)

    # stream handler to stdout
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(
        logging.Formatter(
            "%(asctime)s-%(name)s-%(levelname)s-%(funcName)s: %(message)s"
        )
    )

    logger.addHandler(ch)

    sys.excepthook = lambda t, v, tb: logger.error('Uncaught exception:', exc_info=(t, v, tb))

    return logger


def get_logger():
    return logging.getLogger('kns')


logger = init_logger()



