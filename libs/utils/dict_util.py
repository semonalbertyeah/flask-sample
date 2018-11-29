# -*- coding:utf-8 -*-

import copy

def is_subdict(con, sub):
    for key, value in sub.iteritems():
        if not con.has_key(key):
            return False
        if con[key] != value:
            return False

    return True

def merge_dicts(*dicts):
    result = {}
    for d in dicts:
        result.update(d)
    return result

def dict_has_keys(d, keys):
    if not isinstance(keys, (list, tuple)):
        keys = [keys]
    # return all (key in d for key in keys)
    for key in keys:
        if not d.has_key(key):
            return False
    return True

def sub_dict(d, *keys):
    return dict((key, d[key]) for key in keys if key in d)


def filter_dict(d, filter_cond=None):
    """
        create a new sub-dict from d whose memeber is filtered by filter_cond
        input:
            d -> source dict
            filter_cond -> function(key, value) -> bool
    """
    d = dict(d)
    if filter_cond:
        return {key: val for key, val in d.iteritems() if filter_cond(key, val)}
    else:
        return copy.copy(d)
