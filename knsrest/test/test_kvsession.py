from knsrest.kvsession import *

import time

def test_NewKVSession():
    sess = NewKVSession({'a':1, 'b':2, 'c':3})

    # test last_touch
    assert not sess.last_touch
    sess.refresh()
    assert sess.last_touch

    # test has_expired
    now = sess.last_touch
    assert not sess.has_expired(1, now)
    assert sess.has_expired(1, now + 2)

    # test refresh
    sess.refresh()
    new_now = sess.last_touch

    assert new_now > now


