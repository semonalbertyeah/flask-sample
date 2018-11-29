# -*- coding:utf-8 -*-

import threading, thread, time

from .time_util import wait


nothing = object()

def threaded(**options):
    """
        make calling of func in a new thread.
        options:
            name -> default : decorated function name
            daemon -> default : False
            start -> default : True
        Example:
            @threaded(name='test_function', start=False, daemon=True)
            def test():
                print 'test'

            t = test()
            t.start()
            t.join()
    """
    def decorator(func):
        name = options.get('name', func.__name__)
        daemon = bool(options.get('daemon', False))
        start = bool(options.get('start', True))

        assert callable(func)

        def thread_gen(*args, **kwargs):

            t = threading.Thread(
                target=func, 
                name=name,
                args=args, 
                kwargs=kwargs
            )
            t.setDaemon(daemon)
            if start:
                t.start()
                t.setName('%s-%d' % (t.name, t.ident))
            return t

        return thread_gen

    return decorator


def make_thread(target, **options):
    """
        options:
            args,
            kwargs
            name -> default : decorated function name
            daemon -> default : False
            start -> default : True
    """

    args = options.pop('args', ())
    kwargs = options.pop('kwargs', {})
    return threaded(**options)(target)(*args, **kwargs)


def wait_threads(tasks, timeout=5):
    """
        output:
            bool -> if all tasks are finished.
    """
    if not isinstance(tasks, (set, list, tuple)):
        tasks = [tasks]

    return wait(
        timeout, 
        break_cond=lambda: len(filter(lambda t: t.is_alive(), tasks)) == 0
    )
    # deadline = time.time() + timeout
    # while time.time() < deadline:
    #     if len(filter(lambda t: t.is_alive(), tasks)) == 0:
    #         return True

    #     time.sleep(0.2)

    # return False


# thread safe decorator for function
def thread_safe(func):

    _thread_lock = threading.Lock()
    def new_func(*args, **kwargs):
        with _thread_lock:
            return func(*args, **kwargs)

    return new_func


# thread safe decorator for class method
# def mthread_safe(method):
#     def new_method(self, *args, **kwargs):
#         if not hasattr(self, '_thread_lock_'):
#             self._thread_lock_ = threading.Lock()
#         with self._thread_lock_:
#             return method(self, *args, **kwargs)
#     return new_method


def mthread_safe(**options):
    """
        options:
            lock_name  -- the attribute name of thread lock
        Usage:
            class Test(object):
                @mthread_safe(lock_name='_lock1')
                def test11(self):
                    print 'test11'

                @mthread_safe(lock_name='lock1')
                def test12(self):
                    print 'test12'

                @mthread_safe(lock_name='lock2')
                def test21(self):
                    print 'test21'

    """

    def decorator(method):
        lock_name = options.get('lock_name', '_thread_lock_')
        def new_method(self, *args, **kwargs):
            lock = getattr(self, lock_name, nothing)
            if lock is nothing:
                lock = threading.Lock()
                setattr(self, lock_name, lock)
            assert isinstance(lock, thread.LockType), \
                    "%s is not instance of threading.Lock, maybe a conflict" % lock_name

            with lock:
                return method(self, *args, **kwargs)

        return new_method

    return decorator


class Flag(object):
    """
        A flag indicate true or false.
    """
    def __init__(self, val=True):
        self.__val = bool(val)

    def __bool__(self):
        return bool(self.__val)

    __nonzero__ = __bool__

    # @mthread_safe()
    def set_true(self):
        self.__val = True

    # @mthread_safe()
    def set_false(self):
        self.__val = False




if __name__ == '__main__':
    print 'main thread id:', threading.current_thread().ident
    @threaded()
    def test():
        print 'sub thread id:', threading.current_thread().ident

    test_t = test()
    test_t.join()
