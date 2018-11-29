# -*- coding:utf-8 -*-


class ListProxyInvalidRange(Exception):
    pass

class ListProxy(object):
    """
        proxying operation on part of a list

        indicate range with: 
            start, length
            start, stop

        usage:
            l = range(10)
            pl1 = ListProxy(l)
            pl2 = ListProxy(l, start=3, length=4)
            pl3 = ListProxy(l, start=3, stop=7)
            pl4 = ListProxy(l, start=3, stop=-4)    # if size of l is changed, pl4 will be changed
    """

    @staticmethod
    def assure_positive_index(idx, length):
        """
            return a positive index
            idx -> index value
            length -> length of list
        """
        if not isinstance(idx, int):
            raise TypeError, "list indices must be integers, not %s" % type(idx).__name__
        if idx < -length or idx >= length:
            raise IndexError, "list index out of range"
        if idx < 0:
            return length + idx
        else:
            return idx

    def __init__(self, target, start=0, stop=None, length=None):
        """
            target -> the proxied list
            start -> the start position of proxied part
            length -> the length of proxied part
                      if length is None,
                      that means proxied part start from 
                      position "start" to stop of the list.
        """
        assert isinstance(target, list)
        target_len = len(target)

        pos_start = self.assure_positive_index(start, target_len)

        if stop is not None:
            # the maximum value of stop is len(target)+1
            pos_stop = stop
            if pos_stop < 0:
                pos_stop = self.assure_positive_index(pos_stop, target_len)
            assert pos_stop >= pos_start

        if length is not None:
            assert isinstance(length, int) and \
                   length >= 0 and \
                   length <= len(target)

        self._target = target
        self._start = start
        self._stop = stop
        self._length = length


    def __get_start(self):
        """
            the start index (a positive integer)
        """
        return self.assure_positive_index(self._start, len(self._target))

    def __get_stop(self):
        """
            stop index (a positive integer) from stop or length.
            this may change if a negative "stop" is indicated when initiating.
        """
        start = self.__get_start()
        if self._stop is not None:
            # from stop
            stop = self.assure_positive_index(self._stop-1, len(self._target))  # stop could be len(target)+1
            stop += 1

        elif self._length is not None:
            # from length
            stop = start + self._length
        else:
            # to the end, len(target)
            stop = len(self._target)

        if stop < start:
            raise ListProxyInvalidRange, "stop (%d) is smaller than start (%d)" % (stop, start)
        if stop > len(self._target):
            raise ListProxyInvalidRange, "stop (%d) is out of range" % stop

        return stop



    @property
    def start(self):
        return self.__get_start()


    @property
    def stop(self):
        """
            the positive value of the stop index (in proxied list)
        """
        return self.__get_stop()

    @property
    def length(self):
        """
            length the proxied part
        """
        return self.stop - self.start




    def adjust_index(self, idx):
        """
            proxy index -> target index
        """
        idx = self.assure_positive_index(idx, self.length)
        return self.start + idx


    def adjust_slice(self, s):
        """
            proxy range -> target range
        """
        assert isinstance(s, slice)
        if s.start is not None:
            start = self.adjust_index(s.start)
        else:
            start = self.start

        if s.stop is not None:
            stop = self.adjust_index(s.stop)
        else:
            stop =self.stop

        step = 1 if s.step is None else s.step

        if step > 0:
            assert start <= stop
        else:
            assert start >= stop

        return slice(start, stop, step)


    ##########################
    # outer APIs
    ##########################

    def __repr__(self):
        return repr(self._target[self.start: self.stop])

    def __str__(self):
        return str(self._target[self.start: self.stop])

    def __getitem__(self, soi):
        """
            soi -> slice of index
        """
        if isinstance(soi, slice):
            s = self.adjust_slice(soi)
            return self._target[s]
        else:
            idx = self.adjust_index(soi)
            return self._target[idx]


    def __setitem__(self, soi, value):
        """
            take care when using slice.
            when value is shorter than slice, target is shortened.
        """
        if isinstance(soi, slice):
            s = self.adjust_slice(soi)
            self._target[s] = value
        else:
            idx = self.adjust_index(soi)
            self._target[idx] = value

    def __delitem__(self, *args, **kwargs):
        raise TypeError, "cannot delete item in a list proxy."

    def __contains__(self, value):
        return value in self._target[self.start: self.stop]

    def __iter__(self):
        return self._target[self.start:self.stop].__iter__()

    def __len__(self):
        return self.length

    def __eq__(self, another):
        return self._target[self.start: self.stop] == another

    def __ne__(self, another):
        return self._target[self.start: self.start] != another

    def count(self, value):
        return self._target[self.start: self.stop].count(value)

    def index(self, value):
        return self._target[self.start: self.stop].index(value)



if __name__ == '__main__':
    import unittest

    class TestListProxy(unittest.TestCase):
        def test_basic(self):
            """
                basic operation
            """
            l = range(10)
            start = 0
            pl = ListProxy(l, start=start)

            # __getitem__
            self.assertEqual(pl[0], l[start+0])
            self.assertEqual(pl[1], l[start+1])
            self.assertEqual(pl[0:2], l[start+0: start+2])

            # __setitem__
            pl[3] = 99
            self.assertEqual(l[start+3], 99)
            pl[0:2] = [11,11]
            self.assertEqual(l[start+0: start+2], [11, 11])

            # __contains__
            self.assertTrue(9 in pl)

            # __iter__ and __eq__
            self.assertEqual([i for i in pl], pl)

            # __ne__
            self.assertNotEqual([33], pl)

            # count
            self.assertEqual(pl.count(9), 1)

            # index
            self.assertEqual(pl.index(9), 9)

        def test_positive_stop(self):
            l = range(10)
            start = 3
            stop = 6
            pl = ListProxy(l, start=start, stop=stop)
            l.insert(start, 99)
            self.assertEqual(pl[0], 99)

        def test_negative_stop(self):
            l = range(10)
            start = 3
            stop = -4
            # [3,4,5]
            pl = ListProxy(l, start=start, stop=stop)
            length = len(pl)
            l.pop()
            self.assertEqual(len(pl), length -1)




    unittest.main()

