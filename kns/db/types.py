# -*- coding:utf-8 -*-


"""
    Some custome data types.
"""


import socket
from sqlalchemy.types import Unicode, TypeDecorator, Enum, Integer, Boolean
from netaddr import EUI


class IpAddress(TypeDecorator):
    impl = Unicode

    def __init__(self, **kwargs):
        kwargs['length'] = 20
        super(IpAddress, self).__init__(**kwargs)

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = self.ip_pretty(value)   # check
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            socket.inet_aton(value) # check
        return value

    @staticmethod
    def ip_pretty(ip):
        """
            return string format IP value (unicode).
            input:
                ip: 4-byte int, [4 8-bit int], display string.
            output:
                display string format of IP address.
        """
        if isinstance(ip, int):
            assert ip >= 0 and ip <= 0xffffffff
            ip = ''.join([chr(i) for i in int_2_byte_array(ip, 4)])
        elif isinstance(ip, (list, tuple)):
            assert all([isinstance(i, int) for i in ip])
            assert all([(i >= 0 and i <= 0xff) for i in ip])
            ip = ''.join([chr(i) for i in ip])
        elif isinstance(ip, (str, unicode)):
            socket.inet_pton(socket.AF_INET, ip)
            return ip
        else:
            raise ValueError, "not supported value: %r" % ip

        return socket.inet_ntoa(ip).decode('utf-8')

    @staticmethod
    def valid(ip):
        try:
            IpAddress.ip_pretty(ip)
            return True
        except Exception:
            return False


class MacAddress(TypeDecorator):
    """
        MAC address compatible with EUI.
    """
    impl = Unicode

    def __init__(self, **kwargs):
        kwargs['length'] = 20
        super(MacAddress, self).__init__(**kwargs)

    @staticmethod
    def valid(mac):
        try:
            mac = EUI(mac)
            if len(mac.words) != 6:
                return False

            return True
        except Exception:
            return False

    @staticmethod
    def is_unicast(mac):
        if not MacAddress.valid(mac):
            return False

        mac = EUI(mac)
        if mac.words[0] % 2:
            return False

        return True

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = unicode(EUI(value))  # check
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = unicode(EUI(value))  # check
        return value


class IntEnum(TypeDecorator):
    """
        Integer enum
    """

    impl = Integer

    def __init__(self, *enums, **kwargs):
        assert enums, "please offer at least one value."
        assert all([isinstance(i, int) for i in enums]), "all values must be integer."
        assert len(enums) == len(set(enums)), "duplicated values."

        self.enums = enums
        super(IntEnum, self).__init__(**kwargs)

    def assure_value(self, value):
        if value not in self.enums:
            raise ValueError, "%r" % value

        return value

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return self.assure_value(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return self.assure_value(value)




class NamedIntEnum(TypeDecorator):
    """
        Usage:
            class Device(Base):
                id = Column(Integer, primary_key=True)
                state = Column(NamedIntEnum(enums={'normal': 0, 'error': 1}))

            dev = Device()
            dev.state = 'normal'    # 'normal'
            dev.state = ''          # 'normal'
    """

    impl = Enum
    def __init__(self, **kwargs):
        enums = kwargs.pop('enums')

        # check enums format: {'value1': 1, 'value2': 2}
        assert all([
            isinstance(key, (str, unicode)) and isinstance(value, int)
            for key, value in enums.iteritems()
        ])

        values = enums.values()
        assert len(values) == len(set(values)), "duplicated integers"

        keys =enums.keys()
        assert len(keys) == len(set(keys)), "duplicated names"

        self.enums = enums
        super(NamedIntEnum, self).__init__(*keys, **kwargs)


    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        if isinstance(value, int):
            for key in self.enums:
                if self.enums[key] == value:
                    value = key
                    break
            else:
                raise ValueError, "%r" % value

        elif isinstance(value, (str, unicode)):
            if value not in self.enums:
                raise ValueError, "%r" % value
        else:
            raise TypeError, "%r" % value

        return value


    def process_result_value(self, value, dialect):
        if value is None:
            return value

        if value not in self.enums:
            return ValueError, "%r" % value
        return value

class IntegerList(TypeDecorator):
    """
        integer list.
        stored as comma seperated int list, e.g.:
            1-3,9,11,20-30
    """

    impl=Unicode

    def __init__(self, **kwargs):
        """
            length: length of the integer list in display string format.
                    e.g.: len("1-100,103,109,200-400")
        """
        if not 'length' in kwargs:
            kwargs['length'] = 200
        super(IntegerList, self).__init__(**kwargs)

    def process_bind_param(self, value, dialect):
        """
            input:
                value: [int], '1,2,3,9-11'
            output (to db):
                display string
        """
        if value is None:
            return None
        elif isinstance(value, list):
            return self.list_to_display(value)
        elif isinstance(value, (str, unicode)):
            self.display_to_list(value) # check
            return value
        else:
            raise TypeError, "%r" % value


    def process_result_value(self, value, dialect):
        if value is None:
            return None
        else:
            return self.display_to_list(value)


    @staticmethod
    def display_to_list(disp):
        """
            display string -> [int]
                "1,2,3,9-11" -> [1,2,3,9,10,11]
        """
        if isinstance(disp, str):
            disp = disp.decode('utf-8')

        if not isinstance(disp, unicode):
            raise TypeError, '%r' % disp

        if not disp:
            return []

        disp = disp.replace(' ', '').split(',')
        lst = []
        for sp in disp:
            try:
                lst.append(int(sp))
            except ValueError as e:
                start, end = [int(p) for p in sp.split('-', 1)]
                if start > end:
                    raise ValueError, "start %r is larger than end %r" % (start, end)
                lst.extend(range(start, end+1))

        lst.sort()

        return lst


    @staticmethod
    def list_to_display(lst):
        """
            [int] -> display string
        """
        if not isinstance(lst, list):
            raise TypeError, '%r' % lst

        if not all(isinstance(i, int) for i in lst):
            raise ValueError, "%r" % lst

        if not lst:
            return ''

        lst.sort()
        display = []
        before = None
        for p in lst:
            if not before:
                display.append(unicode(p))
            elif p == before+1: # succession
                if not display[-1].endswith(u'-'):
                    display[-1] = display[-1] + u'-'
            else:
                if display[-1].endswith(u'-'):
                    display[-1] = display[-1] + unicode(before)

                display.append(unicode(p))

            before = p

        if display[-1].endswith(u'-'):
            display[-1] = display[-1] + unicode(before)

        return u','.join(display)


class KnsPorts(IntegerList):
    """
        KNS device ports.
        stored as comma seperated int list, e.g.:
            1,2,3,9,11
        as a list when used in python.
    """

    def __init__(self, **kwargs):
        kwargs['length'] = 200
        super(KnsPorts, self).__init__(**kwargs)


class StpBridgeId(TypeDecorator):
    """
        STP bridge ID.
        priority (16-bit) + MAC address (48-bit)
    """
    impl = Unicode

    def __init__(self, **kwargs):
        kwargs['length'] = 40
        super(StpBridgeId, self).__init__(**kwargs)

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = EUI(value)
            # assert len(value.words) == 8, "%r" % value
            if len(value.words) != 8:
                raise ValueError, '%r' % value
            value = unicode(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = EUI(value)  # check
            assert len(value.words) == 8, "%r" % value
            value = unicode(value)
        return value


class SnmpTruthValue(TypeDecorator):
    """
        STP TruthValue:
            1 - true
            2 - false
    """
    impl = Boolean

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        elif isinstance(value, bool):
            return value
        elif isinstance(value, int):
            if value == 1:
                return True
            elif value == 2:
                return False
            else:
                raise ValueError, '%r' % value
        else:
            raise TypeError, '%r' % value


