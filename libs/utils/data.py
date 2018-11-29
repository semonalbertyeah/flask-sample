# -*- coding:utf-8 -*-

"""
    utilities to convert data.
"""

import socket
from socket import inet_aton, inet_ntoa

def int_2_byte_array(value, width):
    """
        convert integer value to array of ubyte
        input:
            value -> integer
            width -> length of value (in bytes)
    """
    arr = []
    for i in xrange(width):
        arr.append(value & 0xff)
        value = (value >> 8)

    arr.reverse()
    return arr


def byte_array_2_int(arr):
    value = 0
    for i in arr:
        assert isinstance(i, int)
        value = (value << 8) | i

    return value


def assure_bin_data(data):
    """
        assure that "data" is available binary data.
        bin data:
            str
            [8-bit int]
        return:
            [8-bit int]
    """
    if isinstance(data, str):
        data = [ord(i) for i in data]
    assert isinstance(data, list)
    assert all([isinstance(i, int) for i in data])
    assert all([(i >= 0 and i <= 0xff) for i in data])

    return data


def ip_2_byte_array(ip):
    """
        convert an IP value into [8-bit int] format.
        ip: display string, 32-bit integer.
    """
    if isinstance(ip, (str, unicode)):
        return [ord(i) for i in inet_aton(ip)]
    else:
        assert isinstance(ip, int) and (ip >= 0 and ip <= 0xffffffff)
        return int_2_byte_array(ip, 4)

def ip_2_int(ip):
    """
        convert an IP addr to a 32-bit int
        ip: display string, 32-bit int
    """
    if isinstance(ip, int):
        assert ip >= 0 and ip <= 0xffffffff
        return ip
    else:
        assert isinstance(ip, (str, unicode))
        assert '.' in ip
        ip = inet_aton(ip)
        return byte_array_2_int([ord(i) for i in ip])


def ip_pretty(ip):
    """
        return display string format IP value.
        ip: 4-byte int, [4 8-bit int], str binary format
    """
    if isinstance(ip, int):
        assert ip >= 0 and ip <= 0xffffffff
        ip = ''.join([chr(i) for i in int_2_byte_array(ip, 4)])
    elif isinstance(ip, list):
        assert all([isinstance(i, int) for i in ip])
        assert all([(i >= 0 and i <= 0xff) for i in ip])
        ip = ''.join([chr(i) for i in ip])
    else:
        assert isinstance(ip, str) and len(ip) == 4

    return inet_ntoa(ip)

def ip_pretty2(ip):
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


def str_2_byte_array(s, length=None):
    """
        string to byte array
    """
    s_len = len(s)
    if not length:
        length = s_len

    if length > s_len:
        s = s + '\0' * (length - s_len)

    return [ord(i) for i in s[:length]]
