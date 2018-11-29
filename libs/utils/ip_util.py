# -*- coding:utf-8 -*-

import struct
import socket

from .data import ip_2_int, ip_2_byte_array

def same_net(ip1, ip2, netmask):
    '''
        check if these two IP in the same subnet.
        input:
            ip1, ip2 : display string. e.g.: '192.168.2.33' or int
            netmask : display string. e.g.: '255.255.255.0' or int
    '''
    ip1 = ip_2_int(ip1)
    ip2 = ip_2_int(ip2)
    netmask = ip_2_int(netmask)

    return ip1 & netmask == ip2 & netmask


def ip2int(addr):
   return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
   return socket.inet_ntoa(struct.pack("!I", addr)).decode('utf-8')


def valid_netmask(netmask):
    netmask = ip_2_int(netmask)

    # netmask < '128.0.0.0' or netmask > 255.255.255.254
    if (netmask < 0x80000000) or (netmask > 0xfffffffe):
        return False

    i = 0
    start = False
    while (i < 32):
        if start:
            if (1 << i) & netmask == 0:
                return False
        else:
            if (1 << i) & netmask != 0:
                start = True

        i += 1;

    return True

