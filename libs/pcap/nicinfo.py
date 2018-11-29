# -*- coding:utf-8 -*-

from netaddr import EUI
from socket import AF_INET, AF_INET6

from .libpcap import all_nics


class NoSuchNic(Exception):
    """
        no such nic
    """
    pass

class NicInfo(object):
    """
        net ineterface information.
    """
    def __init__(self, name=None, info=None):
        if name:
            all_nics_info = all_nics()
            nic = filter(lambda i: i['name'] == name, all_nics_info)
            if not nic:
                raise NoSuchNic, 'no such NIC %r' % name
            nic = nic[0]

            self.name = name
            self.mac = EUI(nic['mac'])
            self.desc = nic['description']

            #########################################################
            # format of addresses:
            #   {
            #       'sa_family': refer to socket, such as AF_INET
            #       'addr': IP address
            #       'netmask': netmask if AF_INET or AF_INET6
            #   }
            #########################################################
            self.addrs = nic['addresses']
            self.loopback = nic['loopback']
            self.running = nic['running']
            self.up = nic['up']
        else:
            # build an instance directly by setting properties.
            self.name = info['name']
            self.mac = EUI(info['mac'])
            self.desc = info['description']
            self.addrs = info['addresses']
            self.loopback = info['loopback']
            self.running = info['running']
            self.up = info['up']

    def reload(self):
        """
            reload NIC info
        """
        all_nics_info = all_nics()
        nic = filter(lambda i: i['name'] == self.name, all_nics_info)
        if not nic:
            raise NoSuchNic, 'no such NIC %r' % self.name
        nic = nic[0]

        self.mac = EUI(nic['mac'])
        self.desc = nic['description']

        #########################################################
        # format of addresses:
        #   {
        #       'sa_family': refer to socket, such as AF_INET
        #       'addr': IP address
        #       'netmask': netmask if AF_INET or AF_INET6
        #   }
        #########################################################
        self.addrs = nic['addresses']
        self.loopback = nic['loopback']
        self.running = nic['running']
        self.up = nic['up']



    def __str__(self):
        return '<NicInfo name=%s>' % self.name

    def __repr__(self):
        return self.__str__()


    @property
    def ipv4(self):
        """
            first IPv4 address
        """
        for addr in self.addrs:
            if addr['sa_family'] == AF_INET:
                return addr['addr'], addr['netmask']

        return None

    @property
    def ipv4s(self):
        addrs = []
        for addr in self.addrs:
            if addr['sa_family'] == AF_INET:
                addrs.append((addr['addr'], addr['netmask']))

        return addrs


    @property
    def ipv6(self):
        """
            first IPv6 address
        """
        for addr in self.addrs:
            if addr['sa_family'] == AF_INET6:
                return addr['addr'], addr['netmask']

        return None

    @property
    def ipv6s(self):
        """
            all IPv6 addresses
        """
        addrs = []
        for addr in self.addrs:
            if addr['sa_family'] == AF_INET6:
                addrs.append((addr['addr'], addr['netmask']))

        return addrs


    def to_dict(self, reload=False):
        if reload:
            self.reload()
        return {
            'name': self.name,
            'mac': str(self.mac),
            'desc': self.desc,
            'ipv4s': self.ipv4s,
            'ipv6s': self.ipv6s,
            'addrs': self.addrs,
            'loopback': self.loopback,
            "running": self.running,
            "up": self.up
        }

    def __eq__(self, another):
        return self.name == another.name and \
               self.mac == another.mac and \
               self.desc == another.desc and \
               self.addrs == another.addrs and \
               self.loopback == another.loopback and \
               self.running == another.running and \
               self.up == another.up


    def __ne__(self, another):
        return not self.__eq__(another)

    @staticmethod
    def all_nicinfo():
        all_nics_info = all_nics()
        return [NicInfo(info=i) for i in all_nics_info if i['up']]
