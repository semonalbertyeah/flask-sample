# -*- coding:utf-8 -*-

"""
    KNMP API:
    Manager -> Topology -> KNMP (interface)
    There may be multiple Topology managed by a Manager.
    There may be multiple KNMP interface bound to a Topology.
"""

import time, warnings, random, copy
from netaddr import EUI
from socket import AF_INET, AF_INET6
import threading

from utils.data import *
from utils.thread_util import *
from utils.time_util import wait
from pcap import Pcap
from pcap.nicinfo import NicInfo
from snap import SnapErrInvalid


from .frame import *


class KNMPError(Exception):
    pass

class KNMPTopoOutdate(KNMPError):
    """
        KNMP topology is outdated.
    """
    pass



# class NoSuchNic(Exception):
#     """
#         no such nic
#     """
#     pass

# class NicInfo(object):
#     """
#         net ineterface information.
#     """
#     def __init__(self, name=None, info=None):
#         if name:
#             all_nics = Pcap.all_devs()
#             nic = filter(lambda i: i['name'] == name, all_nics)
#             if not nic:
#                 raise NoSuchNic, 'no such NIC %r' % name
#             nic = nic[0]

#             self.name = name
#             self.mac = EUI(nic['mac'])
#             self.desc = nic['description']

#             #########################################################
#             # format of addresses:
#             #   {
#             #       'sa_family': refer to socket, such as AF_INET
#             #       'addr': IP address
#             #       'netmask': netmask if AF_INET or AF_INET6
#             #   }
#             #########################################################
#             self.addrs = nic['addresses']
#             self.loopback = nic['loopback']
#             self.running = nic['running']
#             self.up = nic['up']
#         else:
#             # build an instance directly by setting properties.
#             self.name = info['name']
#             self.mac = EUI(info['mac'])
#             self.desc = info['description']
#             self.addrs = info['addresses']
#             self.loopback = info['loopback']
#             self.running = info['running']
#             self.up = info['up']

#     def reload(self):
#         """
#             reload NIC info
#         """
#         all_nics = Pcap.all_devs()
#         nic = filter(lambda i: i['name'] == self.name, all_nics)
#         if not nic:
#             raise NoSuchNic, 'no such NIC %r' % self.name
#         nic = nic[0]

#         self.mac = EUI(nic['mac'])
#         self.desc = nic['description']

#         #########################################################
#         # format of addresses:
#         #   {
#         #       'sa_family': refer to socket, such as AF_INET
#         #       'addr': IP address
#         #       'netmask': netmask if AF_INET or AF_INET6
#         #   }
#         #########################################################
#         self.addrs = nic['addresses']
#         self.loopback = nic['loopback']
#         self.running = nic['running']
#         self.up = nic['up']



#     def __str__(self):
#         return '<NicInfo name=%s>' % self.name

#     def __repr__(self):
#         return self.__str__()


#     @property
#     def ipv4(self):
#         """
#             first IPv4 address
#         """
#         for addr in self.addrs:
#             if addr['sa_family'] == AF_INET:
#                 return addr['addr'], addr['netmask']

#         return None

#     @property
#     def ipv4s(self):
#         addrs = []
#         for addr in self.addrs:
#             if addr['sa_family'] == AF_INET:
#                 addrs.append((addr['addr'], addr['netmask']))

#         return addrs


#     @property
#     def ipv6(self):
#         """
#             first IPv6 address
#         """
#         for addr in self.addrs:
#             if addr['sa_family'] == AF_INET6:
#                 return addr['addr'], addr['netmask']

#         return None

#     @property
#     def ipv6s(self):
#         """
#             all IPv6 addresses
#         """
#         addrs = []
#         for addr in self.addrs:
#             if addr['sa_family'] == AF_INET6:
#                 addrs.append((addr['addr'], addr['netmask']))

#         return addrs


#     def to_dict(self, reload=False):
#         if reload:
#             self.reload()
#         return {
#             'name': self.name,
#             'mac': str(self.mac),
#             'desc': self.desc,
#             'ipv4s': self.ipv4s,
#             'ipv6s': self.ipv6s,
#             'addrs': self.addrs,
#             'loopback': self.loopback,
#             "running": self.running,
#             "up": self.up
#         }

#     def __eq__(self, another):
#         return self.name == another.name and \
#                self.mac == another.mac and \
#                self.desc == another.desc and \
#                self.addrs == another.addrs and \
#                self.loopback == another.loopback and \
#                self.running == another.running and \
#                self.up == another.up


#     def __ne__(self, another):
#         return not self.__eq__(another)




class DeviceInfo(object):
    """
        scanned device info.
    """
    def __init__(self, **info):
        """
            info:
                flag: 8-bit int
                ip: display string, or int
                netmask: display string, or int
                gateway: display string, or int
                vlan: int, >=1 and <= 4095
                device_name: display string, len <= 15
                product_name: display string, len <= 15
                from_nic: NicInfo
        """
        self._mac = EUI(info['mac'])
        self.set_flag(info['flag'])
        self.set_ip(info['ip'])
        self.set_netmask(info['netmask'])
        self.set_gateway(info['gateway'])
        self.set_vlan(info['vlan'])
        self.set_device_name(info['device_name'])
        self.set_product_name(info['product_name'])
        self.set_from_nic(info.get('from_nic', None))

    def __str__(self):
        return '<DeviceInfo: device_name=%s, mac=%s>' % (self._device_name, self._mac)

    def __repr__(self):
        return self.__str__()

    @property
    def info(self):
        return {
            "mac": str(self.mac),
            "flag": self.flag,
            "ip": self.ip,
            "netmask": self.netmask,
            "gateway": self.gateway,
            "vlan": self.vlan,
            "device_name": self.device_name,
            "product_name": self.product_name,
            "from_nic": self.from_nic.to_dict()
        }
    

    #####################
    # MAC
    #####################
    @property
    def mac(self):
        return self._mac

    #####################
    # flag
    #####################
    @property
    def flag(self):
        return self._flag

    def set_flag(self, flag):
        assert isinstance(flag, int) and \
               flag >= 0 and flag <= 0xff
        self._flag = flag

    @flag.setter
    def flag(self, value):
        self.set_flag(value)

    #####################
    # dhcp
    #####################
    @property
    def dhcp(self):
        return bool(self.flag & 0x01)

    def set_dhcp(self, dhcp):
        if dhcp:
            self.flag |= 0x01
        else:
            self.flag &= 0xfe

    @dhcp.setter
    def dhcp(self, value):
        self.set_dhcp(value)

    #####################
    # ip
    #####################
    @property
    def ip(self):
        return ip_pretty(self._ip)

    def set_ip(self, ip):
        """
            ip: display string, 32-bit int
        """
        self._ip = ip_2_int(ip)

    @ip.setter
    def ip(self, value):
        self.set_ip(value)


    #####################
    # netmask
    #####################
    @property
    def netmask(self):
        return ip_pretty(self._netmask)

    def set_netmask(self, netmask):
        self._netmask = ip_2_int(netmask)

    @netmask.setter
    def netmask(self, value):
        self.set_netmask(value)


    #####################
    # gateway
    #####################
    @property
    def gateway(self):
        return ip_pretty(self._gateway)

    def set_gateway(self, gateway):
        self._gateway = ip_2_int(gateway)

    @gateway.setter
    def gateway(self, value):
        self.set_gateway(value)


    #####################
    # vlan
    #####################
    @property
    def vlan(self):
        return self._vlan

    def set_vlan(self, vlan):
        assert isinstance(vlan, int) and \
               vlan >= 1 and vlan <= 4095
        self._vlan = vlan

    @vlan.setter
    def vlan(self, value):
        self.set_vlan(value)


    #####################
    # device_name
    #####################
    @property
    def device_name(self):
        return self._device_name.rstrip('\0')

    def set_device_name(self, device_name):
        if isinstance(device_name, unicode):
            device_name = device_name.encode('utf-8')
        assert isinstance(device_name, (str,unicode)) and \
               len(device_name) <= 15
        self._device_name = str(device_name)

    @device_name.setter
    def device_name(self, value):
        self.set_device_name(value)


    #####################
    # product_name
    #####################
    @property
    def product_name(self):
        return self._product_name

    def set_product_name(self, product_name):
        if isinstance(product_name, unicode):
            product_name = product_name.encode('utf-8')
        assert isinstance(product_name, (str, unicode))

        self._product_name = str(product_name)

    @product_name.setter
    def product_name(self, value):
        self.set_product_name(value)

    #####################
    # from_nic
    #####################
    @property
    def from_nic(self):
        return self._from_nic

    def set_from_nic(self, value):
        if not (isinstance(value, NicInfo) or value is None):
            value = NicInfo(name=value)
        self._from_nic = value

    @from_nic.setter
    def from_nic(self, value):
        self.set_from_nic(value)


    def __eq__(self, another):
        return self._mac == another._mac and \
               self._flag == another._flag and \
               self._ip == another._ip and \
               self._netmask == another._netmask and \
               self._gateway == another._gateway and \
               self._vlan == another._vlan and \
               self._device_name == another._device_name and \
               self._product_name == another._product_name
               # and self._from_nic == another._from_nic

    def __ne__(self, another):
        return not self.__eq__(another)

    def __hash__(self):
        return hash((
            self._mac, 
            self._flag, 
            self._ip, 
            self._netmask, 
            self._gateway,
            self._vlan,
            self._device_name,
            self._product_name,
            # self._from_nic
        ))

    @property
    def config_items(self):
        """
            return CmdConfig items to config device.
        """
        return [
            CmdConfig(
                cmd='IP Setup %s %s %s %d' % (self.ip, self.netmask, self.gateway, self.vlan)
            ),
            CmdConfig(
                cmd='System Name %s' % self.device_name
            )
        ]


class KNMPBase(object):
    # execution status: same as ConfigAckFrame
    EXEC_STAT_TIMEOUT = None
    EXEC_STAT_SUCCESS = ConfigAckFrame.CFG_STAT_SUCCESS
    EXEC_STAT_FAILURE = ConfigAckFrame.CFG_STAT_FAILURE

    DEFAULT_AGING = 3 * 60    # default aging: 3 minutes

    #########################
    # various id generator
    #########################
    @staticmethod
    def generate_mgmt_id():
        """
            generate a management ID
        """

        return int(time.time() * 1000) & 0xffffffff


    @staticmethod
    def get_topo_id_gen():
        """
            generate a topology ID domain (iterator)
        """
        domain = xrange(1, 65536)
        id_iter = iter(domain)
        while 1:
            try:
                yield id_iter.next()
            except StopIteration:
                id_iter = iter(domain)
                yield id_iter.next()


    @staticmethod
    def get_req_id_gen():
        """
            generate a request ID domain (iterator)
        """
        domain = random.sample(xrange(1, 65536), 65535)
        id_iter = iter(domain)
        while 1:
            try:
                yield id_iter.next()
            except StopIteration:
                id_iter = iter(domain)
                yield id_iter.next()

    @staticmethod
    def all_netifs():
        # all_nics = Pcap.all_devs()
        # all_nics = [NicInfo(info=i) for i in all_nics if i['up']]
        # return all_nics
        return NicInfo.all_nicinfo()



class Topology(KNMPBase):
    """
        KNMP topology information.
        identified by:
            NIC mac,
            mgmt_id,
            topo_id
    """
    def __init__(self, nic, aging=None):

        if not isinstance(nic, NicInfo):
            nic = NicInfo(name=nic)

        self.nic = nic

        ########################
        # topology state
        ########################

        # aging time
        self._aging = aging or self.DEFAULT_AGING

        # topology deadline from aging time
        self._deadline = 0   # initially, make it outdate

        ################
        # ID domains
        ################
        self._topo_id_iter = self.get_topo_id_gen()
        self._req_id_iter = self.get_req_id_gen()

        ######################################
        # all devices in current topology
        ######################################
        self._devices = []

    def __repr__(self):
        return "<Topology nic=%s>" % self.nic.name

    def __str__(self):
        return self.__repr__()


    def set_aging(self, aging):
        assert isinstance(aging, (int, float))
        self._aging = aging


    #################
    # ID generators
    #################
    @property
    def topo_id(self):
        return getattr(self, '_topo_id', None)

    @mthread_safe(lock_name='topo_id_gen_lock')
    def next_topo_id(self):
        self._topo_id = self._topo_id_iter.next()
        return self._topo_id

    @mthread_safe(lock_name='req_id_gen_lock')
    def next_req_id(self):
        """
            get a new request ID.
        """
        return self._req_id_iter.next()

    @property
    def deadline(self):
        return self._deadline

    def update_deadline(self):
        self._deadline = time.time() + self._aging
        return self._deadline

    @property
    def outdated(self):
        return time.time() > self._deadline


    @property
    def devices(self):
        return copy.copy(self._devices)

    def set_devices(self, devices):
        assert isinstance(devices, list)
        assert all([isinstance(d, DeviceInfo) for d in devices])
        self._devices = devices

    def get_devices_by_mac(self, macs):
        """
            get devices by MAC addresses
            input:
                macs -> EUI mac or [EUI mac]

            return:
                [DeviceInfo()]
        """
        if not isinstance(macs, (tuple, list, set)):
            macs = [macs]

        macs = set(EUI(str(mac)) for mac in macs)

        devs_by_mac = {dev.mac: dev for dev in self._devices}

        devs = []
        for mac in macs:
            if mac in devs_by_mac:
                devs.append(devs_by_mac[mac])

        return devs




    def update_devices(self, devs):
        """
            update cached devices' information.
            input:
                devs -> [DeviceInfo]
        """
        if not isinstance(devs, (list, tuple, set)):
            devs = [devs]

        assert all(isinstance(dev, DeviceInfo) for dev in devs), \
                "input must be DeviceInfo or [DeviceInfo], wrong value: %r" % devs

        cached_dev_maps = {str(dev.mac): dev for dev in self._devices}
        for dev in devs:
            if str(dev.mac) in cached_dev_maps:
                self._devices.remove(cached_dev_maps[str(dev.mac)])
            self._devices.append(dev)



    def find_devices(self, **fields):
        """
            find devices according to fields value:
            input:
                fields:
                    {
                        "mac": str or EUI
                        "flag"
                        "ip"
                        "netmask"
                        "gateway"
                        "vlan"
                        "device_name"
                        "product_name"
                    }
        """
        result = []
        for dev in self._devices:
            for key, val in fields.iteritems():
                if getattr(dev, key, None) != fields[key]:
                    break
            else:
                result.append(dev)

        return result



class KNMP(KNMPBase):
    """
        KNMP interface.
        bound to a netiface.
        Usage:
            ##################
            # 1. normal usage
            ##################
            kif = KNMP('eth0')
            dev0 = kif.scan()[0]
            kif.execute('Ip setup xxxxx', dev0)

            ###############################################
            # 2. multiple interfaces
            #   typically, one thread, one KNMP interface.
            ###############################################
            topo = topology('eth0')
            kif_e01 = KNMP(topology=topo)
            kif_e02 = KNMP(topology=topo)

            # maintain topology
            exit_tag = 0
            def main_tain_topo(kif, period=60*5):
                deadline = 0
                while not exit_tag:
                    if time.time() >= deadline:
                        kif.scan()
                        deadline = time.time() + period

            t = make_thread(main_tain_topo, args=(kif_e01,))
            t.start()

            # kif_e02 can directly use devices scanned by kif_e01
            dev = kif_e02.devices[0]
            kif_e02.execute('asdfasdf', dev)
    """

    def __init__(self, nic=None, mgmt_id=None, topology=None, auto_refresh=False):
        """
            manager: Manager
            topo_aging: age of KNMP topology (for now: it's fixed to 5 minutes.)
            auto_refresh: if True, topology will be updated when outdated.
        """
        if topology:
            assert isinstance(topology, Topology)
            self._topology = topology
        else:
            assert nic, "an Nic or Topology is needed."
            if not isinstance(nic, NicInfo):
                nic = NicInfo(name=nic)

            self._topology = Topology(nic)

        # self._pcap = Pcap(self._topology.nic.name, prosmic=False, filter_exp='ether dst %s' % self._topology.nic.mac)
        self._pcap = Pcap(
            self._topology.nic.name, 
            prosmic=False, 
            snaplen=100,     # only need to be larger than the size of ConfigAckFrame and ScanAckFrame
            direction='in',
            filter_exp='llc'    # custom protocol use SNAP (LLC)
        )

        self._mgmt_id = mgmt_id or self.generate_mgmt_id()

        self._auto_refresh = auto_refresh



    ######################
    # shortcut properties
    ######################

    def _set_topology(self, topo):
        self._topology = topo

    @property
    def topology(self):
        return self._topology

    @property
    def devices(self):
        return self._topology.devices

    @property
    def mgmt_id(self):
        return self._mgmt_id

    @property
    def nic(self):
        return self._topology.nic



    ##############
    # APIs
    ##############
    def find_devices(self, **fields):
        """
            usage:
                KNMP = 
        """
        return self.topology.find_devices(**fields)



    ######################
    # operations
    ######################

    def _req_scan(self, macs=None, timeout=5, callback=None):
        """
            scan (specific) devices

            input:
                macs -> 
                    if specified, only scan specific devices
                    else wait until timeout
                timeout -> waiting timeout
                callback -> called upon every acking frame

            return:
                [DeviceInfo()]
        """
        from_nic = self.nic

        if macs is not None:
            if not isinstance(macs, (list, tuple, set)):
                macs = [macs]
            macs = set(
                EUI(str(mac)) for mac in macs
            )

        results = []

        # recv_macs = []
        def cb(frame):
            try:
                frame = ScanAckFrame(raw=frame[:])
                if frame.mgmt_id != self.mgmt_id:
                    warnings.warn("Scan ACK frame: not the management ID of curent manager")
                    return

                if macs is not None and  frame.src_mac not in macs:
                    return

                # recv_macs.append(frame.src_mac)
                dev = DeviceInfo(
                    mac=frame.src_mac,
                    flag=frame.flag,
                    ip=frame.ip,
                    netmask=frame.netmask,
                    gateway=frame.gateway,
                    vlan=frame.vlan,
                    device_name=frame.device_name,
                    product_name=frame.product_name,
                    from_nic=from_nic
                )
                results.append(dev)

                if macs is not None:
                    macs.remove(dev.mac)

                if callback:
                    callback(dev)
            except (InvalidScanAckFrame, KNMPFrameErrInvalid, SnapErrInvalid) as e:
                # warnings.warn(str(e))
                pass

        self._pcap.clear_recv_buffer()
        self._pcap.poll(callback=cb, thread=True, count=-1)

        topo_id = self.topology.next_topo_id()
        self._pcap.send(
            ScanFrame(
                src_mac=self.nic.mac, 
                mgmt_id=self.mgmt_id, 
                topo_id=topo_id
            )[:]
        )

        try:
            wait(
                timeout, 
                break_cond=lambda: macs is not None and len(macs) == 0
            )
        finally:
            self._pcap.break_poll()

        return results


    def _req_exec(self, mappings, timeout=10, callback=None):
        """
            send exec request to target devies
            input:
                mappings -> device_mac : commands
                    {
                        mac1: [cmd1, cmd2, ...], 
                        mac2: [cmd1, cmd2, ...], 
                        ...
                    }
                    mac: DeviceInfo or EUI mac
                timeout -> wait timeout
                callback -> called upon each exe_ack
                    callback(mac, status)
        """
        mappings = dict(mappings)

        _mappings = {}
        for mac, cmds in copy.copy(mappings).iteritems():

            if isinstance(mac, DeviceInfo):
                mac = mac.mac
            else:
                mac = EUI(str(mac))

            if not isinstance(cmds, (list, tuple, set)):
                cmds = [cmds]

            cmd_items = []
            for cmd in cmds:
                if isinstance(cmd, CmdConfig):
                    cmd_items.append(cmd)
                else:
                    cmd_items.append(CmdConfig(cmd))

            _mappings[mac] = cmd_items


        ########################
        # generate request IDs
        ########################
        result = {}
        for mac, cmds in _mappings.iteritems():
            req_id = self.topology.next_req_id()
            result[req_id] = {'mac': mac, 'commands': cmds, 'status': self.EXEC_STAT_TIMEOUT}


        ##########################
        # receive response
        ##########################
        acked_reqs = set() # acknowledged request (req_id)
        def cb(frame):
            try:
                frame = ConfigAckFrame(raw=frame[:])

                if frame.mgmt_id != self.mgmt_id:
                    warnings.warn("Config ACK Frame, not the management ID of current manager.")
                    return

                if frame.req_id not in result:
                    warnings.warn('Config ACK Frame, req_id %d not in the sent ones.' % frame.req_id)
                    return

                acked_reqs.add(frame.req_id)
                result[frame.req_id]['status'] = frame.status
                if callback:
                    callback(result[frame.req_id]['mac'], result[frame.req_id]['status'])
            except (InvalidConfigAckFrame, KNMPFrameErrInvalid, SnapErrInvalid) as e:
                # warnings.warn(str(e))
                pass


        self._pcap.clear_recv_buffer()
        self._pcap.poll(callback=cb, thread=True, count=-1)


        ################
        # send requests
        ################
        for req_id, req_info in result.iteritems():
            self._pcap.send(
                ConfigFrame(
                    dest_mac=req_info['mac'],
                    src_mac=self.nic.mac,
                    mgmt_id=self.mgmt_id,
                    req_id=req_id,
                    items=req_info['commands']
                )[:]
            )

        try:
            req_num = len(result)
            wait(
                timeout, 
                break_cond=lambda: len(acked_reqs) >= req_num
            )

        finally:
            self._pcap.break_poll()

        return {i['mac']: i['status'] for i in result.itervalues()}


    def scan(self, timeout=5, callback=None):
        devices = self._req_scan(timeout=timeout, callback=callback)

        self.topology.update_deadline()
        self.topology.set_devices(devices)

        return devices


    def update_device_info(self, devs, timeout=5, callback=None):
        """
            update specific devices' information.
            input:
                devs -> [DeviceInfo|mac]
                timeout
                callback: function(DeviceInfo()) {}
            output:
                [DeviceInfo] -> updated device's info
                If some devices not returned,
                that means they didn't return an response before timeout.
        """

        if not isinstance(devs, (list, tuple, set)):
            devs = [devs]

        target_macs = [
            dev.mac if isinstance(dev, DeviceInfo) else EUI(str(dev))
            for dev in devs
        ]

        devices = self._req_scan(macs=target_macs, timeout=timeout, callback=callback)

        self.topology.update_devices(devices)

        return devices


    def assure_topology(method):
        """
            make sure topology is available.
        """
        def new_method(self, *args, **kwargs):

            if self.topology.outdated:
                if self._auto_refresh:
                    warnings.warn("topology outdated, re-scan...")
                    self.scan()
                else:
                    raise KNMPTopoOutdate, "topology %r outdated." % self.topology
            return method(self, *args, **kwargs)

        return new_method


    @assure_topology
    def execute_each(self, mappings, timeout=10, callback=None):
        """
            execute commands seperatedly for different devices.
            input:
                mappings -> [(dev, [cmd1, cmd2] or cmd), ...]
                callback -> function(device, status)
            output:
                {
                    dev1: status,
                    dev2: status,
                    ...
                }
                status -> refer to ConfigAckFrame
        """
        mappings = dict(mappings)

        """
            devices must be cached
        """
        for dev in mappings.iterkeys():
            assert isinstance(dev, DeviceInfo), "%r is not an instance of DeviceInfo" % dev
            assert dev in self.topology.devices, 'device %r not cached' % dev

        devs_by_mac = {dev.mac: dev for dev in self._topology.devices}

        def cb(mac, status):
            dev = devs_by_mac[mac]
            if callback:
                callback(dev, status)

        results = self._req_exec(mappings, timeout, cb)
        return {
            devs_by_mac[mac]: status 
            for mac, status in results.iteritems()
        }


    def safe_execute_each(self, mappings, timeout=10, callback=None):
        mappings = dict(mappings)

        mappings = {
                    dev.mac if isinstance(dev, DeviceInfo) else EUI(str(dev)) : cmds 
                    for dev, cmds in mappings.iteritems()
                }
        dev_macs = set(mappings.keys())

        # timeout means not reachable through KNMP
        results = {mac: KNMPBase.EXEC_STAT_TIMEOUT for mac in dev_macs}

        if self.topology.outdated:
            devs = self.update_device_info(dev_macs, 5)
        else:
            devs = filter(lambda dev: dev.mac in dev_macs, self.topology.devices)
            cached_macs = set(dev.mac for dev in devs)
            non_cached_macs = dev_macs - cached_macs

            if len(non_cached_macs) > 0:
                devs += self.update_device_info(non_cached_macs)

        # mappings for KNMP-reachable devices
        _mappings = {dev: mappings[dev.mac] for dev in devs}

        _results = self._req_exec(_mappings, timeout, callback)

        for mac, result in _results.iteritems():
            results[str(mac)] = result

        return {
            mac: result
            for mac, result in results.iteritems()
        }



    @assure_topology
    def execute(self, cmds, devs=None, timeout=10, callback=None):
        devs = devs or self.topology.devices
        if not isinstance(devs, list):
            devs = [devs]

        mappings = {}
        for dev in devs:
            assert isinstance(dev, DeviceInfo), "%r is not an instance of DeviceInfo" % dev
            assert dev in self.topology.devices, 'device %r not cached' % dev
            mappings[dev.mac] = cmds

        devs_by_mac = {dev.mac: dev for dev in self._topology.devices}
        def cb(mac, status):
            dev = devs_by_mac[mac]
            if callback:
                callback(dev, status)

        results = self._req_exec(mappings, timeout, cb)
        return {
            devs_by_mac[mac]: status 
            for mac, status in results.iteritems()
        }


    def safe_execute(self, cmds, devs, timeout=10, callback=None):
        if not isinstance(devs, (list, set, tuple)):
            devs = [devs]
            
        dev_macs = set(
            dev.mac if isinstance(dev, DeviceInfo) else EUI(str(dev))
            for dev in devs
        )

        results = {mac: KNMPBase.EXEC_STAT_TIMEOUT for mac in dev_macs}

        if self.topology.outdated:
            devs = self.update_device_info(dev_macs, 5)
        else:
            devs = filter(lambda dev: dev.mac in dev_macs, self.topology.devices)
            cached_macs = set(dev.mac for dev in devs)
            non_cached_macs = dev_macs - cached_macs

            if len(non_cached_macs) > 0:
                devs += self.update_device_info(non_cached_macs)

        mappings = {
            dev.mac: cmds
            for dev in devs
        }
        # _results = self._execute(cmds, devs, timeout, callback)
        _results = self._req_exec(mappings, timeout, callback)

        for mac, result in _results.iteritems():
            results[mac] = result

        return {
            mac: result
            for mac, result in results.iteritems()
        }


    del assure_topology




# class Manager(KNMPBase):
#     """
#         KNMP manager
#         used to manage multiple KNMP topologies.
#     """

#     def __init__(self):
#         self._mgmt_id = self.generate_mgmt_id()     # management id (represent current manager)

#         #########################################################
#         # topologies (a topology is associated with an NIC)
#         #   {'eth0': Topology()}
#         #########################################################
#         self.topos = {}

#     @property
#     def mgmt_id(self):
#         return self._mgmt_id

#     def add_interface(self, kif, topo_aging=None):
#         """
#             add a KNMP interface to current manager.
#         """
#         if getattr(kif, 'manager', None):
#             warnings.warn("%r is already attached to a manager." % kif)

#         topo = self.topos.setdefault(
#             kif._nic.name, 
#             Topology(kif._nic.name, aging=topo_aging)
#         )
#         topo.add_interface(kif)

#         if topo_aging:
#             # change topo_aging to the newly added interface's aging
#             # improvements: aging = min(topo.aging, topo_aging)
#             topo.set_aging(topo_aging)

#         kif._manager = self

#     def del_interface(self, kif):
#         if kif._nic.name in self.topos:
#             topo = self.topos[kif._nic.name]
#             topo.del_interface(kif)


class ScopedManager(KNMPBase):
    """
        Manage KNMP interfaces in multi-thread environment.
    """

    @staticmethod
    def norm_nic(nic):
        """
            make sure return an NicInfo instance
            input:
                nic -> NicInfo instance or name of a NIC
        """
        if not isinstance(nic, NicInfo):
            nic = NicInfo(name=nic)

        return nic


    def __init__(self, nics=None, auto_refresh=False):
        """
            input:
                nics -> [name(str) or NicInfo]
                auto_refresh -> bool
        """
        if nics is None:
            nics = self.all_netifs()
        else:
            if not isinstance(nics, (list, tuple)):
                nics = [nics]
            nics = [self.norm_nic(nic) for nic in nics]

        self._auto_refresh = auto_refresh
        self._mgmt_id = self.generate_mgmt_id()

        # _topos:
        #     {
        #         'nic_name1': Topology('nic_name1'),
        #         'nic_name2': Topology('nic_name2'),
        #         ...
        #     }
        self._topos = {nic.name: Topology(nic) for nic in nics}


        # _kifs_local.kifs (thread local)
        # {
        #     'nic_name1': kif1,
        #     'nic_name2': kif2,
        #     ...
        # }
        self._kifs_local = threading.local()

    @property
    @mthread_safe(lock_name='topos_lck')
    def topos(self):
        """
            used to lock read of _topos
        """
        return copy.copy(self._topos)


    @property
    def nics(self):
        return [topo.nic for topo in self.topos.itervalues()]

    @mthread_safe(lock_name='topos_lck')
    def add_nics(self, nics):
        if not isinstance(nics, (list, tuple, set)):
            nics = [nics]
        nics = [self.norm_nic(nic) for nic in nics]

        for nic in nics:
            if nic.name not in self._topos:
                self._topos[nic.name] = Topology(nic)

    @mthread_safe(lock_name='topos_lck')
    def remove_nics(self, nics):
        if not isinstance(nics, (list, tuple, set)):
            nics = [nics]
        nics = [self.norm_nic(nic) for nic in nics]

        for nic in nics:
            if nic.name in self._topos:
                del self._topos[nic.name]

    @property
    def kifs(self):
        """
            get a set of KIFs corresponding current topologies,
            and local to current thread.
        """
        topos = self.topos

        if not hasattr(self._kifs_local, 'kifs'):
            self._kifs_local.kifs = {
                topo.nic.name: KNMP(
                                    mgmt_id=self._mgmt_id,
                                    topology=topo,
                                    auto_refresh=self._auto_refresh
                                )
                for topo in topos.itervalues()
            }
        else:
            ###########################################################
            # sync, in case there is some change(add/remove) in monitored NICs
            ###########################################################

            kif_nic_names = set(self._kifs_local.kifs.iterkeys())
            topo_nic_names = set(topos.iterkeys())

            for nic_name in (kif_nic_names - topo_nic_names):
                # removed NICs
                del self._kifs_local.kifs[nic_name]

            for nic_name in topo_nic_names:
                topo = topos[nic_name]
                if nic_name in self._kifs_local.kifs:
                    if self._kifs_local.kifs[nic_name].topology is not topo:
                        # may happen when calling:
                        #   "manager.remove_nics(nic1); manager.add_nics(nic1);"
                        self._kifs_local.kifs[nic_name]._set_topology(topo)
                else:
                    # new NICs
                    self._kifs_local.kifs[nic_name] = KNMP(
                        mgmt_id=self._mgmt_id,
                        topology=topo,
                        auto_refresh=self._auto_refresh
                    )

        return self._kifs_local.kifs


    def reload_nics(self):
        """
            reload all NICs' information
        """
        for topo in self.topos.itervalues():
            topo.nic.reload()


    #######################
    # devices API
    #######################

    @property
    def devices(self):
        """
            all cached devices cached in manager.
        """
        return self.get_devices()


    def get_devices(self, nics=None):
        """
            get devices scanned from one or all NICs.
        """
        topos = self.topos
        if nics is None:
            nics = self.nics
        else:
            if not isinstance(nics, (list, tuple)):
                nics = [nics]
            nics = [self.norm_nic(nic) for nic in nics]

        from_nic_names = [nic.name for nic in nics]

        devs = []
        for nic_name in from_nic_names:
            devs.extend(topos[nic_name].devices)

        return devs

    def get_alive_devices(self):
        """
            get devices in which topology is not outdated
        """
        topos = self.topos
        devs = []
        for nic_name, topo in topos.iteritems():
            if not topo.outdated:
                devs.extend(topo.devices)

        return devs

    def get_alive_devices_by_mac(self, macs):
        if not isinstance(macs, (tuple, list, set)):
            macs = [macs]

        topos = self.topos
        devs = []
        for nic_name, topo in topos.iteritems():
            if not topo.outdated:
                devs.extend(topo.get_devices_by_mac(macs))

        return devs


    def find_devices(self, **fields):
        """
            find devices according to fields value:
            input:
                fields:
                    {
                        "mac": str or EUI
                        "flag"
                        "ip"
                        "netmask"
                        "gateway"
                        "vlan"
                        "device_name"
                        "product_name"
                        "from_nic": instance of NicInfo or nic_name
                    }
        """
        topos = self.topos
        from_nic = fields.pop('from_nic', None)
        if from_nic is not None:
            from_nic = self.norm_nic(from_nic)
            return topos[from_nic.name].find_devices(**fields)
        else:
            devs = []
            for topo in topos.itervalues():
                devs.extend(topo.find_devices(**fields))
            return devs

    #########################
    # KNMP operations
    #########################

    def scan(self, nics=None, timeout=5, callback=None):
        nics = nics or self.nics
        kifs = self.kifs

        tasks = []
        tname_base = 'scan_%s' % time.strftime('%x-%X') # for debug
        i = 0   # for debug
        for nic in nics:
            tasks.append(make_thread(
                kifs[nic.name].scan, 
                name="%s::%d" % (tname_base, i), # for debug
                kwargs={'timeout': timeout, 'callback': callback},
                daemon=True,
                start=True
            ))
            i += 1  # for debug
        assert wait_threads(tasks, timeout=timeout+2), \
                "some scanning tasks still running, which is not expected. running tasks: %r" % [t for t in tasks if t.is_alive()]

        devices = []
        for nic in nics:
            devices.extend(kifs[nic.name].devices)

        return devices

    def update_device_info(self, devs, timeout=5, callback=None):
        """
            get specific devices' info.
            input:
                devs ->
                    DeviceInfo() or
                    [DeviceInfo(), ...] or
                    mac or
                    [mac, ...]
            return:
                updated devices' info, (devices not responding are not included)
                    [DeviceInfo(), ...]
        """

        # topos = self.topos
        # nics = self.nics

        if not isinstance(devs, (list, tuple, set)):
            devs = [devs]

        macs = set(
            dev.mac if isinstance(dev, DeviceInfo) else EUI(str(dev))
            for dev in devs
        )

        online_devs = set(self.get_alive_devices_by_mac(macs))
        online_macs = set(dev.mac for dev in online_devs)
        offline_macs = macs.difference(online_macs)

        targets = {nic.name: set() for nic in self.nics}
        for dev in online_devs:
            targets[dev.from_nic.name].add(dev.mac)

        result = []
        def cb(dev):
            result.append(dev)
            if callback:
                callback(dev)

        kifs = self.kifs
        tasks = []
        for nic_name, dev_macs in targets.iteritems():
            kif = kifs[nic_name]
            tasks.append(
                make_thread(
                    kif.update_device_info,
                    args=(dev_macs.union(offline_macs),),
                    kwargs={'timeout': timeout, 'callback': cb},
                    daemon=True,
                    start=True
                )
            )

        assert wait_threads(tasks, timeout=timeout+1), \
                "some update_device_info tasks still running, which is not expected. running tasks: %r" % [t for t in tasks if t.is_alive()]

        return result



    def refresh_outdated(self, timeout=5, callback=None):
        """
            re-scan for those KIFs which are nearly outdated.
            output:
                {
                    'nic_name1': [devs,],
                    'nic_name2': [devs,],
                    ......
                }
        """
        topos = self.topos
        kifs = self.kifs

        tasks = []
        refreshed_topos = []
        for nic_name, topo in topos.iteritems():
            if topo.deadline - time.time() < 10 or \
               topo.deadline - time.time() > topo._aging:   # check if deadline valid
                refreshed_topos.append(topo)
                tasks.append(make_thread(
                    kifs[nic_name].scan,
                    kwargs={'timeout': timeout, 'callback': callback},
                    daemon=True,
                    start=True
                ))

        assert wait_threads(tasks, timeout=timeout+1), \
                "some scanning tasks still running, which is not expected. running tasks: %r" % [t for t in tasks if t.is_alive()]
        devices = {topo.nic.name: topo.devices for topo in refreshed_topos}

        return devices


    def execute_each(self, mappings, timeout=10, callback=None):
        """
            execute commands seperatedly for different devices.
            input:
                mappings -> [(dev, [cmd1, cmd2] or cmd), ...]
                    dev -> DeviceInfo or mac
                callback -> function(device, status)
            output:
                {
                    dev1: status,
                    dev2: status,
                    ...
                }
                status -> refer to ConfigAckFrame
        """
        kifs = self.kifs
        mappings = dict(mappings)


        # targets
        # {
        #     nic_name: {dev1: cmds, dev2: cmds, ...},
        #     ...
        # }
        targets = {}
        results = {}
        for dev, cmds in mappings.iteritems():
            if not isinstance(dev, DeviceInfo):
                mac = dev
            else:
                mac = dev.mac
            dev = self.find_devices(mac=mac)
            assert dev, "no such devices whose mac is %r" % mac
            dev = dev[0]
            targets.setdefault(dev.from_nic.name, {})[dev] = cmds
            results[dev] = self.EXEC_STAT_TIMEOUT

        def cb(dev, status):
            results[dev] = status
            if callback:
                callback(dev, status)

        tasks = []
        for nic_name, mp in targets.iteritems():
            kif = kifs[nic_name]
            tasks.append(make_thread(
                kif.execute_each, 
                args=(mp,),
                kwargs={'timeout': timeout, 'callback': cb},
                start=True,
                daemon=True
            ))

        assert wait_threads(tasks, timeout+1), \
                "some execution tasks still running, which is not expected. running tasks: %r" % [t for t in tasks if t.is_alive()]

        return results


    def execute(self, commands, devs=None, timeout=10, callback=None):
        """
            To execute commands on target devices specified by devs or all devices.
            input:
                commands -> [str|unicode] or str|unicode
                devs -> None or [mac|DeviceInfo]
                timeout -> timeout to wait response
                callback -> an optional callback to process result
                    function(dev, status)
                    dev -> DeviceInfo
                    status -> execute status

            return:
                {dev: status, ...}
                dev -> DeviceInfo
        """
        kifs = self.kifs

        if isinstance(commands, (str, unicode)):
            commands = [commands]

        if devs is None:
            devs = self.get_devices()
        elif not isinstance(devs, (set, list, tuple)):
            # single dev parameter
            devs = [devs]

        # targets
        # {
        #     nic_name1: [devs, ],
        #     ...
        # }
        targets = {}
        results = {}
        for dev in devs:
            if not isinstance(dev, DeviceInfo):
                mac = dev
            else:
                mac = dev.mac
            dev = self.find_devices(mac=mac)
            assert dev, "no such devices whose mac is %r" % mac
            dev = dev[0]
            targets.setdefault(dev.from_nic.name, []).append(dev)
            results[dev] = self.EXEC_STAT_TIMEOUT

        def cb(dev, status):
            results[dev] = status
            if callback:
                callback(dev, status)

        tasks = []
        for nic_name, devs in targets.iteritems():
            kif = kifs[nic_name]
            tasks.append(make_thread(
                kif.execute, 
                args=(commands,),
                kwargs={'devs': devs, 'timeout': timeout, 'callback': cb},
                start=True,
                daemon=True
            ))

        assert wait_threads(tasks, timeout+2), \
                "some execution tasks still running, which is not expected. running tasks: %r" % [t for t in tasks if t.is_alive()]

        return results


    def safe_execute(self, commands, devs, timeout=10, callback=None):
        """
            given macs -> results {mac: timeout for mac in macs}
            find cached_devs (with from_nic)
            sync_macs = macs - cached_macs (<- cached_devs)
            all_kifs.sync(sync_macs) -> alive_devs (with from_nic)

            cached_devs + alive_devs -> target_devs

            execute on target_devs (through their kifs) -> update to results

            return results
        """
        kifs = self.kifs
        if not isinstance(devs, (list, tuple, set)):
            devs = [devs]

        macs = set(
            dev.mac if isinstance(dev, DeviceInfo) else EUI(str(dev))
            for dev in devs
        )

        results = {mac: KNMPBase.EXEC_STAT_TIMEOUT for mac in macs}

        target_devs = self.update_device_info(macs)

        #
        # arrange tasks:
        #   one task for each kif
        #
        tasks_info = {}
        for dev in target_devs:
            tasks_info.setdefault(dev.from_nic.name, []).append(dev)

        def _exec_cb(mac, status):
            results[mac] = status
            if callback:
                callback(mac, status)

        tasks = []
        for nic_name, devs in tasks_info.iteritems():
            kif = kifs[nic_name]
            mappings = {
                dev.mac: commands
                for dev in devs
            }
            tasks.append(make_thread(
                kif._req_exec, 
                args=(mappings,),
                kwargs={'timeout': timeout, 'callback': _exec_cb},
                start=True,
                daemon=True
            ))
        assert wait_threads(tasks, timeout+2), \
                "some execution tasks still running, running tasks: %r" % [t for t in tasks if t.is_alive()]

        return {mac: status for mac, status in results.iteritems()}


    def safe_execute_each(self, mappings, timeout=10, callback=None):
        """

        """
        kifs = self.kifs
        mappings = dict(mappings)
        mappings = {
            dev.mac if isinstance(dev, DeviceInfo) else EUI(str(dev)): cmds
            for dev, cmds in mappings.iteritems()
        }

        macs = mappings.keys()

        results = {
            mac: KNMPBase.EXEC_STAT_TIMEOUT 
            for mac in macs
        }

        target_devs = self.update_device_info(macs)

        #
        # tasks_info:
        #   {
        #       nic_name: {
        #           mac1: [cmd1, cmd2,...],
        #           ....
        #       },
        #       ....
        #   }
        tasks_info = {}
        for dev in target_devs:
            tasks_info.setdefault(
                dev.from_nic.name, {}
            )[dev.mac] = mappings[dev.mac]

        def _exec_cb(mac, status):
            results[mac] = status
            if callback:
                callback(mac, status)

        tasks=[]
        for nic_name, mp in tasks_info.iteritems():
            kif = kifs[nic_name]
            tasks.append(make_thread(
                kif._req_exec, 
                args=(mp,),
                kwargs={'timeout': timeout, 'callback': _exec_cb},
                start=True,
                daemon=True
            ))
        assert wait_threads(tasks, timeout+2), \
                "some execution tasks still running, running tasks: %r" % [t for t in tasks if t.is_alive()]

        return results


if __name__ == '__main__':
    import unittest
    class Test(unittest.TestCase):
        # def test_KNMP(self):
        #     nif = 'ens38'   # change this to proper net interface
        #     manager = KNMP(nif, scan_timeout=1, topo_aging=5*60, auto_refresh=True)

        #     # scan
        #     print 'scanning'
        #     devs = manager.scan()
        #     dev1 = devs[0]

        #     # # update device info
        #     # dev1.ip = '192.168.2.34'
        #     # dev1.netmask = '255.255.255.0'
        #     # dev1.gateway = '0.0.0.0'
        #     # dev1.vlan = 12
        #     # dev1.device_name = 'new device name'
        #     # # product_name is immutable
        #     # result = manager.update(dev1)
        #     # self.assertTrue(all(result.values()))

        #     # print 're scan'
        #     # manager.scan()
        #     # self.assertTrue(dev1 manager.devices)

        #     # execute command on device
        #     result = manager.execute("SNMP Configuration", devices=dev1)
        #     self.assertTrue(all(result.values()))

        #     restul = manager.execute("IP Configuration")
        #     self.assertTrue(all(result.values()))

        def test_KNMPDevice(self):
            # self._mac = EUI(info['mac'])
            # self.set_flag(info['flag'])
            # self.set_ip(info['ip'])
            # self.set_netmask(info['netmask'])
            # self.set_gateway(info['gateway'])
            # self.set_vlan(info['vlan'])
            # self.set_device_name(info['device_name'])
            # self.set_product_name(info['product_name'])

            dev = DeviceInfo(
                mac='11-11-11-11-11-11',
                flag = 0x01,
                ip='192.168.3.33',
                netmask='255.255.255.0',
                gateway='192.168.3.1',
                vlan=33,
                device_name='test_dev',
                product_name='KNS500'
            )
            self.assertEqual(dev.mac, EUI('11-11-11-11-11-11'))

            self.assertEqual(dev.ip, '192.168.3.33')
            dev.set_ip('192.168.3.44')
            self.assertEqual(dev.ip, '192.168.3.44')

            self.assertEqual(dev.netmask, '255.255.255.0')
            dev.set_netmask('255.255.0.0')
            self.assertEqual(dev.netmask, '255.255.0.0')

            self.assertEqual(dev.gateway, '192.168.3.1')
            dev.set_gateway('192.168.2.1')
            self.assertEqual(dev.gateway, '192.168.2.1')

            self.assertEqual(dev.vlan, 33)
            dev.set_vlan(44)
            self.assertEqual(dev.vlan, 44)

            self.assertEqual(dev.device_name, 'test_dev')
            dev.set_device_name('test_device')
            self.assertEqual(dev.device_name, 'test_device')

            self.assertEqual(dev.product_name, 'KNS500')
            dev.set_product_name('kns5000')
            self.assertEqual(dev.product_name, 'kns5000')

            dev2 = DeviceInfo(
                mac = dev.mac,
                flag = dev.flag,
                ip = dev.ip,
                netmask = dev.netmask,
                gateway = dev.gateway,
                vlan = dev.vlan,
                device_name = dev.device_name,
                product_name = dev.product_name
            )
            self.assertEqual(dev, dev2)


    unittest.main()



