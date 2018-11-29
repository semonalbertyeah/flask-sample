# -*- coding:utf-8 -*-

import time
import logging

from utils.thread_util import thread_safe
from utils.time_util import wait
from utils.data import ip_2_int, ip_pretty, ip_pretty2

from pcap import Pcap
from pcap.frames.arp import *
from pcap.nicinfo import NicInfo


class ArpErr(Exception):
    pass

#
# Network related, no unit test
# 
def _arp_req(ips, pcap, timeout=3, use_probe=True, callback=None, gap=0):
    """
        ARP Request for multiple IP Addresses on such NIC -- nic
        input:
            ips -> set("192.168.2.1", "192.168.2.3")
            nic -> MUST be an instance of NicInfo
            timeout -> waiting timeout
            use_probe ->
                if True: spa = "0.0.0.0"
                else: spa = first IPv4 configured on nic
            callback -> called when a response is received
                callback(ip, mac)
            gap -> period between sending each request

        return:
            {
                ip1: mac1,
                ip2: None,  // None means no response
                ....
            }
    """
    assert isinstance(ips, set)
    assert isinstance(pcap, Pcap)

    target_ips = ips

    nic = pcap.nic
    nic.reload()
    sha = nic.mac

    result = {ip: None for ip in target_ips}

    if use_probe:
        spa = '0.0.0.0'
    else:
        nic_ip = nic.ipv4
        if nic_ip is None:
            logging.warning("no ip configured on such NIC %r" % nic)
            return result
        spa = nic_ip[0]

    def cb(frame):
        try:
            frame = ArpResponseFrame(raw=frame[:])
            if frame.spa in target_ips:
                result[frame.spa] = frame.sha
                target_ips.discard(frame.spa)
                if callback:
                    callback(frame.spa, frame.sha)
        except (InvalidArpResponseFrame, InvalidArpFrame) as e:
            pass

    try:
        pcap.poll(callback=cb, thread=True, count=-1)

        for ip in result.iterkeys():
            pcap.send(
                ArpRequestFrame(
                    src_mac=sha,
                    src_ip = spa,
                    target_ip=ip
                )[:]
            )
            if gap:
                time.sleep(float(gap))

        wait(int(timeout), break_cond=lambda: len(target_ips) == 0)
    finally:
        pcap.break_poll()

    return result


class ARP(object):
    """
        usage:
            1. request a target
                arphandler = ARP('eth0', ip='192.168.1.33') # ip must be configured on NIC.
                r = arphandler.request('192.168.1.1')   # returns the MAC of target
            2. scan or request multiple targets
                arphandler = ARP('eth0')    # sender IP will use the first IP configured on NIC.
                arphandler.scan(
                    exp="192.168.1.1, 192.168.1.3-192.168.1.99, 192.168.2.0/24, 192.168.3.0:255.255.255.0"
                )
    """
    def __init__(self, nics, use_probe=True):
        """
            input:
                nics -> [nicname1, NicInfo(), nicname12]
                use_probe -> if True, use ARP Probe to request target.
        """
        if not isinstance(nics, (tuple, set, list)):
            nics = [nics]
        nic_names = set(
            nic.name if isinstance(nic, NicInfo) else NicInfo(nic).name
            for nic in nics
        )

        self._use_probe = use_probe
        # self._nicinfo = nics
        # self._spa = ip
        # self._pcap = Pcap(nics.name, filter_exp='arp', snaplen=100, direction='in')
        self._pcaps = {
            name: Pcap(name, filter_exp='arp', snaplen=100, direction='in')
            for name in nic_names
        }

    def _req(self, ips, timeout=3, callback=None, gap=0):
        """
            start polling
            send request
            callack should use thread_safe
        """
        assert isinstance(ips, set)

        addr = {}
        for nic_name, pcap in self._pcaps.iteritems():
            # refresh NicInfo in case IP changed
            pcap.nic.reload()
            if not pcap.nic.up:
                # link-down
                logging.warning("%r is link-down" % pcap.nic)
                continue

            if pcap.nic.loopback:
                # loopback interface
                logging.warning("%r is loopback" % pcap.nic)
                continue

            if self._use_probe:
                spa = "0.0.0.0"
            else:
                # if pcap.nic.ipv4 is None:
                #     # no ip configured
                #     continue
                spa = pcap.nic.ipv4

            addr[nic_name] = (pcap.nic.mac, spa[0])

        result = {ip: None for ip in ips}
        if not addr:
            return result

        @thread_safe
        def cb(frame):
            try:
                frame = ArpResponseFrame(raw=frame[:])
                if frame.spa in ips:
                    result[frame.spa] = frame.sha
                    ips.discard(frame.spa)
                    if callback:
                        callback(frame.spa, frame.sha)
            except (InvalidArpResponseFrame, InvalidArpFrame) as e:
                # logging.error("exception: %r" % e)
                pass

        try:
            for pcap in self._pcaps.itervalues():
                pcap.poll(callback=cb, thread=True, count=-1)

            for ip in result.iterkeys():
                for nic_name, pcap in self._pcaps.iteritems():
                    sha, spa = addr[nic_name]
                    pcap.send(
                        ArpRequestFrame(
                            src_mac=sha,
                            src_ip = spa,
                            target_ip=ip
                        )[:]
                    )
                if gap:
                    time.sleep(float(gap))

            wait(int(timeout), break_cond=lambda: len(ips) == 0)
        finally:
            for pcap in self._pcaps.itervalues():
                pcap.break_poll()

        return result


    def request(self, ip, timeout=3):
        """
            start pcap.poll thread.
            send a request
            wait result or timeout.
            if timeout:
                raise exception

            return result
        """
        ip = ip_pretty2(ip)
        result = self._req(set([ip]), timeout=timeout)
        return result[ip]


    @staticmethod
    def parse_target(exp):
        """
            parse target expression
            input:
                exp ->
                    1. single IP: 192.168.1.2
                    2. range: 192.168.2.3-192.168.2.66
                    3. network: 192.168.4.0/24 or 192.168.4.0:255.255.255.0
        """
        if not isinstance(exp, (unicode, str)):
            raise TypeError, "Invalid input: %r" % exp

        exp = exp.replace(' ', '')

        if '/' in exp:
            net, netmask_len = exp.split('/')
            net = ip_2_int(net)
            netmask_len = int(netmask_len)
            if netmask_len <= 0 or netmask_len >= 32:
                raise ValueError, "Invalid expression %r, invalid netmask" % exp

            hostmask_len = 32 - netmask_len
            netmask = 0
            for i in xrange(32):
                bit_pos = 32 - i - 1
                if bit_pos >= hostmask_len:
                    netmask = netmask | (1 << bit_pos)
                else:
                    break

            hostmask = (0xffffffff & (~netmask))

            if (net & hostmask) != 0:
                raise ValueError, "Invalid expression %s, host ID should be 0." % exp

            start_ip = net + 1
            end_ip = (net | hostmask) - 1
            return [ip_pretty(ip) for ip in xrange(start_ip, end_ip + 1)]

        elif ':' in exp:
            net, netmask = exp.split(':')
            net = ip_2_int(net)
            netmask = ip_2_int(netmask)
            hostmask = (0xffffffff & (~netmask))
            if netmask == 0 or netmask == 0xffffffff:
                raise ValueError, "Invalid expression %s, invalid netmask" % exp

            if net & hostmask != 0:
                raise ValueError, "Invalid expression %s, host ID should be 0." % exp

            start_ip = net + 1
            end_ip = (net | hostmask) - 1
            return [ip_pretty(ip) for ip in xrange(start_ip, end_ip + 1)]

        elif '-' in exp:
            start_ip , end_ip = exp.split('-')
            start_ip = ip_2_int(start_ip)
            end_ip = ip_2_int(end_ip)
            return [ip_pretty(ip) for ip in xrange(start_ip, end_ip + 1)]

        else:
            return [ip_pretty(ip_2_int(exp))]



    def scan(self, exps, timeout=5, callback=None, gap=0):
        """
            Scan multiple targets.
            input:
                exps ->
                    1. string expression:
                        "192.168.1.2, 192.168.1.99-192.168.1.200, 192.168.2.0/24, 192.168.33.0:255.255.255.0"
                    2. array of expression units
                        [
                            "192.168.1.1",
                            "192.168.1.99-192.168.1.200",
                            "192.168.2.0/24",
                            "192.168.33.0:255.255.255.0"
                        ]
            output:
                {
                    'ip1': 'mac1',
                    'ip2': None,        # no response for this target.
                    'ip3': 'mac3',
                    ...
                }
        """
        if not exps:
            return {}

        if isinstance(exps, (str, unicode)):
            exps = exps.split(',')

        if not isinstance(exps, list):
            pass

        if not all(isinstance(ip, (str, unicode)) for ip in exps):
            raise ValueError, "invalid input: %r" % exps


        target_ips = set()
        for exp in exps:
            if exp:
                target_ips.update(self.parse_target(exp))

        return self._req(target_ips, timeout=timeout, callback=callback, gap=gap)




