# -*- coding:utf-8 -*-

from netaddr import EUI

from utils.func import proxy_method
from utils.data import *


def is_unicast_mac(mac):
    """
        input:
            mac -> EUI compatible data
    """
    mac = EUI(mac)
    return not bool(mac[0] & 0x01)

def is_local_admin_mac(mac):
    mac = EUI(mac)
    return bool(mac[0] & 0x02)

class InvalidEtherFrame(Exception):
    pass

class EtherFrame(object):
    """
        Ethernet Frame
    """

    # ethernet header: DMAC (6 bytes), SMAC (6 bytes), FRAME LENGTH (2 bytes)
    ETHER_HEADER_LEN = 14

    VLAN_TAG_LEN = 4
    VLAN_TPID = 0x8100

    MIN_ETHER_PAYLOAD_LEN = 46
    MAX_ETHER_PAYLOAD_LEN = 1500

    MIN_ETHER_TYPE = 1536
    MAX_ETHER_LEN = 1500

    MIN_FRAME_LEN = MIN_ETHER_PAYLOAD_LEN + ETHER_HEADER_LEN
    MAX_FRAME_LEN = MAX_ETHER_PAYLOAD_LEN + ETHER_HEADER_LEN + VLAN_TAG_LEN

    def __init__(self, dest_mac=None, src_mac=None, 
                vlan=None, priority=0, dei=0, 
                ethertype=None, payload=None, raw=None):

        if raw:
            raw = assure_bin_data(raw)
            # self.parse_frame(raw)
            self._raw = raw
            self.check(raise_exc=True)

        else:
            self._raw = self.build_raw(
                dest_mac,
                src_mac,
                payload,
                ethertype=ethertype,
                dei=dei,
                priority=priority,
                vlan=vlan
            )

    def check(self, raise_exc=False):
        try:
            raw_len = len(self._raw)
            if raw_len < EtherFrame.MIN_FRAME_LEN:
                raise InvalidEtherFrame, 'frame length (0x%0.4x) is smaller than minimum ethernet frame size (0x%0.4x)' % (raw_len, EtherFrame.MIN_FRAME_LEN)
            if raw_len > EtherFrame.MAX_FRAME_LEN:
                raise InvalidEtherFrame, 'frame length (0x%0.4x) is larger than maximum ethernet frame size (0x%0.4x)' % (raw_len, EtherFrame.MAX_FRAME_LEN)

            if self.ethertype is not None:
                if self.ethertype < self.MIN_ETHER_TYPE:
                    raise InvalidEtherFrame, "Invalid Ether Type: 0x%0.4x" % self.ethertype
            else:
                if self.etherlen != len(self.payload):
                    raise InvalidEtherFrame, "Ether Length (0x%0.4x) is not equal to the length of payload" % self.etherlen

            return True
        except InvalidEtherFrame as e:
            if raise_exc:
                raise
            else:
                return False

    @staticmethod
    def build_raw(dest_mac, src_mac, payload, ethertype=None, dei=None, priority=None, vlan=None):

        frame = []

        dest_mac = EUI(dest_mac)
        src_mac = EUI(src_mac)

        frame.extend(dest_mac.words)
        frame.extend(src_mac.words)

        if vlan is not None:
            # vlan could be 0,
            # which makes this frame an priority-tagged frame.

            if dei is None:
                dei = 0         # default, drop eligible indicator 0
            assert dei in (0, 1), 'invalid DEI: %r' % dei

            if priority is None:
                priority = 0    # default, 0 -> best effort
            assert priority in xrange(0,8), "invalid VLAN Priority %r" % priority

            frame.extend([
                0x81,
                0x00,
                (priority << 5) | (dei << 4) | ((vlan & 0x0f00) >> 8),
                vlan & 0xff
            ])

        if ethertype is not None:
            assert ethertype >= EtherFrame.MIN_ETHER_TYPE, "invalid ethertype: 0x%0.04x" % ethertype
            frame.extend([
                (ethertype & 0xff00) >> 8,
                ethertype & 0x00ff
            ])

        else:
            size = len(payload)
            assert size <= EtherFrame.MAX_ETHER_PAYLOAD_LEN and size >= EtherFrame.MIN_ETHER_PAYLOAD_LEN, \
                "length of payload is invalid: %d" % size
            frame.extend([
                (size & 0xff00) >> 8,
                size & 0x00ff
            ])

        payload = assure_bin_data(payload)
        frame.extend(payload)

        return frame


    ##############################
    # enumerate list (readonly)
    ##############################

    __getitem__ = proxy_method('_raw', '__getitem__')
    __len__ = proxy_method('_raw', '__len__')
    __contains__ = proxy_method('_raw', '__contains__')
    __iter__ = proxy_method('_raw', '__iter__')


    def __eq__(self, another):
        return self._raw == another._raw

    def __ne__(self, another):
        return self._raw != another._raw

    def __str__(self):
        """
            return binary data
        """
        return ''.join([chr(i) for i in self._raw])


    ####################
    # dest mac [0:6]
    ####################
    @property
    def dest_mac(self):
        return EUI(byte_array_2_int(self._raw[0:6]))

    def set_dest_mac(self, mac):
        mac = EUI(mac)
        self._raw[0:6] = mac.words

    @dest_mac.setter
    def dest_mac(self, mac):
        self.set_dest_mac(mac)


    ####################
    # src mac [6:12]
    ####################
    @property
    def src_mac(self):
        """
            change dest mac of snap frame
            mac: compatible with snap frame
        """
        return EUI(byte_array_2_int(self._raw[6:12]))

    def set_src_mac(self, mac):
        """
            change source mac of snap frame
            mac: which is compatible EUI
        """
        mac = EUI(mac)
        self._raw[6:12] = mac.words

    @src_mac.setter
    def src_mac(self, mac):
        self.set_src_mac(mac)


    ####################
    # vlan related
    ####################
    def has_vlan(self):
        type_or_size = byte_array_2_int(self._raw[12:14])
        return type_or_size == self.VLAN_TPID

    def _get_payload_pos(self):
        if self.has_vlan():
            return 18
        else:
            return 14

    def set_vlan_tag(self, priority=None, dei=None, vlan=None):
        if not self.has_vlan():
            # add default 8021q tag
            #   priority: 0
            #   dei: 0
            #   vlan: 0
            raw = self._raw[:12]    # dmac, smac
            raw.extend([0x81, 0x00, 0x00, 0x00])
            raw.extend(self._raw[12:])
            self._raw = raw

        origin_priority = (self._raw[14] & 0xfe) >> 5
        origin_dei = (self._raw[14] & 0x10) >> 4
        origin_vlan = ((self._raw[14] & 0x0f) << 8) | self._raw[15]

        # set priority, dei, vlan
        if priority is not None:
            assert priority in xrange(0, 8), "invalid priority value: %r" % priority
            self._raw[14] = (priority << 5) | (origin_dei << 4) | ((origin_vlan & 0x0f00) >> 8)
            origin_priority = priority

        if dei is not None:
            assert dei in (0, 1), "invalid DEI value: %r" % dei
            self._raw[14] = (origin_priority << 5) | (dei << 4) | ((origin_vlan & 0x0f00) >> 8)
            origin_dei = dei

        if vlan is not None:
            assert isinstance(vlan, int) and \
                   vlan >= 0 and vlan <= 4095, "invalid VLAN value: %r" % vlan
            self._raw[14] = (origin_priority << 5) | (origin_dei << 4) | ((vlan & 0x0f00) >> 8)
            self._raw[15] = vlan & 0xff


    @property
    def vlan(self):
        if self.has_vlan():
            return ((self._raw[14] & 0x0f) << 8) | self._raw[15]
        else:
            return None

    def set_vlan(self, value):
        """
            if has vlan:
                set vlan
            else:
                add 802.1q tag to frame.
        """
        assert value is not None, "invalid VLAN value %r" % value
        self.set_vlan_tag(vlan=value)

    @vlan.setter
    def vlan(self, value):
        self.set_vlan(value)


    @property
    def priority(self):
        if self.has_vlan():
            return (self._raw[14] & 0xfe) >> 5
        else:
            return None

    def set_priority(self, value):
        assert value is not None, "invalid priority value: %r" % value
        self.set_vlan_tag(priority=value)

    @priority.setter
    def priority(self, value):
        self.set_priority(value)


    @property
    def dei(self):
        if self.has_vlan():
            return (self._raw[14] & 0x10) >> 4
        else:
            return None

    def set_dei(self, value):
        assert value is not None, "invalid DEI value: %r" % value
        self.set_vlan_tag(dei=value)

    @dei.setter
    def dei(self, value):
        self.set_dei(value)


    ####################
    # ether_len [12:14]
    ####################
    @property
    def etherlen(self):
        if self.has_vlan():
            type_or_size = byte_array_2_int(self._raw[16:18])
        else:
            type_or_size = byte_array_2_int(self._raw[12:14])

        if type_or_size <= self.MAX_ETHER_LEN:
            return type_or_size
        else:
            return None

    # def set_etherlen(self, value):
    #     value = int(value)
    #     assert value <= self.MAX_ETHER_LEN, "invalid ether length: %r" % value
    #     if self.has_vlan():
    #         self._raw[16:18] = [
    #             (value & 0xff00) >> 8,
    #             value & 0xff
    #         ]
    #     else:
    #         self._raw[12:14] = [
    #             (value & 0xff00) >> 8,
    #             value & 0xff
    #         ]

    # @etherlen.setter
    # def etherlen(self, value):
    #     self.set_etherlen(value)

    @property
    def ethertype(self):
        if self.has_vlan():
            type_or_size = byte_array_2_int(self._raw[16:18])
        else:
            type_or_size = byte_array_2_int(self._raw[12:14])

        if type_or_size >= self.MIN_ETHER_TYPE:
            return type_or_size
        else:
            return None

    def set_ethertype(self, value):
        value = int(value)
        assert value >= self.MIN_ETHER_TYPE, "invalid ether type: %r" % value
        if self.has_vlan():
            self._raw[16:18] = [
                (value & 0xff00) >> 8,
                value & 0xff
            ]
        else:
            self._raw[12:14] = [
                (value & 0xff00) >> 8,
                value & 0xff
            ]

    @ethertype.setter
    def ethertype(self, value):
        self.set_ethertype(value)


    @property
    def payload(self):
        if self.has_vlan():
            return self._raw[18:]
        else:
            return self._raw[14:]


    def set_payload(self, value):
        value = assure_bin_data(value)
        plen = len(value)
        assert plen >= self.MIN_ETHER_PAYLOAD_LEN and plen <= self.MAX_ETHER_PAYLOAD_LEN, \
                "payload with invalid size."

        if self.has_vlan():
            raw = self._raw[:18]
        else:
            raw = self._raw[:14]

        raw.extend(value)
        self._raw = raw

    @payload.setter
    def payload(self, value):
        self.set_payload(value)


    def dump(self):
        print 'source mac:', '.'.join('%0.2x' % i for i in self._raw[:6])
        print 'dest mac:', '.'.join('%0.2x' % i for i in self._raw[6:12])
        pos = 12
        if self.has_vlan():
            print 'TPID:', '.'.join('%0.2x' % i for i in self._raw[12:14])
            print 'TCI:', '.'.join('%0.2x' % i for i in self._raw[14:16])
            pos = 16

        print 'type or size:', '.'.join('%0.2x' % i for i in self._raw[pos:pos+2])
        print 'payload:', '.'.join('%0.2x' % i for i in self._raw[pos+2:])



class IPv4Frame(EtherFrame):
    def __init__(self, dscp=0, ecn=0, identification=None, ttl=64, ):
        # version: fixed to 4
        # IHL: calculated (from headers)
        # dscp: default 0
        # ecn: default 0
        # (total)length: calculated
        # identification: default random
        # fragmented: force to false
        # fragment offset: force to 0
        # time to live: default 64
        # protocol: refer to https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        # header checksum: calculated ()
        # src_ip
        # dest_ip
        # options: disabled
        # data
        pass


