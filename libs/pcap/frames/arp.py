# -*- coding:utf-8 -*-

from netaddr import EUI

from utils.data import *

from .ether import EtherFrame, is_unicast_mac, is_local_admin_mac


class ErrArpFrame(Exception):
    pass

class InvalidArpFrame(ErrArpFrame):
    pass

class UnsupportedArpFrame(ErrArpFrame):
    pass



class ArpFrame(EtherFrame):
    """
        ARP frame with Hardware Type: Ethernet and Protocol Type: Ipv4.
    """

    # ethertype of ARP
    ETHER_TYPE_ARP = 0x0806

    # hardware type
    HTYPE_ETHER = 1

    # hardware address length
    HTYPE_ETHER_LEN = 6

    # protocol type
    PTYPE_IPV4 = 0x0800

    # protocol address length
    PTYPE_IPV4_LEN = 4

    # operation code
    OP_REQ = 1
    OP_REP = 2


    MIN_PAYLOAD_SIZE = 28

    def __init__(self, dest_mac=None, src_mac=None,
                vlan=None, priority=0, dei=0,
                op=None, sha=None, tha=None,
                spa=None, tpa=None, raw=None):

        if raw is not None:
            super(ArpFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)

        else:
            payload = self.build_payload(op, sha, spa, tha, tpa)
            padding_size = EtherFrame.MIN_ETHER_PAYLOAD_LEN - len(payload)
            if vlan is not None:
                padding_size = padding_size - 4

            if padding_size > 0:
                # fill to make ethernet payload size of 46 bytes.
                # 802.1q tag is not counted.
                payload.extend([0x00] * padding_size)

            super(ArpFrame, self).__init__(
                dest_mac=dest_mac,
                src_mac=src_mac,
                vlan=vlan,
                dei=dei,
                priority=priority,
                ethertype=self.ETHER_TYPE_ARP,
                payload=payload
            )
            self.check(raise_exc=True)

    def check(self, raise_exc=False):
        try:
            # check for HTYPE, PTYPE, HLEN, PLEN
            if self.htype != self.HTYPE_ETHER:
                raise InvalidArpFrame, "Invalid Hardware Type: %r" % self.htype
            if self.ptype != self.PTYPE_IPV4:
                raise InvalidArpFrame, "Invalid Protocol Type: %r" % self.ptype
            if self.hlen != self.HTYPE_ETHER_LEN:
                raise InvalidArpFrame, "Invalid Hardware Address Length: %r" % self.hlen
            if self.plen != self.PTYPE_IPV4_LEN:
                raise InvalidArpFrame, "Invalid Protocol Address Length: %r" % self.plen

            # check for operation code
            if self.op not in (1, 2):
                raise InvalidArpFrame, "Invalid operation code: %r" % self.op

            # check Source Hardware Address
            if not self.is_valid_sha(self.sha):
                raise InvalidArpFrame, "Invalid Source Hardware Address: %r" % self.sha

            if self.sha != self.src_mac:
                raise InvalidArpFrame, "SHA should be the same as Source MAC."

            # check for Target Hardware Address
            if not self.is_valid_tha(self.tha):
                raise InvalidArpFrame, "Invalid Target Hardware Address: %r" % self.tha

            return True

        except InvalidArpFrame as e:
            if raise_exc:
                raise
            else:
                return False

    @staticmethod
    def is_valid_tha(mac):
        mac = EUI(mac)
        if is_unicast_mac(mac) or \
           mac == EUI('00-00-00-00-00-00') or \
           mac == EUI('ff-ff-ff-ff-ff-ff'):

            return True
        else:
            return False


    @staticmethod
    def is_valid_sha(mac):
        mac = EUI(mac)
        if is_unicast_mac(mac):
            return True
        else:
            return False


    @staticmethod
    def build_payload(op, sha, spa, tha, tpa):
        """
            ARP packet data, without padding.
            input:
                op -> int, 0 or 1
                sha -> EUI compatible
                spa -> ip display string or int 
                tha -> EUI compatible
                tpa -> ip display string or int
        """
        payload = []

        # hardware type
        payload.extend([
            (ArpFrame.HTYPE_ETHER & 0xff00) >> 8,
            ArpFrame.HTYPE_ETHER & 0xff,
        ])

        # protocol type
        payload.extend([
            (ArpFrame.PTYPE_IPV4 & 0xff00) >> 8,
            ArpFrame.PTYPE_IPV4 & 0xff,
        ])

        # hardware address length
        payload.append(ArpFrame.HTYPE_ETHER_LEN)

        # protocol address length
        payload.append(ArpFrame.PTYPE_IPV4_LEN)

        # operation code
        assert op in (1, 2), "Invalid operation code: %r" % op
        payload.extend([
            (op & 0xff00) >> 8,
            op & 0xff,
        ])

        # source hardware address
        assert ArpFrame.is_valid_sha(sha), "invalid Source Hardware Address: %r" % sha
        payload.extend(EUI(sha).words)

        # source protocol address
        payload.extend(ip_2_byte_array(spa))

        # target hardware address
        assert ArpFrame.is_valid_tha(tha), "invalid Target Hardware Address: %r" % tha
        payload.extend(EUI(tha).words)

        # target protocol address
        payload.extend(ip_2_byte_array(tpa))

        return payload


    @property
    def htype(self):
        pos = self._get_payload_pos()
        return byte_array_2_int(self._raw[pos:pos+2])

    @property
    def ptype(self):
        pos = self._get_payload_pos() + 2
        return byte_array_2_int(self._raw[pos:pos+2])

    @property
    def hlen(self):
        pos = self._get_payload_pos() + 4
        return self._raw[pos]

    @property
    def plen(self):
        pos = self._get_payload_pos() + 5
        return self._raw[pos]

    @property
    def op(self):
        pos = self._get_payload_pos() + 6
        return byte_array_2_int(self._raw[pos:pos+2])

    def set_op(self, value):
        assert value in (1, 2), "Invalid Operation Code: %r" % value
        pos = self._get_payload_pos() + 6
        self._raw[pos: pos+2] = int_2_byte_array(value, 2)

    @op.setter
    def op(self, value):
        self.set_op(value)

    @property
    def sha(self):
        pos = self._get_payload_pos() + 8
        return EUI(byte_array_2_int(self._raw[pos: pos+6]))

    def set_sha(self, mac):
        """
            This may cause inequality of SHA and source MAC.
        """
        assert self.is_valid_sha(mac), "invalid Source Hardware Address: %r" % mac

        pos = self._get_payload_pos() + 8
        mac = EUI(mac)
        self._raw[pos: pos+6] = mac.words

    @sha.setter
    def sha(self, mac):
        self.set_sha(mac)


    @property
    def spa(self):
        pos = self._get_payload_pos() + 14
        return '.'.join(str(i) for i in self._raw[pos: pos+4])

    def set_spa(self, value):
        pos = self._get_payload_pos() + 14
        self._raw[pos: pos+4] = ip_2_byte_array(value)

    @spa.setter
    def spa(self, value):
        self.set_spa(value)

    @property
    def tha(self):
        pos = self._get_payload_pos() + 18
        return EUI(byte_array_2_int(self._raw[pos: pos+6]))

    def set_tha(self, mac):
        assert self.is_valid_tha(mac), "invalid Target Hardware Address: %r" % mac

        pos = self._get_payload_pos() + 18
        mac = EUI(mac)
        self._raw[pos: pos+6] = mac.words

    @tha.setter
    def tha(self, value):
        self.set_tha(value)


    @property
    def tpa(self):
        pos = self._get_payload_pos() + 24
        return '.'.join(str(i) for i in self._raw[pos: pos+4])

    def set_tpa(self, value):
        pos = self._get_payload_pos() + 24
        self._raw[pos: pos+4] = ip_2_byte_array(value)

    @tpa.setter
    def tpa(self, value):
        self.set_tpa(value)





class InvalidArpRequestFrame(Exception):
    pass

class ArpRequestFrame(ArpFrame):
    def __init__(self, src_mac=None, src_ip=None, target_ip=None,
                vlan=None, priority=0, dei=0,
                raw=None):
        if raw is not None:
            super(ArpRequestFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)

        else:
            super(ArpRequestFrame, self).__init__(
                dest_mac='ff-ff-ff-ff-ff-ff', 
                src_mac=src_mac,
                vlan=vlan, priority=priority, dei=dei,
                op=self.OP_REQ, 
                sha=src_mac, 
                tha='00-00-00-00-00-00',
                spa=src_ip,
                tpa=target_ip
            )
            self.check(raise_exc=True)

    def check(self, raise_exc=False):
        try:
            if not super(ArpRequestFrame, self).check(raise_exc):
                return False

            if self.op != self.OP_REQ:
                raise InvalidArpRequestFrame, "Wrong Operation code: %r" % self.op

            if self.tha != EUI("00-00-00-00-00-00"):
                raise InvalidArpRequestFrame, "Target Hardware Address must be 00-00-00-00-00-00, current value: %r" % self.tha

            if self.dest_mac != EUI('ff-ff-ff-ff-ff-ff'):
                raise InvalidArpRequestFrame, "Destination MAC Address must be ff-ff-ff-ff-ff-ff, current value: %r" % self.dest_mac

            return True
        except InvalidArpRequestFrame as e:
            if raise_exc:
                raise
            else:
                return False






class InvalidArpResponseFrame(Exception):
    pass


class ArpResponseFrame(ArpFrame):
    def __init__(self, src_mac=None, src_ip=None, 
                target_mac=None, target_ip=None,
                vlan=None, priority=0, dei=0,
                raw=None):
        if raw is not None:
            super(ArpResponseFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)

        else:
            super(ArpResponseFrame, self).__init__(
                dest_mac=target_mac, 
                src_mac=src_mac,
                vlan=vlan, priority=priority, dei=dei,
                op=self.OP_REP, 
                sha=src_mac, 
                tha=target_mac,
                spa=src_ip,
                tpa=target_ip
            )
            self.check(raise_exc=True)

    def check(self, raise_exc=False):
        try:
            if not super(ArpResponseFrame, self).check(raise_exc):
                return False

            if self.op != self.OP_REP:
                raise InvalidArpResponseFrame, "Wrong Operation code: %r" % self.op

            if not is_unicast_mac(self.tha):
                raise InvalidArpResponseFrame, "Invalid Target Hardware Address: %r" % self.tha

            if self.tha != self.dest_mac:
                raise InvalidArpResponseFrame, "Target Hardware Address should the same as Destination MAC."

            return True
        except InvalidArpResponseFrame as e:
            if raise_exc:
                raise
            else:
                return False






class InvalidGArpFrame(Exception):
    pass

class GArpFrame(ArpFrame):
    def __init__(self, mac=None, ip=None, op=2,
                vlan=None, priority=0, dei=0,
                raw=None):
        if raw is not None:
            super(GArpFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)

        else:
            super(GArpFrame, self).__init__(
                dest_mac='ff-ff-ff-ff-ff-ff', 
                src_mac=mac,
                vlan=vlan, priority=priority, dei=dei,
                op=op, 
                sha=mac, 
                tha='ff-ff-ff-ff-ff-ff',
                spa=ip,
                tpa=ip
            )
            self.check(raise_exc=True)

    def check(self, raise_exc=False):
        try:
            if not super(GArpFrame, self).check(raise_exc):
                return False

            if self.dest_mac != EUI('ff-ff-ff-ff-ff-ff'):
                raise InvalidGArpFrame, "Destination MAC should be ff-ff-ff-ff-ff-ff, current: %r" % self.dest_mac

            if (self.tha != EUI('00-00-00-00-00-00')) and (self.tha != EUI('ff-ff-ff-ff-ff-ff')):
                raise InvalidGArpFrame, "Invalid Target Hardware Address: %r" % self.tha

            if self.spa != self.tpa:
                raise InvalidGArpFrame, "Source Protocol Address and Target Protocol Address should be the same."

            return True

        except InvalidGArpFrame as e:
            if raise_exc:
                raise
            else:
                return False



class InvalidArpProbeFrame(Exception):
    pass

class ArpProbeFrame(ArpFrame):
    """
        dest_mac=ff-ff-ff-ff-ff-ff
        op=1 (request)
        sha=sender’s MAC
        spa=0.0.0.0
        tha=00-00-00-00-00-00
        tpa=ip being probed
    """
    def __init__(self, src_mac=None, target_ip=None,
                vlan=None, priority=0, dei=0,
                raw=None):
        if raw is not None:
            super(ArpProbeFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)

        else:
            super(ArpProbeFrame, self).__init__(
                dest_mac='ff-ff-ff-ff-ff-ff', 
                src_mac=src_mac,
                vlan=vlan, priority=priority, dei=dei,
                op=self.OP_REQ, 
                sha=src_mac, 
                tha='00-00-00-00-00-00',
                spa='0.0.0.0',
                tpa=target_ip
            )
            self.check(raise_exc=True)

    def check(self, raise_exc=False):
        try:
            if not super(ArpProbeFrame, self).check(raise_exc):
                return False

            if self.op != self.OP_REQ:
                raise InvalidArpProbeFrame, "Wrong Operation code: %r" % self.op

            if self.tha != EUI("00-00-00-00-00-00"):
                raise InvalidArpProbeFrame, "Target Hardware Address must be 00-00-00-00-00-00, current value: %r" % self.tha

            if self.dest_mac != EUI('ff-ff-ff-ff-ff-ff'):
                raise InvalidArpProbeFrame, "Destination MAC Address must be ff-ff-ff-ff-ff-ff, current value: %r" % self.dest_mac

            if self.spa != '0.0.0.0':
                raise InvalidArpProbeFrame, "Source Protocol Address should be 0.0.0.0, current value: %r" % self.spa

            return True
        except InvalidArpProbeFrame as e:
            if raise_exc:
                raise
            else:
                return False


class ArpAnnouncementFrame(ArpFrame):
    pass



