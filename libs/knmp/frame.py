# -*- coding:utf-8 -*-

from netaddr import EUI
from binascii import crc32

from utils.func import proxy_method
from utils.data import *

from snap import (
    SnapFrame,
    int_2_byte_array, byte_array_2_int,
    assure_bin_data
)



class KNMPFrameError(Exception):
    pass

class KNMPFrameErrInvalid(KNMPFrameError):
    pass


class KNMPFrame(SnapFrame):
    """
        KNMP Frame
        data length: 38 bytes
        frame length: 60 bytes
            ----------------------------------------------------------------------------
            DMAC        SMAC        FRAME LENGTH
            6 bytes     6 bytes     2 bytes
            ----------------------------------------------------------------------------
            DSAP        SSAP        CONTROL         OUIID                   Protocol ID
            0xAA        0xAA        0x03            0x983000 (3 bytes)      2 bytes
            ----------------------------------------------------------------------------
            PAYLOAD                 CRC
            >= 34 bytes             crc32(payload)
            ----------------------------------------------------------------------------
    """

    OUIID = 0x983000

    # protocol ID
    PROTO_SCAN = 0xff
    PROTO_SCAN_ACK = 0x10
    PROTO_CFG = 0x01
    PROTO_CFG_ACK = 0x11

    PROTOS = [
        PROTO_SCAN,
        PROTO_SCAN_ACK,
        PROTO_CFG,
        PROTO_CFG_ACK
    ]


    def __init__(self, dest_mac=None, src_mac=None, protocol_id=None, 
                 payload=None, raw=None):
        if raw:
            super(KNMPFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)
        else:
            assert protocol_id in self.PROTOS

            payload = assure_bin_data(payload)
            assert len(payload) >= 34

            checksum = int_2_byte_array(
                self.calculate_checksum(payload), 4
            )
            data = payload + checksum
            super(KNMPFrame, self).__init__(dest_mac, src_mac, self.OUIID, 
                                            protocol_id, data)


    @property
    def proto(self):
        """
            display of protocol_id
        """
        if self.protocol_id == self.PROTO_SCAN:
            return 'scan'
        elif self.protocol_id == self.PROTO_SCAN_ACK:
            return 'scan ack'
        elif self.protocol_id == self.PROTO_CFG:
            return 'config'
        elif self.protocol_id == self.PROTO_CFG_ACK:
            return 'config ack'
        else:
            raise KNMPFrameErrInvalid, 'wrong protocol id: 0x%0.4x' % self.protocol_id


    def check(self, raise_exc=False):
        """
            check whether KNMP frame is valid.
        """
        try:
            # ouiid
            if self.ouiid != self.OUIID:
                raise KNMPFrameErrInvalid, "wrong ouiid: 0x%0.6x" % self.ouiid

            # protocol id
            if not self.protocol_id in self.PROTOS:
                raise KNMPFrameErrInvalid, "invalid protocol id 0x%0.4x" % self.protocol_id

            # checksum
            if self.calculate_checksum(self.payload) != self.checksum:
                raise KNMPFrameErrInvalid, 'CRC failure'

            return True
        except KNMPFrameErrInvalid as e:
            if raise_exc:
                raise e

            return False

    @property
    def payload(self):
        """
            KNMP frame payload
        """
        return self.data[:-4]

    def set_payload(self, payload):
        """
            change payload (and crc)
        """
        payload = assure_bin_data(payload)
        assert len(payload) >= 34
        checksum = int_2_byte_array(
            self.calculate_checksum(payload), 4
        )

        self.set_data(payload + checksum)


    def update_checksum(self):
        new_checksum = self.calculate_checksum(self.payload)
        self._raw[-4:] = int_2_byte_array(new_checksum, 4)


    @staticmethod
    def calculate_checksum(payload):
        if isinstance(payload, list):
            payload = ''.join([chr(i) for i in payload])
        assert isinstance(payload, str)
        return crc32(payload) & 0xffffffff

    @property
    def checksum(self):
        crc = self.data[-4:]
        return byte_array_2_int(crc)



#########################################
#    Scan 
#########################################


class InvalidScanFrame(Exception):
    pass

class ScanFrame(KNMPFrame):
    """
        KNMP scan frame
        data length: 38 bytes
        frame length: 60 bytes
            --------------------------------------------------------------------------------------------------------
            DMAC                    SMAC                    FRAME LENGTH
            98-30-00-00-02-20       6 bytes                 2 bytes
            --------------------------------------------------------------------------------------------------------
            DSAP                    SSAP                    CONTROL         OUIID           Protocol ID
            0xAA                    0xAA                    0x03            0x983000        0x00ff
            --------------------------------------------------------------------------------------------------------
            Management ID           Topo ID                 filling                         CRC
            4 bytes (manager)       2 bytes (topology)      0xff * 28                       4 bytes ( crc32(payload) )
            --------------------------------------------------------------------------------------------------------

        Usage:
            ScanFrame(src_mac='11-22-33-44-55-66', mgmt_id=33, topo_id=1)
    """
    PROBE_MAC = EUI('98-30-00-00-02-20')

    def __init__(self, src_mac=None, mgmt_id=None, topo_id=None, raw=None):
        if raw:
            if isinstance(raw, KNMPFrame):
                raw = KNMPFrame._raw
            super(ScanFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)
        else:
            dest_mac = self.PROBE_MAC
            protocol_id = self.PROTO_SCAN
            payload = self.build_payload(mgmt_id, topo_id)

            super(ScanFrame, self).__init__(dest_mac, src_mac,  protocol_id, payload)

    @staticmethod
    def build_payload(mgmt_id, topo_id):
        """
            management id: 4 bytes
            topology id : 2 bytes
            filling : 0xff * 28
        """
        assert isinstance(mgmt_id, int) 
        assert mgmt_id >= 0 and mgmt_id <= 0xffffffff
        assert isinstance(topo_id, int)
        assert topo_id >= 0 and topo_id <= 0xffff

        payload = []
        payload.extend(int_2_byte_array(mgmt_id, 4))
        payload.extend(int_2_byte_array(topo_id, 2))
        payload.extend([0xff] * 28)

        return payload


    def check(self, raise_exc=False):
        if not super(ScanFrame, self).check(raise_exc):
            return False
        try:
            if self.dest_mac.words != self.PROBE_MAC.words:
                raise InvalidScanFrame, "Destination MAC (%s) is not Probe MAC (%s)" % (str(self.dest_mac), str(self.PROBE_MAC))
            if self.protocol_id != self.PROTO_SCAN:
                raise InvalidScanFrame, "protocol id (0x%0.4x) is not SCAN" % self.protocol_id

            return True
        except InvalidScanFrame as e:
            if raise_exc:
                raise e
            return False


    @property
    def mgmt_id(self):
        return byte_array_2_int(self._raw[22:26])

    def set_mgmt_id(self, mgmt_id):
        assert isinstance(mgmt_id, int)
        assert mgmt_id >= 0 and mgmt_id <= 0xffffffff
        self._raw[22:26] = int_2_byte_array(mgmt_id, 4)
        self.update_checksum()

    @property
    def topo_id(self):
        return byte_array_2_int(self._raw[26:28])

    def set_topo_id(self, topo_id):
        assert isinstance(topo_id, int)
        assert topo_id >= 0 and topo_id <= 0xffff
        self._raw[26:28] = int_2_byte_array(topo_id, 2)
        self.update_checksum()


from socket import inet_aton, inet_ntoa


class InvalidScanAckFrame(Exception):
    pass

class ScanAckFrame(KNMPFrame):
    """
        KNMP Scan ACK
        scan ack (protocol id: 0x0010)
        data length: 55 bytes
        frame length: 77 bytes
            --------------------------------------------------------------------------------------------------------
            DMAC                    SMAC                    FRAME LENGTH
            6 bytes                 6 bytes                 2 bytes
            --------------------------------------------------------------------------------------------------------
            DSAP                    SSAP                    CONTROL             OUIID           Protocol ID
            0xAA                    0xAA                    0x03                0x983000        0x0010
            --------------------------------------------------------------------------------------------------------
            Management ID           DHCP                    IP                  netmask         gateway
            4 bytes (manager)       1 byte (0x01 dhcp)      4 bytes             4 bytes         4 bytes
            --------------------------------------------------------------------------------------------------------
            VLAN                    device name             product name        CRC
            2 bytes                 16 bytes                16 bytes            4 bytes ( crc32(payload) )
            --------------------------------------------------------------------------------------------------------
    """
    def __init__(
        self, dest_mac=None, src_mac=None, mgmt_id=None, 
        flag=None, ip=None, netmask=None, gateway=None,
        vlan=None, device_name=None, product_name=None,
        raw=None
    ):
        """
            dest_mac    EUI compatible
            src_mac     EUI compatible
            mgmt_id     4 bytes
            flag (dhcp) 1 byte (lowest 1 bit: DHCP tag)
            ip          str or 32-bit int value
            netmask     str or 32-bit int value
            gateway     str or 32-bit int value
            vlan        2 bytes
            device_name    str, less than 16 characters
            product_name    str, less than 16 characters

            or just raw     str or [int] or KNMPFrame instance
        """
        if raw:
            if isinstance(raw, KNMPFrame):
                raw = KNMPFrame._raw
            super(ScanAckFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)
        else:
            protocol_id = self.PROTO_SCAN_ACK
            payload = self.build_payload(mgmt_id, flag, ip, netmask, gateway, 
                                         vlan, device_name, product_name)
            super(ScanAckFrame, self).__init__(dest_mac, src_mac, protocol_id, payload)



    def build_payload(self, mgmt_id, flag, ip, netmask, gateway, vlan, device_name, product_name):
        payload = []
        payload.extend(int_2_byte_array(mgmt_id, 4))
        payload.append(flag)
        payload.extend(ip_2_byte_array(ip))
        payload.extend(ip_2_byte_array(netmask))
        payload.extend(ip_2_byte_array(gateway))
        payload.extend(int_2_byte_array(vlan, 2))

        assert isinstance(device_name, (str, unicode))
        assert len(device_name) <= 15   # need last \0
        device_name = [ord(i) for i in device_name]
        payload.extend(
            device_name + [0] * (16 - len(device_name))
        )

        assert isinstance(product_name, (str, unicode))
        assert len(product_name) <= 15  # need last \0
        product_name = [ord(i) for i in product_name]
        payload.extend(
            product_name + [0] * (16 - len(product_name))
        )

        return payload


    def check(self, raise_exc=False):
        if not super(ScanAckFrame, self).check(raise_exc):
            return False
        try:
            if self.protocol_id != self.PROTO_SCAN_ACK:
                raise InvalidScanAckFrame, "protocol id (0x%0.4x) is not SCAN_ACK" % self.protocol_id

            if len(self) != 77:
                raise InvalidScanAckFrame, "The length of scan ack frame should be exactly 77, not %d" % len(self)

            return True
        except InvalidScanAckFrame as e:
            if raise_exc:
                raise e
            return False

    # mgmt_id     4 bytes
    @property
    def mgmt_id(self):
        return byte_array_2_int(self._raw[22:26])

    def set_mgmt_id(self, mgmt_id):
        assert isinstance(mgmt_id, int) and (mgmt_id >= 0 and mgmt_id <= 0xffffffff)
        self._raw[22:26] = int_2_byte_array(mgmt_id, 4)
        self.update_checksum()

    @property
    def flag(self):
        return self._raw[26]


    # flag (dhcp) 1 byte (lowest 1 bit: DHCP tag)
    @property
    def dhcp(self):
        return bool(self._raw[26] & 0x01)

    def set_dhcp(self, dhcp):
        if dhcp:
            self._raw[26] |= 0x01
        else:
            self._raw[26] &= 0xfe
        self.update_checksum()


    # ip          str or 32-bit int value
    @property
    def ip(self):
        return ip_pretty(self._raw[27:31])

    def set_ip(self, ip):
        self._raw[27:31] = ip_2_byte_array(ip)
        self.update_checksum()

    # netmask     str or 32-bit int value
    @property
    def netmask(self):
        return ip_pretty(self._raw[31:35])

    def set_netmask(self, netmask):
        self._raw[31:35] = ip_2_byte_array(netmask)
        self.update_checksum()

    # gateway     str or 32-bit int value
    @property
    def gateway(self):
        return ip_pretty(self._raw[35:39])

    def set_gateway(self, gateway):
        self._raw[35:39] = ip_2_byte_array(gateway)
        self.update_checksum()
    

    # vlan        2 bytes
    @property
    def vlan(self):
        return byte_array_2_int(self._raw[39:41])

    def set_vlan(self, vlan):
        assert isinstance(vlan, int) and (vlan >= 1 and vlan <= 4095)
        self._raw[39:41] = int_2_byte_array(vlan, 2)
        self.update_checksum()

    # device_name    str, less than 16 characters
    @property
    def device_name(self):
        name = ''.join([chr(i) for i in self._raw[41: 57]])
        return name.rstrip('\0')

    def set_device_name(self, device_name):
        assert isinstance(device_name, (str, unicode))
        assert len(device_name) <= 15
        self._raw[41:57] = str_2_byte_array(device_name, 16)
        self.update_checksum()

    # product_name    str, less than 16 characters
    @property
    def product_name(self):
        name = ''.join([chr(i) for i in self._raw[57: 73]])
        return name.rstrip('\0')

    def set_product_name(self, product_name):
        assert isinstance(product_name, str)
        # assert len(product_name) <= 15
        self._raw[57:73] = str_2_byte_array(product_name, 16)
        self.update_checksum()





#########################################
#    Config
#########################################
class ConfigBase(object):
    """
        macro specific to Config Frame.
    """
    # Config TLV
    CFG_TYPE_CMD = 0x01
    CFG_TYPE_END = 0xff

    CFG_TYPES = [
        CFG_TYPE_CMD,
        CFG_TYPE_END
    ]



class InvalidConfigItem(Exception):
    pass

class ConfigItem(ConfigBase):
    """
        TLV (means for binary format -> [8-bit int])
        type: 1 byte
        length: 1 byte
        value: length bytes

        TODO: make it list-like
    """


    def __init__(self, tlv=None, raw=None):
        """
            tlv -> (t, v) or (t, l, v)
            raw -> binary data(str or [8-bit int])
        """
        if tlv:
            assert isinstance(tlv, (tuple, list))
            if len(tlv) == 2:
                # t,v
                t,v = tlv
                l = len(v)
            elif len(tlv) == 3:
                # t, l, v
                t, l, v = tlv
            else:
                raise InvalidConfigItem, "wrong initiating value: %r" % tlv
        elif raw:
            raw = assure_bin_data(raw)
            t = raw[0]
            l = raw[1]
            v = raw[2:2+l]
        else:
            raise 
        self._raw = self.build_raw(t, l, v)

    __getitem__ = proxy_method('_raw', '__getitem__')
    __len__ = proxy_method('_raw', '__len__')
    __contains__ = proxy_method('_raw', '__contains__')
    __iter__ = proxy_method('_raw', '__iter__')

    def __str__(self):
        """
            return binary frame
        """
        return ''.join([chr(i) for i in self._raw[2:]])


    def __eq__(self, another):
        return self._raw == another._raw

    def __ne__(self, another):
        return self._raw != another._raw

    @property
    def raw(self):
        return self._raw



    @property
    def type(self):
        return self._raw[0]

    @property
    def length(self):
        return self._raw[1]

    @property
    def value(self):
        return self._raw[2:]


    @staticmethod
    def build_raw(t, l, v):
        """
            return a raw tlv data ([int])
            t: int
            l: int
            v: [8-bit int] or str
        """
        assert t in ConfigItem.CFG_TYPES
        assert l >= 0 and l <= 0xff
        v = assure_bin_data(v)
        assert len(v) <= l

        raw = []
        raw.append(t)
        raw.append(l)
        raw.extend(v)
        raw.extend([0] * (l - len(v)))

        return raw



class CmdConfig(ConfigItem):
    """
        Config type: CMD
        type: 0x01
        length: strlen(value) + 1
        value: device command
    """
    def __init__(self, cmd=None, tlv=None, raw=None):
        if cmd:
            assert isinstance(cmd, (str,unicode))
            if isinstance(cmd, unicode):
                cmd = cmd.encode('utf-8')
            if not cmd.endswith('\0'):
                cmd = cmd + '\0'
            tlv = (self.CFG_TYPE_CMD, len(cmd), cmd)

        super(CmdConfig, self).__init__(tlv=tlv, raw=raw)
        assert self.type == self.CFG_TYPE_CMD
        assert str(self).endswith('\0')



class EndConfig(ConfigItem):
    """
        Config type: END
        type: 0xff
        length: 1
        data: [0xff]
    """
    def __init__(self, tlv=None, raw=None):
        if tlv is None and raw is None:
            tlv = (self.CFG_TYPE_END, 1, [0xff])
        super(EndConfig, self).__init__(tlv=tlv, raw=raw)



class ConfigItems(ConfigBase):
    """
        Config frame, TLV part
        note:
            EndConfig should not be added manually.
    """

    CFG_TYPE_MAPPING = {
        ConfigBase.CFG_TYPE_CMD: CmdConfig,
        ConfigBase.CFG_TYPE_END: EndConfig
    }

    def __init__(self, items=None, raw=None):
        """
            items:
                [instances of ConfigItem] 
                or 
                just a instance of ConfigItem
        """
        self._items= []  # no EndConfig
        if items:
            self.extend(items)
        elif raw:
            raw = assure_bin_data(raw)

            while raw:
                t = raw[0]
                l = raw[1]
                v = raw[2:2+l]
                item = self.build_item((t, l, v))
                if isinstance(item, EndConfig):
                    break
                self._items.append(item)
                raw = raw[2+l:]

    @staticmethod
    def build_item(item):
        """
            build a ConfigItem
            item:
                instance of ConfigItem
                or
                tuple (t, l, v), or (t, v)
        """
        if isinstance(item, ConfigItem):
            return item

        if isinstance(item, tuple):
            assert len(item) in (2, 3)

            t = item[0]
            assert t in ConfigItems.CFG_TYPE_MAPPING
            item_type = ConfigItems.CFG_TYPE_MAPPING[t]
            return item_type(tlv=item)

        else:
            raise InvalidConfigItem, '%r' % item


    # @property
    # def items(self):
        # return self._items

    @property
    def raw(self):
        # append EndConfig()
        data = []
        for item in self._items + [EndConfig()]:
            data.extend(item.raw)

        return data


    def __setitem__(self, idx, items):
        if isinstance(items. list):
            # slice
            items = [self.build_item(i) for i in items]
            assert all([(not isinstance(i, EndConfig)) for i in items])
        else:
            items = self.build_item(items)
            assert not isinstance(items, EndConfig), "EndConfig is added automatically"
        self._items.__setitem__(idx, items)

    __getitem__ = proxy_method('_items', '__getitem__')
    __delitem__ = proxy_method('_items', '__delitem__')
    __iter__ = proxy_method('_items', '__iter__')
    __len__ = proxy_method('_items', '__len__')

    def __eq__(self, another):
        return self._items == another._items

    def __ne__(self, another):
        return self._items != another._items


    def append(self, item):
        item = self.build_item(item)
        assert item.type != self.CFG_TYPE_END, "EndConfig is added automatically"
        self._items.append(item)

    def extend(self, items):
        if isinstance(items, ConfigItems):
            self._items.extend(items._items)
        else:
            assert isinstance(items, list)
            for i in items:
                i = self.build_item(i)
                assert i.type != self.CFG_TYPE_END, "EndConfig is added automatically"
                self._items.append(i)





class InvalidConfigFrame(Exception):
    pass


class ConfigFrame(KNMPFrame, ConfigBase):
    """
        KNMP Config (protocol id: 0x0001)
        TLV type:
            0x01 - CMD
            0xff - end of TLV data; length: 1, data: 0xff

            --------------------------------------------------------------------------------------------------------
            DMAC                    SMAC                    FRAME LENGTH
            6 bytes                 6 bytes                 2 bytes
            --------------------------------------------------------------------------------------------------------
            DSAP                    SSAP                    CONTROL             OUIID           Protocol ID
            0xAA                    0xAA                    0x03                0x983000        0x0001
            --------------------------------------------------------------------------------------------------------
            Management ID           request id              TLV part
            4 bytes (manager)       2 bytes (request)       type:1 byte; length:1 byte; value: length bytes;
            --------------------------------------------------------------------------------------------------------
            filling                                         CRC
            0xff * n (n + 4 + 2 + len(tlv part) >= 34)      4 bytes ( crc32(data) )
            --------------------------------------------------------------------------------------------------------
    """
    def __init__(self, dest_mac=None, src_mac=None, 
                 mgmt_id=None, req_id=None, items=None, 
                 raw=None):

        if raw:
            if isinstance(raw, KNMPFrame):
                raw = KNMPFrame._raw
            super(ConfigFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)
        else:
            payload = self.build_payload(mgmt_id, req_id, items)
            super(ConfigFrame, self).__init__(dest_mac, src_mac, self.PROTO_CFG, payload)


    @staticmethod
    def build_payload(mgmt_id, req_id, items):
        payload = []
        payload.extend(int_2_byte_array(mgmt_id, 4))
        payload.extend(int_2_byte_array(req_id, 2))
        payload.extend(ConfigItems(items=items).raw)

        if len(payload) < 34:
            payload.extend([0xff] * (34 - len(payload)))

        return payload


    def check(self, raise_exc=False):
        if not super(ConfigFrame, self).check(raise_exc):
            return False

        try:
            if self.protocol_id != self.PROTO_CFG:
                raise InvalidConfigFrame, 'protocol_id (%0.2x) is not %0.2x' % (self.protocol_id, self.PROTO_CFG)
            self.get_items()
            return True
        except (InvalidConfigFrame, InvalidConfigItem) as e:
            if raise_exc:
                raise e
            return False



    @property
    def mgmt_id(self):
        return byte_array_2_int(self._raw[22:26])

    def set_mgmt_id(self, mgmt_id):
        assert isinstance(mgmt_id, int) and (mgmt_id >= 0 and mgmt_id <= 0xffffffff)
        self._raw[22:26] = int_2_byte_array(mgmt_id, 4)
        self.update_checksum()

    @property
    def req_id(self):
        return byte_array_2_int(self._raw[26:28])

    def set_req_id(self, req_id):
        assert isinstance(req_id, int) and req_id >=0 and req_id <= 0xffff
        self._raw[26:28] = int_2_byte_array(req_id, 2)
        self.update_checksum()


    def get_items(self):
        raw = self._raw[28:]
        return ConfigItems(raw=raw)

    @property
    def items(self):
        return self.get_items()

    def set_items(self, items):
        mgmt_id = self.mgmt_id
        req_id = self.req_id
        payload = self.build_payload(mgmt_id, req_id, items)
        self.set_payload(payload)



class InvalidConfigAckFrame(Exception):
    pass

class ConfigAckFrame(KNMPFrame):
    """
        KNMP Config ACK (protocol id: 0x0011)
            --------------------------------------------------------------------------------------------------------
            DMAC                    SMAC                    FRAME LENGTH
            6 bytes                 6 bytes                 2 bytes
            --------------------------------------------------------------------------------------------------------
            DSAP                    SSAP                    CONTROL             OUIID           Protocol ID
            0xAA                    0xAA                    0x03                0x983000        0x0011
            --------------------------------------------------------------------------------------------------------
            Management ID           request id              status/result
            4 bytes (manager)       2 bytes (request)       1 byte
            --------------------------------------------------------------------------------------------------------
            filling                 CRC
            0xff * 27               4 bytes ( crc32(data) )
            --------------------------------------------------------------------------------------------------------
            status:
                0x00 - success
                0x01 - failure
    """

    # Config status
    CFG_STAT_SUCCESS = 0x00
    CFG_STAT_FAILURE = 0x01
    CFG_STATS = [
        CFG_STAT_SUCCESS,
        CFG_STAT_FAILURE
    ]

    def __init__(self, dest_mac=None, src_mac=None, mgmt_id=None,
                 req_id=None, status=None, raw=None):
        if raw:
            if isinstance(raw, KNMPFrame):
                raw = KNMPFrame._raw
            super(ConfigAckFrame, self).__init__(raw=raw)
            self.check(raise_exc=True)
        else:
            payload = self.build_payload(mgmt_id, req_id, status)
            super(ConfigAckFrame, self).__init__(dest_mac, src_mac, self.PROTO_CFG_ACK, payload)

    @staticmethod
    def build_payload(mgmt_id, req_id, status):
        assert isinstance(status, int) and \
               status >= 0 and \
               status <= 0xff
        assert status in ConfigAckFrame.CFG_STATS
        payload = []
        payload.extend(int_2_byte_array(mgmt_id, 4))
        payload.extend(int_2_byte_array(req_id, 2))
        payload.append(status)
        payload.extend([0xff] * 27)

        return payload


    def check(self, raise_exc=False):
        if not super(ConfigAckFrame, self).check(raise_exc):
            return False

        try:
            if self.protocol_id != self.PROTO_CFG_ACK:
                raise InvalidConfigAckFrame, 'protocol_id (0x%0.2x) is not 0x%0.2x' % (self.protocol_id, self.PROTO_CFG_ACK)
            if self._raw[28] not in self.CFG_STATS:
                raise InvalidConfigAckFrame, 'wrong status (0x%x)' % self._raw[28]
            return True
        except InvalidConfigAckFrame as e:
            if raise_exc:
                raise e
            return False

    @property
    def mgmt_id(self):
        return byte_array_2_int(self._raw[22:26])

    def set_mgmt_id(self, mgmt_id):
        assert isinstance(mgmt_id, int) and (mgmt_id >= 0 and mgmt_id <= 0xffffffff)
        self._raw[22:26] = int_2_byte_array(mgmt_id, 4)
        self.update_checksum()

    @property
    def req_id(self):
        return byte_array_2_int(self._raw[26:28])

    def set_req_id(self, req_id):
        assert isinstance(req_id, int) and req_id >=0 and req_id <= 0xffff
        self._raw[26:28] = int_2_byte_array(req_id, 2)
        self.update_checksum()

    @property
    def status(self):
        return self._raw[28]

    def set_status(self, status):
        assert status in self.CFG_STATS
        self._raw[28] = status
        self.update_checksum()

    @property
    def success(self):
        return self.status == self.CFG_STAT_SUCCESS





if __name__ == '__main__':
    import unittest
    class TestKNMP(unittest.TestCase):
        def test_KNMPFrame(self):
            f = KNMPFrame(dest_mac='11-11-11-11-11-11', src_mac='22-22-22-22-22-22',
                          protocol_id=KNMPFrame.PROTO_SCAN, payload='a' * 55)
            self.assertEqual(f.dest_mac, EUI('11-11-11-11-11-11'))
            self.assertEqual(f.src_mac, EUI('22-22-22-22-22-22'))
            self.assertEqual(f.protocol_id, KNMPFrame.PROTO_SCAN)
            self.assertEqual(f.payload, [ord('a')] * 55)
            self.assertEqual(f.checksum, f.calculate_checksum(f.payload))
            f.set_payload('b' * 66)
            self.assertEqual(f.payload, [ord('b')] * 66)

            f2 = KNMPFrame(raw=str(f))
            self.assertEqual(f, f2)

        def test_ScanFrame(self):
            f = ScanFrame(src_mac='11-11-11-11-11-11', mgmt_id=0x11223344, topo_id=0x3344)
            self.assertEqual(f.mgmt_id, 0x11223344)
            f.set_mgmt_id(0xffffffff)
            self.assertEqual(f.mgmt_id, 0xffffffff)

            self.assertEqual(f.topo_id, 0x3344)
            f.set_topo_id(0xffff)
            self.assertEqual(f.topo_id, 0xffff)

            self.assertEqual(f.dest_mac, EUI(ScanFrame.PROBE_MAC))

            f2 = ScanFrame(raw=str(f))
            self.assertEqual(f, f2)

        def test_ScanAckFrame(self):
            # dest_mac=None, src_mac=None, mgmt_id=None, 
            # flag=None, ip=None, netmask=None, gateway=None,
            # vlan=None, device_name=None, product_name=None,
            # raw=None
            f = ScanAckFrame(dest_mac='11-11-11-11-11-11', src_mac='22-22-22-22-22-22',
                             mgmt_id=0x11223344, flag=0x01, ip='192.168.1.2',
                             netmask='255.255.255.0', gateway='192.168.1.1', vlan=33,
                             device_name='test_dev', product_name='KNS5000')

            self.assertEqual(f.mgmt_id, 0x11223344)
            f.set_mgmt_id(0xffffffff)
            self.assertEqual(f.mgmt_id, 0xffffffff)

            self.assertTrue(f.dhcp)
            f.set_dhcp(False)
            self.assertFalse(f.dhcp)

            self.assertEqual(f.ip, '192.168.1.2')
            f.set_ip('192.168.1.3')
            self.assertEqual(f.ip, '192.168.1.3')

            self.assertEqual(f.netmask, '255.255.255.0')
            f.set_netmask('255.255.0.0')
            self.assertEqual(f.netmask, '255.255.0.0')

            self.assertEqual(f.gateway, '192.168.1.1')
            f.set_gateway('192.168.0.1')
            self.assertEqual(f.gateway, '192.168.0.1')

            self.assertEqual(f.vlan, 33)
            f.set_vlan(99)
            self.assertEqual(f.vlan, 99)

            self.assertEqual(f.device_name, 'test_dev')
            f.set_device_name('test_device')
            self.assertEqual(f.device_name, 'test_device')

            self.assertEqual(f.product_name, 'KNS5000')
            f.set_product_name('KNS5001')
            self.assertEqual(f.product_name, 'KNS5001')

            f2 = ScanAckFrame(raw=str(f))
            self.assertEqual(f, f2)

        def test_ConfigFrame(self):
            # def __init__(self, dest_mac=None, src_mac=None, 
            #  mgmt_id=None, req_id=None, items=None, 
            #  raw=None):

            items = ConfigItems(items=[CmdConfig('ip config')])
            f = ConfigFrame(
                    dest_mac='11-11-11-11-11-11', 
                    src_mac='22-22-22-22-22-22',
                    mgmt_id=0x11223344,
                    req_id=0x1122,
                    items=items
                )
            self.assertEqual(f.mgmt_id, 0x11223344)
            self.assertEqual(f.req_id, 0x1122)
            self.assertEqual(f.items,items)

            f2 = ConfigFrame(raw=str(f))
            self.assertEqual(f, f2)


        def test_ConfigAckFrame(self):
            # def __init__(self, dest_mac, src_mac, mgmt_id=None,
            #              req_id=None, status=None, raw=None):
            f = ConfigAckFrame(
                    dest_mac='11-11-11-11-11-11',
                    src_mac='22-22-22-22-22-22',
                    mgmt_id=0x11223344,
                    req_id=0x1122,
                    status=ConfigAckFrame.CFG_STAT_SUCCESS
                )
            self.assertEqual(f.mgmt_id, 0x11223344)
            self.assertEqual(f.req_id, 0x1122)

            self.assertEqual(f.status, ConfigAckFrame.CFG_STAT_SUCCESS)
            f.set_status(ConfigAckFrame.CFG_STAT_FAILURE)
            self.assertEqual(f.status, ConfigAckFrame.CFG_STAT_FAILURE)

            f2 = ConfigAckFrame(raw=str(f))
            self.assertEqual(f, f2)


    unittest.main()

