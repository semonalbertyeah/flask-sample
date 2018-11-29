# -*- coding:utf-8 -*-

"""
    SNAP (Subnetwork Access Protocol) utilities

    format:
        DMAC        SMAC        FRAME LENGTH
        6 octets    6 octets    2 octets
        ---------------------------------------------------------------
        DSAP        SSAP        Control         OUI         Protocol ID
        1 octet     1 octet     1  octet        3 octets    2 octets
        ---------------------------------------------------------------
        DATA
        n octest
"""

from ctypes import c_ubyte
from netaddr import EUI

from utils.func import proxy_method
from utils.data import *
# from utils.proxy import ListProxy



# def int_2_byte_array(value, width):
#     """
#         convert integer value to array of ubyte
#         input:
#             value -> integer
#             width -> length of value (in bytes)
#     """
#     arr = []
#     for i in xrange(width):
#         arr.append(value & 0xff)
#         value = (value >> 8)

#     arr.reverse()
#     return arr


# def byte_array_2_int(arr):
#     value = 0
#     for i in arr:
#         assert isinstance(i, int)
#         value = (value << 8) | i

#     return value


# def assure_bin_data(data):
#     """
#         assure that "data" is available binary data.
#         bin data:
#             str
#             or
#             list of 8-bit integers
#     """
#     if isinstance(data, str):
#         data = [ord(i) for i in data]
#     assert isinstance(data, list)
#     assert all([isinstance(i, int) for i in data])
#     assert all([(i >= 0 and i <= 0xff) for i in data])

#     return data




class SnapError(Exception):
    pass

class SnapErrInvalid(SnapError):
    """
        not a snap frame
    """
    pass





class SnapFrame(object):
    """
        SNAP frame, without CRC as most NICs will calculate it automatically.
        frame format:
            DMAC        SMAC        FRAME LENGTH
            6 octets    6 octets    2 octets
            ---------------------------------------------------------------
            DSAP        SSAP        Control         OUI         Protocol ID
            1 octet     1 octet     1  octet        3 octets    2 octets
            ---------------------------------------------------------------
            DATA
            n octest

        usage:
            frame = SnapFrame(
                '11:22:33:44:55:66', 
                '22:33:44:55:66:77',
                0x983000,
                0x00ff,
                "whatever the data is."
            )
    """

    DSAP = 0xaa
    SSAP = 0xaa
    CTRL = 0x03

    # ethernet header: DMAC (6 bytes), SMAC (6 bytes), FRAME LENGTH (2 bytes)
    ETHER_HEADER_LEN = 14   
    # SNAP header: DSAP (1 byte), SSAP (1 byte), Control (1 byte), OUI (3 bytes), Protocol ID (2 bytes)
    SNAP_HEADER_LEN = 8     

    MIN_ETHER_PAYLOAD_LEN = 46
    MAX_ETHER_PAYLOAD_LEN = 1500

    MIN_DATA_LEN = MIN_ETHER_PAYLOAD_LEN - SNAP_HEADER_LEN
    MAX_DATA_LEN = MAX_ETHER_PAYLOAD_LEN - SNAP_HEADER_LEN

    MIN_FRAME_LEN = MIN_ETHER_PAYLOAD_LEN + ETHER_HEADER_LEN
    MAX_FRAME_LEN = MAX_ETHER_PAYLOAD_LEN + ETHER_HEADER_LEN

    def __init__(self, dest_mac=None, src_mac=None, ouiid=None, 
                 protocol_id=None, data=None, raw=None):
        if raw:
            raw = assure_bin_data(raw)
            self.parse_frame(raw)
            self._raw = raw

        else:
            self._raw = self.build_raw(
                dest_mac,
                src_mac,
                ouiid,
                protocol_id,
                data
            )

        # self._data = ListProxy(self, start=22)


    @staticmethod
    def parse_frame(frame):
        """
            get SnapFrame info from raw.
            input:
                frame -> str, [int]
        """
        frame = assure_bin_data(frame)

        raw_len = len(frame)
        if raw_len < SnapFrame.MIN_FRAME_LEN: 
            raise SnapErrInvalid, 'frame length (0x%0.4x) is smaller than minimum ethernet frame size (0x%0.4x)' % (raw_len, SnapFrame.MIN_FRAME_LEN)
        if raw_len > SnapFrame.MAX_FRAME_LEN:
            raise SnapErrInvalid, 'frame length (0x%0.4x) is larger than maximum ethernet frame size (0x%0.4x)' % (raw_len, SnapFrame.MAX_FRAME_LEN)

        # dest_mac = EUI(frame[0] << 40 | frame[1] << 32 | frame[2] << 24 | frame[3] << 16 | frame[4] << 8 | frame[5])
        # src_mac = EUI(frame[6] << 40 | frame[7] << 32 | frame[8] << 24 | frame[9] << 16 | frame[10] << 8 | frame[11])
        dest_mac = EUI(
            byte_array_2_int(frame[0:6])
        )
        src_mac = EUI(
            byte_array_2_int(frame[6:12])
        )


        # frame_len = frame[12] << 8 | frame[13]
        frame_len = byte_array_2_int(frame[12:14])
        if frame_len > SnapFrame.MAX_ETHER_PAYLOAD_LEN:
            if frame_len >= 0x0800:
                raise SnapErrInvalid, "frame_len(0x%0.4x) >= 0x0800, which means it's an Ethernet frame." % frame_len
            else:
                raise SnapErrInvalid, "frame_len(0x%0.4x), is not valid" % frame_len

        # 0xaa, 0xaa, 0x03 -> snap
        dsap, ssap, ctrl = frame[14:17]
        if dsap != SnapFrame.DSAP:
            raise SnapErrInvalid, 'wrong dsap(%0.2x), maybe not a snap frame' % dsap
        if ssap != SnapFrame.SSAP:
            raise SnapErrInvalid, 'wrong ssap(%0.2x), maybe not a snap frame' % ssap
        if ctrl != SnapFrame.CTRL:
            raise SnapErrInvalid, 'wrong control(%0.2x), maybe not a snap frame' % ctrl

        # ouiid = frame[17] << 16 | frame[18] << 8 | frame[19]
        ouiid = byte_array_2_int(frame[17:20])

        # protocol_id = frame[20] << 8 | frame[21]
        protocol_id = byte_array_2_int(frame[20:22])

        # data = frame[14: 14+frame_len][8:]
        data = frame[22:]

        return dest_mac, src_mac, ouiid, protocol_id, data


    @staticmethod
    def build_raw(dest_mac, src_mac, ouiid, protocol_id, data):
        """
            build a raw(in list format) snap frame
            input:
                dest_mac, src_mac: should be compatible with netaddr.EUI
                ouiid: a 3-octet integer (be aware of the range)
                protocol_id: 2-octet integer
                data: 
                    [int] whose members are 8-bit values
                    or
                    str
        """

        dest_mac = EUI(dest_mac)
        src_mac = EUI(src_mac)

        assert ouiid >= 0 and ouiid <= 0xffffff
        assert protocol_id >= 0 and protocol_id <= 0xffff

        data = assure_bin_data(data)

        frame = []

        data_len = len(data)
        frame_len = data_len + 22    # length of ether frame
        frame_payload_len = data_len + 8    # length of ether frame data

        frame.extend(dest_mac.words)
        frame.extend(src_mac.words)
        frame.extend([(frame_payload_len & 0xff00) >> 8, frame_payload_len & 0xff])
        frame.extend([SnapFrame.DSAP, SnapFrame.SSAP, SnapFrame.CTRL])
        frame.extend([(ouiid  & 0xff0000) >> 16, (ouiid & 0xff00) >> 8, ouiid & 0xff])
        frame.extend([(protocol_id & 0xff00) >> 8, protocol_id & 0xff])
        frame.extend(data)

        assert len(frame) == frame_len

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
    # ether_len [12:14]
    ####################
    @property
    def ether_len(self):
        # return (self._raw[12] << 8) | self._raw[13]
        return byte_array_2_int(self._raw[12:14])


    ####################
    # dsap, ssa, ctrl [14:17]
    ####################


    ####################
    # ouiid [17:20]
    ####################
    @property
    def ouiid(self):
        return byte_array_2_int(self._raw[17:20])

    def set_ouiid(self, value):
        """
            change OUI ID of snap frame
            value: 16-bit int value
        """
        value = int(value)
        assert value >= 0 and value <= 0xffffff
        self._raw[17:20] = int_2_byte_array(value, 3)

    @ouiid.setter
    def ouiid(self, value):
        self.set_ouiid(value)


    ####################
    # protocol_id [20:22]
    ####################
    @property
    def protocol_id(self):
        return byte_array_2_int(self._raw[20:22])

    def set_protocol_id(self, value):
        """
            change Protocol Id
            value: 24-bit int value
        """
        value = int(value)
        assert value >= 0 and value <= 0xffff
        self._raw[20:22] = int_2_byte_array(value, 2)

    @protocol_id.setter
    def protocol_id(self, value):
        self.set_protocol_id(value)


    ####################
    # data [22:]
    ####################
    @property
    def data(self):
        return self._raw[22:]

    def set_data(self, value):
        """
            change data of snap frame (ether_len will be updated)
            input:
                value: str or [8-bit int value]
        """
        value = assure_bin_data(value)

        new_data_len = len(value)
        assert new_data_len >= self.MIN_DATA_LEN and new_data_len <= self.MAX_DATA_LEN

        new_ether_payload_len = new_data_len + self.SNAP_HEADER_LEN
        self._raw = self._raw[:22] + value
        self._raw[12:14] = int_2_byte_array(new_ether_payload_len, 2)

    @data.setter
    def data(self, value):
        self.set_data(value)



if __name__ == '__main__':
    import unittest
    class TestSnapFrame(unittest.TestCase):
        def test_basic(self):
            f = SnapFrame(dest_mac='11-11-11-11-11-11', src_mac='22-22-22-22-22-22', 
                          ouiid=0x112233, protocol_id=0x3344, data='a' * 55)
            self.assertEqual(f.dest_mac, EUI('11-11-11-11-11-11'))
            f.set_dest_mac('33-33-33-33-33-33')
            self.assertEqual(f.dest_mac, EUI('33-33-33-33-33-33'))

            self.assertEqual(f.src_mac, EUI('22-22-22-22-22-22'))
            f.set_src_mac('44-44-44-44-44-44')
            self.assertEqual(f.src_mac, EUI('44-44-44-44-44-44'))

            self.assertEqual(f.ouiid, 0x112233)
            f.set_ouiid(0xffffff)
            self.assertEqual(f.ouiid, 0xffffff)

            self.assertEqual(f.protocol_id, 0x3344)
            f.set_protocol_id(0xffff)
            self.assertEqual(f.protocol_id, 0xffff)

            self.assertEqual(f.data, [ord('a')] * 55)
            f.set_data('b'* 66)
            self.assertEqual(f.data, [ord('b')] * 66)

            f2 = SnapFrame(raw=str(f))
            self.assertEqual(f, f2)



    unittest.main()

