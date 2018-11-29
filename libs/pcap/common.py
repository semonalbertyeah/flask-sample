# -*- coding:utf-8 -*-

from ctypes import *
import warnings


def iter_link_list(p, next='next'):
    """
        traverse c link list.
        such as:
            struct linkList{
                struct linkList * next; 
                int data;
            }
        l = iter_link_list(p, next='next')
        for d in l:
            print d.data
    """

    while p:
        yield p.contents
        p = getattr(p.contents, next)



# FILE from linux stdio.h
class FILE(Structure):
    pass


#############################
#   convert c FILE to python file object
# PyObject* PyFile_FromFile(
#     FILE *fp, 
#     char *name, 
#     char *mode, 
#     int (*close)(FILE*)
# );
#############################
CLOSE_FUNC = CFUNCTYPE(c_int, POINTER(FILE))
PyFile_FromFile = pythonapi.PyFile_FromFile
PyFile_FromFile.restype = py_object # ctypes.py_object
PyFile_FromFile.argtypes = [POINTER(FILE),
                            c_char_p,
                            c_char_p,
                            CLOSE_FUNC]



# time stamp
class timeval(Structure):
    _fields_ = [('tv_sec', c_long),
                ('tv_usec', c_long)]

    @property
    def microseconds(self):
        return self.tv_sec << 32 | self.tv_usec

    @property
    def seconds(self):
        return self.tv_sec


# packet dump header
class pcap_pkthdr(Structure):
    _fields_ = [('ts', timeval),
                ('caplen', c_uint),
                ('len', c_uint)]


# ip 地址结构体
from socket import (
    AF_INET, AF_INET6, AF_PACKET,
    ntohs, getnameinfo, inet_ntop
)


class sockaddr(Structure):
    _fields_ = [('sa_family', c_ushort),
                ('sa_data', c_char * 14)]

    @property
    def info(self):
        return {
            'family': self.sa_family,
            'data': self.sa_data
        }

    @property
    def exact_info(self):
        """
            if AF_INET or AF_INET6, return specific.
        """
        if self.sa_family == AF_INET:
            return cast(pointer(self), POINTER(sockaddr_in)).contents.info
        elif self.sa_family == AF_INET6:
            return cast(pointer(self), POINTER(sockaddr_in6)).contents.info
        elif self.sa_family == AF_PACKET:
            return cast(pointer(self), POINTER(sockaddr_ll)).contents.info     # mac address
        else:
            return self.info


# class S_un_b(Structure):
#     _fields_ = [("s_b1",c_ubyte),
#                 ("s_b2",c_ubyte),
#                 ("s_b3",c_ubyte),
#                 ("s_b4",c_ubyte)]


# class S_un_w(Structure):
#     _fields_ = [("s_wl",c_ushort),
#                 ("s_w2",c_ushort)]


# class S_un(Union):
#     _fields_ = [("S_un_b",S_un_b),
#                 ("S_un_w",S_un_w),
#                 ("S_addr",c_ulong)]


# class in_addr(Structure):
#     """
#         IP v4 address (in network byte order)
#     """
#     _fields_ = [("S_un",S_un)]

#     @property
#     def ip(self):
#         return "%d.%d.%d.%d" % (self.S_un.S_un_b.s_b1,
#                                 self.S_un.S_un_b.s_b2,
#                                 self.S_un.S_un_b.s_b3,
#                                 self.S_un.S_un_b.s_b4)



class sockaddr_in(Structure):
    """
       IPv4 info
    """
    _fields_ = [("sin_family", c_ushort),
                ("sin_port", c_ushort),
                # ("sin_addr", in_addr),
                ("sin_addr", c_byte * 4),
                ("sin_zero", c_char * 8)]

    @property
    def info(self):
        return {
            'family': self.sin_family,
            'port': self.sin_port,
            # 'ip': self.sin_addr.ip
            'addr': inet_ntop(AF_INET, self.sin_addr)
        }



# class _S6_un(Union):
#     _fields_=[("_S6_u8",c_ubyte *16),
#               ("_S6_u16",c_ushort *8),
#               ("_S6_u32",c_ulong *4)]


# class in6_addr(Structure):
#     """
#         IP v6 address (in network byte order)

#         128 bits divided into eight 16-bit blocks.
#     """
#     _fields_=[("_S6_un",_S6_un)]

#     @property
#     def ip(self):
#         return ':'.join(['%0.4x' % ntohs(i) for i in self._S6_un._S6_u16])


class sockaddr_in6(Structure):
    """
       IPv6 info 
    """
    _fields_=[("sin6_family",c_short),
              ("sin6_port",c_ushort),
              ("sin6_flowinfo",c_ulong),
              # ("sin6_addr",in6_addr),
              ("sin6_addr", c_byte * 16),
              ("sin6_scope_id",c_ulong)]

    @property
    def info(self):
        return {
            'family': self.sin6_family,
            'port': self.sin6_port,
            # 'ip': self.sin6_addr.ip,
            'addr': inet_ntop(AF_INET6, self.sin6_addr),
            'flowinfo': self.sin6_flowinfo,
            'scope_id': self.sin6_scope_id
        }


class sockaddr_ll(Structure):
    """
        MAC Address
    """
    _fields_ = [('ssl_family', c_ushort),
                ('ssl_protocol', c_ushort),
                ('ssl_ifindex', c_int),
                ('ssl_hatype', c_ushort),
                ('ssl_pkttype', c_ubyte),
                ('sll_halen', c_ubyte),
                ('sll_addr', c_ubyte * 8)]

    @property
    def info(self):
        return {
            'family': self.ssl_family,
            'protocol': self.ssl_protocol,
            'ifindex': self.ssl_ifindex,
            'hatype': self.ssl_hatype,
            'pkttype': self.ssl_pkttype,
            'halen': self.sll_halen,
            'addr': '-'.join('%02x' % i for i in self.sll_addr[:6])
        }





# 设备的 ip 地址信息
class pcap_addr(Structure):
    @property
    def info(self):
        addr = None
        sa_family = None
        if self.addr:
            addr_sa_family = sa_family = self.addr.contents.sa_family
            if addr_sa_family == AF_INET:
                addr = cast(self.addr, POINTER(sockaddr_in)).contents.info['addr']
            elif addr_sa_family == AF_INET6:
                addr = cast(self.addr, POINTER(sockaddr_in6)).contents.info['addr']
            else:
                warnings.warn("not supported sa_family for addr: %d" % addr_sa_family)

        netmask = None
        if self.netmask:
            netmask_sa_family = self.netmask.contents.sa_family
            if netmask_sa_family == AF_INET:
                netmask = cast(self.netmask, POINTER(sockaddr_in)).contents.info['addr']
            elif netmask_sa_family == AF_INET6:
                netmask = cast(self.netmask, POINTER(sockaddr_in6)).contents.info['addr']
            else:
                warnings.warn("not supported sa_family for netmask: %d" % netmask_sa_family)

        broadaddr = None
        if self.broadaddr:
            broadaddr_sa_family = self.broadaddr.contents.sa_family
            if broadaddr_sa_family == AF_INET:
                broadaddr = cast(self.broadaddr, POINTER(sockaddr_in)).contents.info['addr']
            elif broadaddr_sa_family == AF_INET6:
                broadaddr = cast(self.broadaddr, POINTER(sockaddr_in6)).contents.info['addr']
            else:
                warnings.warn("not supported sa_family for broadaddr: %d" % broadaddr_sa_family)

        dstaddr = None
        if self.dstaddr:
            dstaddr_sa_family = self.dstaddr.sa_family
            if dstaddr_sa_family == AF_INET:
                dstaddr = cast(self.dstaddr, POINTER(sockaddr_in)).contents.info['addr']
            elif dstaddr_sa_family == AF_INET6:
                dstaddr = cast(self.dstaddr, POINTER(sockaddr_in6)).contents.info['addr']
            else:
                warnings.warn("not supported sa_family for dstaddr: %d" % dstaddr_sa_family)

        return {
            'addr': addr,
            'netmask': netmask,
            'broadaddr': broadaddr,
            'dstaddr': dstaddr,
            'sa_family': sa_family
        }

pcap_addr._fields_ = [('next', POINTER(pcap_addr)),
            ('addr', POINTER(sockaddr)),
            ('netmask', POINTER(sockaddr)),
            ('broadaddr', POINTER(sockaddr)),
            ('dstaddr', POINTER(sockaddr))]



# item in a list of interfaces (pcap_findalldevs)

PCAP_IF_LOOPBACK = 0x00000001   # interface is loopback
PCAP_IF_UP = 0x00000002         # interface is up
PCAP_IF_RUNNING = 0x00000004    # interface is running/


class pcap_if(Structure):
    @property
    def info(self):
        addresses = []
        for addr in iter_link_list(self.addresses):
            if addr.info['addr']:
                addresses.append(addr.info)

        return {
            'next': self.next,
            'name': self.name,
            'description': self.description,
            'addresses': addresses,
            'loopback': bool(PCAP_IF_LOOPBACK & self.flags),
            'up': bool(PCAP_IF_UP & self.flags),
            'running': bool(PCAP_IF_RUNNING & self.flags)
        }

pcap_if._fields_ = [('next', POINTER(pcap_if)),
            ('name', c_char_p),
            ('description', c_char_p),
            ('addresses', POINTER(pcap_addr)),
            ('flags', c_uint)]
pcap_if_t = pcap_if


# remote user authentication
class pcap_rmtauth(Structure):
    _fields_ = [('type', c_int),
                ('username', c_char_p),
                ('password', c_char_p)]


# for filter
class bpf_insn(Structure):
    _fields_ = [('code', c_ushort),
                ('jt', c_ubyte),
                ('jf', c_ubyte),
                ('k', c_uint)]



class bpf_program(Structure):
    _fields_ = [('bf_len', c_uint),
                ('bf_insns', POINTER(bpf_insn))]



# struct pcap_stat {
#     u_int ps_recv;
#     u_int ps_drop;
#     u_int ps_ifdrop;
#
#     #ifdef WIN32
#     u_int bs_capt;
#     #endif /* WIN32 */
# };
class pcap_stat(Structure):
    _fields_ = [("ps_recv", c_uint),
                ("ps_drop", c_uint),
                ("ps_ifdrop", c_uint)]



############################
# typedef enum {
#        PCAP_D_INOUT = 0,
#        PCAP_D_IN,
#        PCAP_D_OUT
# } pcap_direction_t;
############################
pcap_direction_t = c_int
PCAP_D_INOUT = 0
PCAP_D_IN = 1
PCAP_D_OUT = 2


# pcap struct
p_pcap_t = c_void_p
p_pcap_dumper_t = c_void_p
size_t = c_uint




PCAP_ERRBUF_SIZE = 256                              # fromd 'pcap.h'

PCAP_SRC_IF_STRING = 'rpcap://'                 

PCAP_OPENFLAG_PROMISCUOUS = 1                       # from remote-ext.h,  混杂模式
PCAP_OPENFLAG_DATATX_UDP = 2
PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4
PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8
PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16

PCAP_IF_LOOPBACK = 0x01                             # pcap_if_t-> flags, 是否为loopback端口



PCAP_HANDLER = CFUNCTYPE(None,                 # reutrn void
                         POINTER(c_ubyte),     # user
                         POINTER(pcap_pkthdr), # pkt_header
                         POINTER(c_ubyte))     # pkt_data


