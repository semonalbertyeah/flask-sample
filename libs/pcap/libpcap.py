# -*- coding:utf-8 -*-


import warnings
from ctypes import *
import ctypes.util


from .common import *


# _lib = CDLL('wpcap.dll')
_lib = cdll.LoadLibrary(ctypes.util.find_library('pcap'))




##############################################
# pcap_t* pcap_open_live(const char *device,
#         int     snaplen,
#         int     promisc,
#         int     to_ms,
#         char *  ebuf     
# )
##############################################
pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype = p_pcap_t
pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]




###############################
# pcap_t* pcap_open_dead(
#     int linktype, 
#     int snaplen
# )
###############################
pcap_open_dead = _lib.pcap_open_dead
pcap_open_dead.restype = p_pcap_t
pcap_open_dead.argtypes = [c_int, c_int]




##############################
# pcap_t* pcap_open_offline(
#     const char *fname, 
#     char *errbuf
# );
##############################
pcap_open_offline = _lib.pcap_open_offline
pcap_open_offline.restype = p_pcap_t
pcap_open_offline.argtypes = [c_char_p, c_char_p]




##################################
# pcap_dumper_t* pcap_dump_open(
#     pcap_t *p, 
#     const char *fname
# );
##################################
pcap_dump_open = _lib.pcap_dump_open
pcap_dump_open.restype = p_pcap_dumper_t
pcap_dump_open.argtypes = [p_pcap_t, c_char_p]







############################
# int pcap_setnonblock(
#     pcap_t *p, 
#     int nonblock, 
#     char *errbuf
# );
############################
pcap_setnonblock = _lib.pcap_setnonblock
pcap_setnonblock.restype = c_int
pcap_setnonblock.argtypes = [p_pcap_t, c_int, c_char_p]





##########################
# int pcap_getnonblock(
#     pcap_t *p, 
#     char *errbuf
# );
##########################
pcap_getnonblock = _lib.pcap_getnonblock
pcap_getnonblock.restype = c_int
pcap_getnonblock.argtypes = [p_pcap_t, c_char_p]





#############################
# int pcap_findalldevs(
#     pcap_if_t **alldevsp, 
#     char *errbuf
# )
#############################
pcap_findalldevs = _lib.pcap_findalldevs
pcap_findalldevs.restype = c_int
pcap_findalldevs.argtypes=  [POINTER(POINTER(pcap_if_t)),   # alldevsp
                             c_char_p]                      # errbuff





##############################
# void pcap_freealldevs(
#     pcap_if_t *alldevsp
# );
##############################
pcap_freealldevs = _lib.pcap_freealldevs
pcap_freealldevs.restype = None
pcap_freealldevs.argtypes = [POINTER(pcap_if_t)]    # alldevsp





#########################
# char* pcap_lookupdev(
#     char *errbuf
# );
#########################
pcap_lookupdev = _lib.pcap_lookupdev
pcap_lookupdev.restype = c_char_p
pcap_lookupdev.argtypes = [c_char_p]





#############################
# int pcap_lookupnet(
#     const char *device, 
#     bpf_u_int32 *netp, 
#     bpf_u_int32 *maskp, 
#     char *errbuf
# );
#############################
pcap_lookupnet = _lib.pcap_lookupnet
pcap_lookupnet.restype = c_int
pcap_lookupnet.argtypes = [c_char_p, 
                           POINTER(c_uint32), 
                           POINTER(c_uint32),
                           c_char_p]





#############################
# int pcap_dispatch(
#     pcap_t *p, 
#     int cnt, 
#     PCAP_HANDLER callback, 
#     u_char *user
# );
#############################
pcap_dispatch = _lib.pcap_dispatch
pcap_dispatch.restype = c_int
pcap_dispatch.argtypes = [p_pcap_t, 
                          c_int, 
                          PCAP_HANDLER, 
                          POINTER(c_ubyte)]





################################
# int pcap_loop(
#     pcap_t *p, 
#     int cnt, 
#     PCAP_HANDLER callback, 
#     u_char *user
# );
################################
pcap_loop = _lib.pcap_loop
pcap_loop.restype = c_int
pcap_loop.argtypes = [p_pcap_t,             # pcap_t
                      c_int,                # cnt
                      PCAP_HANDLER,         # callback
                      POINTER(c_ubyte)]     # user





##############################
# u_char* pcap_next(
#     pcap_t *p, 
#     struct pcap_pkthdr *h
# );
##############################
pcap_next = _lib.pcap_next
pcap_next.restype = POINTER(c_ubyte)
pcap_next.argtypes = [p_pcap_t, POINTER(pcap_pkthdr)]





#########################################
# int pcap_next_ex(
#     pcap_t *p, 
#     struct pcap_pkthdr **pkt_header, 
#     const u_char **pkt_data
# );
#########################################
pcap_next_ex = _lib.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [p_pcap_t,                          # pcap_t
                         POINTER(POINTER(pcap_pkthdr)),     # pkt_header
                         POINTER(POINTER(c_ubyte))]         # pkt_data




###################################
# void pcap_breakloop(
#     pcap_t *
# );
###################################
pcap_breakloop = _lib.pcap_breakloop
pcap_breakloop.restype = None
pcap_breakloop.argtypes = [p_pcap_t]    # pcap_t




#############################
# int pcap_sendpacket(
#     pcap_t *p, 
#     u_char *buf, 
#     int size
# );
#############################
pcap_sendpacket = _lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [p_pcap_t,           # pcap_t
                            POINTER(c_ubyte),   # buf
                            c_int]              # size


####################################
# void pcap_dump(
#     u_char *user, 
#     const struct pcap_pkthdr *h, 
#     const u_char *sp
# );
####################################
pcap_dump = _lib.pcap_dump
pcap_dump.restype = None
pcap_dump.argtypes = [POINTER(c_ubyte), 
                      POINTER(pcap_pkthdr), 
                      POINTER(c_ubyte)]


#########################
# long pcap_dump_ftell(
#     pcap_dumper_t *
# );
#########################
pcap_dump_ftell = _lib.pcap_dump_ftell
pcap_dump_ftell.restype = c_long
pcap_dump_ftell.argtypes = [p_pcap_dumper_t]




########################
# int pcap_compile(
#     pcap_t *p, 
#     struct bpf_program *fp,
#     const char *str, 
#     int optimize, 
#     bpf_u_int32 netmask
# );
########################
pcap_compile = _lib.pcap_compile
pcap_compile.restype = c_int
pcap_compile.argtypes = [p_pcap_t,              # pcap_t
                         POINTER(bpf_program),  # fp
                         c_char_p,              # str
                         c_int,                 # optimize
                         c_uint]                # netmask



#####################################
# int pcap_compile_nopcap(
#     int snaplen_arg, 
#     int linktype_arg, 
#     struct bpf_program *program, 
#     char *buf, 
#     int optimize, 
#     bpf_u_int32 mask
# );
#####################################
pcap_compile_nopcap = _lib.pcap_compile_nopcap
pcap_compile_nopcap.restype = c_int
pcap_compile_nopcap.argtypes = [c_int, 
                                c_int, 
                                POINTER(bpf_program),
                                c_char_p,
                                c_int,
                                c_uint32]




###################################
# int pcap_setfilter(
#     pcap_t *p, 
#     struct bpf_program *fp
# );
###################################
pcap_setfilter = _lib.pcap_setfilter
pcap_setfilter.restype = c_int
pcap_setfilter.argtypes = [p_pcap_t,                # pcap_t
                           POINTER(bpf_program)]    # fp




##############################
# int pcap_setfilter(
#     pcap_t *p, 
#     struct bpf_program *fp
# );
##############################
pcap_freecode = _lib.pcap_freecode
pcap_freecode.restype = None
pcap_freecode.argtypes = [POINTER(bpf_program)]




######################
# int pcap_datalink(
#     pcap_t *p
# );
######################
pcap_datalink = _lib.pcap_datalink
pcap_datalink.restype = c_int
pcap_datalink.argtypes = [p_pcap_t]



#############################
# int pcap_list_datalinks(
#     pcap_t *p, 
#     int **dlt_buf
# );
#############################
pcap_list_datalinks = _lib.pcap_list_datalinks
pcap_list_datalinks.restype = c_int
pcap_list_datalinks.argtypes = [p_pcap_t, 
                                POINTER(POINTER(c_int))]



#############################
# int pcap_set_datalink(
#     pcap_t *p, 
#     int dlt
# );
#############################
pcap_set_datalink = _lib.pcap_set_datalink
pcap_set_datalink.restype = c_int
pcap_set_datalink.argtypes = [p_pcap_t, c_int]



###################################
# int pcap_datalink_name_to_val(
#     const char *name
# );
###################################
pcap_datalink_name_to_val = _lib.pcap_datalink_name_to_val
pcap_datalink_name_to_val.restype = c_int
pcap_datalink_name_to_val.argtypes = [c_char_p]



##########################################
# const char* pcap_datalink_val_to_name(
#     int dlt
# );
##########################################
pcap_datalink_val_to_name = _lib.pcap_datalink_val_to_name
pcap_datalink_val_to_name.restype = c_char_p
pcap_datalink_val_to_name.argtypes = [c_int]




###################################################
# const char* pcap_datalink_val_to_description(
#     int dlt
# );
###################################################
pcap_datalink_val_to_description = _lib.pcap_datalink_val_to_description
pcap_datalink_val_to_description.restype = c_char_p
pcap_datalink_val_to_description.argtypes = [c_int]



########################
# int pcap_snapshot(
#     pcap_t *p
# );
########################
pcap_snapshot = _lib.pcap_snapshot
pcap_snapshot.restype = c_int
pcap_snapshot.argtypes = [p_pcap_t]



#########################
# int pcap_is_swapped(
#     pcap_t *p
# );
#########################
pcap_is_swapped = _lib.pcap_is_swapped
pcap_is_swapped.restype = c_int
pcap_is_swapped.argtypes = [p_pcap_t]



#############################
# int pcap_major_version(
#     pcap_t *p
# );
#############################
pcap_major_version = _lib.pcap_major_version
pcap_major_version.restype = c_int
pcap_major_version.argtypes = [p_pcap_t]



#############################
# int pcap_minor_version(
#     pcap_t *p
# );
#############################
pcap_minor_version = _lib.pcap_minor_version
pcap_minor_version.restype = c_int
pcap_minor_version.argtypes = [p_pcap_t]




######################
# FILE* pcap_file(
#     pcap_t *p
# );
######################
pcap_file = _lib.pcap_file
pcap_file.restype = POINTER(FILE)
pcap_file.argtypes = [p_pcap_t]



############################
# int pcap_stats(
#     pcap_t *p, 
#     struct pcap_stat *ps
# );
############################
pcap_stats = _lib.pcap_stats
pcap_stats.restype = c_int
pcap_stats.argtypes = [p_pcap_t, POINTER(pcap_stat)]



########################
# void pcap_perror(
#     pcap_t *p, 
#     char *prefix
# );
########################
pcap_perror = _lib.pcap_perror
pcap_perror.restype = None
pcap_perror.argtypes = [p_pcap_t, c_char_p]




###################################
# char* pcap_geterr(
#     pcap_t *p
# )
###################################
pcap_geterr = _lib.pcap_geterr
pcap_geterr.restype = c_char_p
pcap_geterr.argtypes = [p_pcap_t]   # pcap_t





########################
# char* pcap_strerror(
#     int error
# );
########################
pcap_strerror = _lib.pcap_strerror
pcap_strerror.restype = c_char_p
pcap_strerror.argtypes = [c_int]




################################
# const char* pcap_lib_version(
#     void
# );
################################
pcap_lib_version = _lib.pcap_lib_version
pcap_lib_version.restype = c_char_p
pcap_lib_version.argtypes = []




#####################
# void pcap_close(
#     pcap_t *p
# );
#####################
pcap_close = _lib.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [p_pcap_t]    # pcap_t



#############################
# FILE* pcap_dump_file(
#     pcap_dumper_t *p
# );
#############################
pcap_dump_file = _lib.pcap_dump_file
pcap_dump_file.restype = POINTER(FILE)
pcap_dump_file.argtypes = [p_pcap_dumper_t]




########################
# int pcap_dump_flush(
#     pcap_dumper_t *p
# );
########################
pcap_dump_flush = _lib.pcap_dump_flush
pcap_dump_flush.restype = c_int
pcap_dump_flush.argtypes = [p_pcap_dumper_t]





#########################
# void pcap_dump_close(
#     pcap_dumper_t *p
# );
#########################
pcap_dump_close = _lib.pcap_dump_close
pcap_dump_close.restype = None
pcap_dump_close.argtypes = [p_pcap_dumper_t]



####################
# int pcap_activate(
#     pcap_t *p
# );
####################
pcap_activate  = _lib.pcap_activate
pcap_activate.restype = c_int
pcap_activate.argtypes = [p_pcap_t]



############################
# int pcap_can_set_rfmon(
#     pcap_t *p
# );
############################
pcap_can_set_rfmon = _lib.pcap_can_set_rfmon
pcap_can_set_rfmon.restype = c_int
pcap_can_set_rfmon.argtypes = [p_pcap_t]



##############################
# pcap_t *pcap_create(
#     const char *source, 
#     char *errbuf
# );
##############################
pcap_create = _lib.pcap_create
pcap_create.restype = p_pcap_t
pcap_create.argtypes = [c_char_p, c_char_p]




#####################
# int pcap_fileno(
#     pcap_t *p
# );
#####################
pcap_fileno = _lib.pcap_fileno
pcap_fileno.restype = c_int
pcap_fileno.argtypes = [p_pcap_t]





###############################
# int pcap_get_selectable_fd(
#     pcap_t *p
# );
###############################
pcap_get_selectable_fd = _lib.pcap_get_selectable_fd
pcap_get_selectable_fd.restype = c_int
pcap_get_selectable_fd.argtypes = [p_pcap_t]




##################################
# int pcap_get_tstamp_precision(
#     pcap_t *p
# );
##################################
pcap_get_tstamp_precision = _lib.pcap_get_tstamp_precision
pcap_get_tstamp_precision.restype = c_int
pcap_get_tstamp_precision.argtypes = [p_pcap_t]




##########################
# int pcap_inject(
#     pcap_t *p, 
#     const void *buf, 
#     size_t size
# );
##########################
pcap_inject = _lib.pcap_inject
pcap_inject.restype = c_int
pcap_inject.argtypes = [p_pcap_t, c_void_p, size_t]




############################
# void pcap_free_datalinks(
#     int *dlt_list
# );
############################
pcap_free_datalinks = _lib.pcap_free_datalinks
pcap_free_datalinks.restype = None
pcap_free_datalinks.argtypes = [POINTER(c_int)]




##############################
# int pcap_list_tstamp_types(
#     pcap_t *p, 
#     int **tstamp_typesp
# );
##############################
pcap_list_tstamp_types = _lib.pcap_list_tstamp_types
pcap_list_tstamp_types.restype = c_int
pcap_list_tstamp_types.argtypes = [p_pcap_t, POINTER(POINTER(c_int))]



##############################
# void pcap_free_tstamp_types(
#     int *tstamp_types
# );
##############################
pcap_free_tstamp_types = _lib.pcap_free_tstamp_types
pcap_free_tstamp_types.restype = None
pcap_free_tstamp_types.argtypes = [POINTER(c_int)]





#####################################
# int pcap_offline_filter(
#     const struct bpf_program *fp,
#     const struct pcap_pkthdr *h, 
#     const u_char *pkt
# );
#####################################
pcap_offline_filter = _lib.pcap_offline_filter
pcap_offline_filter.restype = c_int
pcap_offline_filter.argtypes = [POINTER(bpf_program), 
                                POINTER(pcap_pkthdr),
                                POINTER(c_ubyte)]



##################################
# int pcap_set_buffer_size(
#     pcap_t *p, 
#     int buffer_size
# );
##################################
pcap_set_buffer_size = _lib.pcap_set_buffer_size
pcap_set_buffer_size.restype = c_int
pcap_set_buffer_size.argtypes = [p_pcap_t, c_int]





################################
# int pcap_set_immediate_mode(
#     pcap_t *p, 
#     int immediate_mode
# );
################################
pcap_set_immediate_mode = _lib.pcap_set_immediate_mode
pcap_set_immediate_mode.restype = c_int
pcap_set_immediate_mode.argtypes = [p_pcap_t, c_int]




###########################
# int pcap_set_promisc(
#     pcap_t *p, 
#     int promisc
# );
###########################
pcap_set_promisc = _lib.pcap_set_promisc
pcap_set_promisc.restype = c_int
pcap_set_promisc.argtypes = [p_pcap_t, c_int]





#########################
# int pcap_set_rfmon(
#     pcap_t *p, 
#     int rfmon
# );
#########################
pcap_set_rfmon = _lib.pcap_set_rfmon
pcap_set_rfmon.restype = c_int
pcap_set_rfmon.argtypes = [p_pcap_t, c_int]



###########################
# int pcap_set_snaplen(
#     pcap_t *p, 
#     int snaplen
# );
###########################
pcap_set_snaplen = _lib.pcap_set_snaplen
pcap_set_snaplen.restype = c_int
pcap_set_snaplen.argtypes = [p_pcap_t, c_int]



###########################
# int pcap_set_timeout(
#     pcap_t *p, 
#     int to_ms
# );
###########################
pcap_set_timeout = _lib.pcap_set_timeout
pcap_set_timeout.restype = c_int
pcap_set_timeout.argtypes = [p_pcap_t, c_int]




###################################
# int pcap_set_tstamp_precision(
#     pcap_t *p, 
#     int tstamp_precision
# );
###################################
pcap_set_tstamp_precision = _lib.pcap_set_tstamp_precision
pcap_set_tstamp_precision.restype = c_int
pcap_set_tstamp_precision.argtypes = [p_pcap_t, c_int]



#############################
# int pcap_set_tstamp_type(
#     pcap_t *p, 
#     int tstamp_type
# );
#############################
pcap_set_tstamp_type = _lib.pcap_set_tstamp_type
pcap_set_tstamp_type.restype = c_int
pcap_set_tstamp_type.argtypes = [p_pcap_t, c_int]



###########################
# int pcap_setdirection(
#     pcap_t *p, 
#     pcap_direction_t d
# );
###########################
pcap_setdirection = _lib.pcap_setdirection
pcap_setdirection.restype = c_int
pcap_setdirection.argtypes = [p_pcap_t, pcap_direction_t]





################################
# const char *pcap_statustostr(
#     int error
# );
################################
pcap_statustostr = _lib.pcap_statustostr
pcap_statustostr.restype = c_char_p
pcap_statustostr.argtypes = [c_int]





#####################################
# int pcap_tstamp_type_name_to_val(
#     const char *name
# );
#####################################
pcap_tstamp_type_name_to_val = _lib.pcap_tstamp_type_name_to_val
pcap_tstamp_type_name_to_val.restype = c_int
pcap_tstamp_type_name_to_val.argtypes = [c_char_p]




##############################################
# const char *pcap_tstamp_type_val_to_name(
#     int tstamp_type
# );
##############################################
pcap_tstamp_type_val_to_name = _lib.pcap_tstamp_type_val_to_name
pcap_tstamp_type_val_to_name.restype = c_char_p
pcap_tstamp_type_val_to_name.argtypes = [c_int]




#####################################################
# const char *pcap_tstamp_type_val_to_description(
#     int tstamp_type
# );
#####################################################
pcap_tstamp_type_val_to_description = _lib.pcap_tstamp_type_val_to_description
pcap_tstamp_type_val_to_description.restype = c_char_p
pcap_tstamp_type_val_to_description.argtypes = [c_int]



#################################################
# API to get NIC list (through pcap_findalldevs)
#################################################

# import fcntl, socket, struct

# def nic_mac_by_name(ifname):
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
#     return ':'.join(['%02x' % ord(char) for char in info[18:24]])


# class LibPcapError(Exception):
#     pass


# def all_nics():
#     devsp = POINTER(pcap_if_t)()
#     err_buf = create_string_buffer(1024)

#     if pcap_findalldevs(byref(devsp), err_buf) == -1:
#         raise LibPcapError, '"%s"' % err_buf.value

#     pdev = devsp
#     result = []
#     for dev in iter_link_list(devsp):
#         info = dev.info
#         # if info['up'] and info['running'] and (not info['loopback']):
#         if not info['loopback']:
#             try:
#                 mac = nic_mac_by_name(info['name'])
#             except IOError as e:
#                 if e.errno == 19:
#                     # no such device
#                     warnings.warn('no MAC address for device %s' % info['name'])
#                     continue
#                 else:
#                     raise e
#             result.append({
#                 'name': info['name'],
#                 'description': info['description'],
#                 'addresses': info['addresses'],
#                 'loopback': info['loopback'],
#                 'up': info['up'],
#                 'running': info['running'],
#                 'mac': mac
#             })

#     return result


###########################################
# API to get NIC list (through socket API)
###########################################

class u_ifa_ifu(Union):
    _fields_ = [('ifu_broadaddr', POINTER(sockaddr)), 
                ('ifu_dstaddr', POINTER(sockaddr))]

class ifaddrs(Structure):
    """
        one address (IPv4, IPv6, MAC)
    """
    @property
    def info(self):
        family = None
        addr = ''
        if self.ifa_addr:
            ifa_addr = self.ifa_addr.contents
            family = ifa_addr.sa_family
            if ifa_addr.sa_family in (AF_INET, AF_INET6, AF_PACKET):
                addr = ifa_addr.exact_info['addr']

        netmask = ''
        if self.ifa_netmask:
            ifa_netmask = self.ifa_netmask.contents
            if ifa_netmask.sa_family in (AF_INET, AF_INET6):
                netmask = ifa_netmask.exact_info['addr']
        return {
            'name': self.ifa_name,
            'family': family,
            'addr': addr,
            'netmask': netmask,
            'loopback': bool(IFF_LOOPBACK & self.ifa_flags),
            'up': bool(IFF_UP & self.ifa_flags),
            'running': bool(IFF_RUNNING & self.ifa_flags),
            'promiscuous': bool(IFF_PROMISC & self.ifa_flags)
        }

ifaddrs._fields_ = [
    ('ifa_next', POINTER(ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),          # below IFF_
    ('ifa_addr', POINTER(sockaddr)),
    ('ifa_netmask', POINTER(sockaddr)),
    ('ifa_ifu', u_ifa_ifu),
    ('ifa_data', c_void_p)
]



IFF_UP = 0x1            # interface is up 
IFF_BROADCAST = 0x2     # broadcast address valid 
IFF_DEBUG = 0x4         # turn on debugging 
IFF_LOOPBACK = 0x8      # is a loopback net 
IFF_POINTOPOINT = 0x10  # interface is point-to-point link 
IFF_NOTRAILERS = 0x20   # avoid use of trailers 
IFF_RUNNING = 0x40      # resources allocated 
IFF_NOARP = 0x80        # no address resolution protocol 
IFF_PROMISC = 0x100     # receive all packets 
IFF_ALLMULTI = 0x200    # receive all multicast packets 
IFF_OACTIVE = 0x400     # transmission in progress 
IFF_SIMPLEX = 0x800     # can't hear own transmissions 
IFF_LINK0 = 0x1000      # per link layer defined bit 
IFF_LINK1 = 0x2000      # per link layer defined bit 
IFF_LINK2 = 0x4000      # per link layer defined bit 
IFF_MULTICAST = 0x8000  # supports multicast 


_c_lib = cdll.LoadLibrary(ctypes.util.find_library('c'))

getifaddrs = _c_lib.getifaddrs
getifaddrs.restype = c_int
getifaddrs.argtypes = [POINTER(POINTER(ifaddrs))]

freeifaddrs = _c_lib.freeifaddrs
freeifaddrs.restype = None
freeifaddrs.argtypes = [POINTER(ifaddrs)]


def nics():
    p_ifa = POINTER(ifaddrs)()
    if getifaddrs(byref(p_ifa)) != 0:
        raise OSError(get_errno())
    try:
        result = []
        for ifa in iter_link_list(p_ifa, next='ifa_next'):
            info = ifa.info
            # info['mac'] = nic_mac_by_name(info['name'])
            result.append(info)
        return result
    finally:
        freeifaddrs(p_ifa)


def all_nics():
    p_ifa = POINTER(ifaddrs)()
    if getifaddrs(byref(p_ifa)) != 0:
        raise OSError(get_errno())
    try:
        result = {} # {'name': info}
        for ifa in iter_link_list(p_ifa, next='ifa_next'):
            info = ifa.info
            if not info['loopback']:
                ifinfo = result.setdefault(info['name'], {})
                ifinfo.setdefault('name', info['name']) 
                ifinfo.setdefault('mac', None)
                ifinfo.setdefault('description', None)
                ifinfo.setdefault('loopback', info['loopback'])
                ifinfo.setdefault('up', info['up'])
                ifinfo.setdefault('running', info['running'])
                ifinfo.setdefault('promiscuous', info['promiscuous'])
                ifinfo.setdefault('addresses', []).append({
                    'sa_family': info['family'],
                    'addr': info['addr'],
                    'netmask': info['netmask']
                })

                if info['family'] == AF_PACKET:
                    ifinfo['mac'] = info['addr']

        return result.values()
    finally:
        freeifaddrs(p_ifa)

