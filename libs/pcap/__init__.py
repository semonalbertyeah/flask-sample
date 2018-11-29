# -*- coding:utf-8 -*-

import sys
from ctypes import *
# import netifaces

from utils.thread_util import threaded
from utils.time_util import wait

from .libpcap import *
from .nicinfo import *


class PcapError(Exception):
    pass


class Pcap(object):
    STAT_READY = 1
    STAT_POLLING = 2
    STAT_CLOSED = 3

    def __init__(self, dev, **options):
        """
            input
                dev -> device name, ("eth0" in linux e.g)
                options:
                    filter_exp -> filter expression string
                    snaplen -> length of data to be captured, default: 65535
                    promisc -> open promiscuous mode,  default: False
                    read_timeout -> read timeout in miliseconds, default: 100
                    direction -> capcturing direction:
                        'in' -> capturing received packets
                        'out' -> capturing sent packets
                        'inout' -> capturing both received and sent packets
                        None -> default, do not set. (usually, it's 'inout')
        """
        self.__stat = self.STAT_CLOSED
        self.nic = NicInfo(dev)

        ########################
        # init pcap handler
        ########################

        err_buf = create_string_buffer(PCAP_ERRBUF_SIZE+1)
        snaplen = options.pop('snaplen', 65535)
        promisc = bool(options.pop('promisc', False))
        read_timeout = int(options.pop('read_timeout', 100))
        self.handler = pcap_open_live(dev, snaplen, int(promisc), 
                                      read_timeout, err_buf)
        if not self.handler:
            raise PcapError, '"pcap_open_live": %s' % err_buf.value

        # state machine "STAT_READY" to make sure the following configuration works.
        self.__stat = self.STAT_READY  # state machine

        #############################
        #   other configurations
        #############################

        # filter
        filter_exp = options.pop('filter_exp', None)
        if filter_exp:
            self.set_filter(filter_exp)

        # capturing direction
        direction = options.pop('direction', None)
        if direction:
            if direction == 'in':
                self.set_direction_in()
            elif direction == 'out':
                self.set_direction_out()
            elif direction == 'inout':
                self.set_direction_inout()
            else:
                raise ValueError, "invalid direction value %r offered." % direction


    @property
    def stat(self):
        """
            for display
        """
        if self.__stat == Pcap.STAT_READY:
            return 'ready'
        elif self.__stat == Pcap.STAT_POLLING:
            return 'polling'
        elif self.__stat == Pcap.STAT_CLOSED:
            return 'closed'


    def assure_stat(stat):
        """
            require such state
        """
        def decorator(f):
            assured_stat = stat
            def assured_f(self, *args, **kwargs):
                assert self.__stat == assured_stat, "wrong stat: %s" % self.stat
                return f(self, *args, **kwargs)
            return assured_f
        return decorator


    def assure_not_stat(stat):
        """
            avoid such state
        """
        def decorator(f):
            avoided_stat = stat
            def assured_f(self, *args, **kwargs):
                assert self.__stat != avoided_stat, "avoided stat: %s" % self.stat
                return f(self, *args, **kwargs)
            return assured_f
        return decorator


    @assure_stat(STAT_READY)
    def set_filter(self, filter_exp):

        filter_program = bpf_program()
        try:
            if pcap_compile(self.handler, byref(filter_program), str(filter_exp), 0, 0) == -1:
                raise PcapError, '"pcap_compile": %s' % \
                        pcap_geterr(self.handler)
            if pcap_setfilter(self.handler, byref(filter_program)) == -1:
                raise PcapError, '"pcap_setfilter": %s' % \
                        pcap_geterr(self.handler)

        finally:
            pcap_freecode(byref(filter_program))


    def clear_filter(self):
        self.set_filter('')

    @assure_stat(STAT_READY)
    def set_direction_in(self):
        if pcap_setdirection(self.handler, PCAP_D_IN) != 0:
            raise PcapError, '"pcap_setdirection": %s' % \
                    pcap_geterr(self.handler)


    @assure_stat(STAT_READY)
    def set_direction_out(self):
        if pcap_setdirection(self.handler, PCAP_D_OUT) != 0:
            raise PcapError, '"pcap_setdirection": %s' % \
                    pcap_geterr(self.handler)


    @assure_stat(STAT_READY)
    def set_direction_inout(self):
        if pcap_setdirection(self.handler, PCAP_D_INOUT) != 0:
            raise PcapError, '"pcap_setdirection": %s' % \
                    pcap_geterr(self.handler)


    @assure_not_stat(STAT_CLOSED)
    def get_stats(self):
        stats = pcap_stat()
        if pcap_stats(self.handler, byref(stats)) != 0:
            raise PcapError, '"pcap_stats": %s' % \
                    pcap_geterr(self.handler)

        return {
            'recv': stats.ps_recv,
            'drop': stats.ps_drop,
            'ifdrop': stats.ps_ifdrop
        }


    @assure_not_stat(STAT_CLOSED)
    def send(self, data):
        """
            data: str, [8-bit integers], c_ubyte*n
        """

        frame_len = len(data)
        if isinstance(data, (c_ubyte * frame_len)):
            frame = data
        else:
            arr_type = (c_ubyte * frame_len)
            if isinstance(data, list):
                data = ''.join([chr(i) for i in data])
            frame = arr_type.from_buffer(create_string_buffer(data))

        if pcap_sendpacket(self.handler, frame, frame_len) != 0:
            raise PcapError, '"pcap_sendpacket": %s' % \
                    pcap_geterr(self.handler)


    @assure_stat(STAT_READY)
    def recv(self):
        """
            receive one frame
            output:
                c_ubyte * len
        """
        header = pcap_pkthdr()
        frame = pcap_next(self.handler, byref(header))
        return (c_ubyte * header.caplen)(*frame[:header.caplen])

    @assure_stat(STAT_READY)
    def clear_recv_buffer(self):
        """
            clear pcap recv buffer
        """
        while self.recv():
            pass


    @assure_stat(STAT_READY)
    def poll(self, callback=None, thread=False, count=10):
        """
            input:
                callback -> function(frame)  # data is type of (c_ubyte * data_len)
                thread -> bool, make polling in a sub-thread
                count -> the number of packets to be captured.
                         -1 means infinite, and you need to call break_loop to end it.
            output:
                [(c_ubyte * len), ...]  # received packets
        """
        result = []
        count = int(count)


        @threaded(daemon=True, start=False)
        def do_polling():
            self.__stat = self.STAT_POLLING
            def cb(p_user_data, p_header, p_data):
                """
                    user_data{unsigned char *}
                    header {struct pcap_pkthdr *}
                    data {unsigned char *}
                """
                caplen = p_header.contents.caplen
                frame = (c_ubyte * caplen)(*p_data[:caplen])

                result.append(frame)
                if callback:
                    callback(frame)

            if pcap_loop(self.handler, count, PCAP_HANDLER(cb), None) == -1:
                raise PcapError, '"pcap_loop": %s' % pcap_geterr(self.handler)
            self.__stat = self.STAT_READY

        polling_task = do_polling()

        if thread:
            polling_task.start()
        else:
            polling_task.run()
            return result


    @assure_not_stat(STAT_CLOSED)
    def break_poll(self, timeout=5):
        if self.__stat == self.STAT_POLLING:
            pcap_breakloop(self.handler)
            if not wait(
                timeout, 
                break_cond=lambda: self.__stat == self.STAT_READY
            ):
                raise PcapError, "timeout"


    def close(self):
        if self.__stat == self.STAT_POLLING:
            self.break_poll()
        if self.__stat == self.STAT_READY:
            pcap_close(self.handler)
            self.__stat = self.STAT_CLOSED


    def __del__(self):
        self.close()



    @staticmethod
    def all_devs():
        """
            return all usable devices
        """
        # return [info for info in all_nics() if info['up']]
        # return all_nics()
        return NicInfo.all_nicinfo()





    del assure_stat
    del assure_not_stat


if __name__ == '__main__':
    print Pcap.all_devs()



