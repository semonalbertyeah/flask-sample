"""
    This part is a fork of the python-ping project that makes
    things work with gevent.
"""

import os
import struct
import sys
import time
# from args import args

import gevent
from gevent import socket
from gevent.pool import Pool
from gevent.event import Event

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.


def checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum = 0
    count_to = (len(source_string) / 2) * 2
    for count in xrange(0, count_to, 2):
        this = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum = sum + this
        sum = sum & 0xffffffff # Necessary?

    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer

# def test_callback(ping):
#     template = '{ip:20s}{delay:15s}{hostname:40s}{message}'
#     message = template.format(
#         hostname = ping['dest_addr'],
#         ip       = ping['dest_ip'],
#         delay    = ping['success'] and str(round(ping['delay'], 6)) or '',
#         message  = 'message' in ping and ping['message'] or ''
#     )
#     message = message.strip()
#     print >>sys.stderr, message


# class GPing:
#     """
#     This class, when instantiated will start listening for ICMP responses.
#     Then call its send method to send pings. Callbacks will be sent ping
#     details
#     """
#     def __init__(self,timeout=2,max_outstanding=10):
#         """
#         :timeout            - amount of time a ICMP echo request can be outstanding
#         :max_outstanding    - maximum number of outstanding ICMP echo requests without responses (limits traffic)
#         """
#         self.timeout = timeout
#         self.max_outstanding = max_outstanding

#         # id we will increment with each ping
#         self.id = 0

#         # object to hold and keep track of all of our self.pings
#         self.pings = {}

#         # Hold results
#         self.results = {}

#         # Hold failures
#         self.failures = []

#         # event to file when we want to shut down
#         self.die_event = Event()

#         # setup socket
#         icmp = socket.getprotobyname("icmp")
#         try:
#             # self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, icmp)
#             self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
#         except socket.error, (errno, msg):
#             if errno == 1:
#                 # Operation not permitted
#                 msg = msg + (
#                     " - Note that ICMP messages can only be sent from processes"
#                     " running as root."
#                 )
#                 raise socket.error(msg)
#             raise # raise the original error

#         self.receive_glet = gevent.spawn(self.__receive__)
#         self.processto_glet = gevent.spawn(self.__process_timeouts__)


#     def die(self):
#         """
#         try to shut everything down gracefully
#         """
#         # print "shutting down"
#         self.die_event.set()
#         # socket.cancel_wait()
#         gevent.joinall([self.receive_glet,self.processto_glet])


#     def join(self):
#         """
#         does a lot of nothing until self.pings is empty
#         """
#         while len(self.pings):
#             gevent.sleep()


#     def send(self, dest_addr, callback=None, psize=64):
#         """
#         Send a ICMP echo request.
#         :dest_addr - where to send it
#         :callback  - what to call when we get a response
#         :psize     - how much data to send with it
#         """
#         # make sure we dont have too many outstanding requests
#         while len(self.pings) >= self.max_outstanding:
#             gevent.sleep()

#         # figure out our id
#         packet_id = self.id

#         # increment our id, but wrap if we go over the max size for USHORT
#         self.id = (self.id + 1) % 2 ** 16


#         # make a spot for this ping in self.pings
#         self.pings[packet_id] = {'sent':False,'success':False,'error':False,'dest_addr':dest_addr,'dest_ip':None,'callback':callback}

#         # Resolve hostname
#         try:
#             dest_ip = socket.gethostbyname(dest_addr)
#             self.pings[packet_id]['dest_ip'] = dest_ip
#         except socket.gaierror as ex:
#             self.pings[packet_id]['error'] = True
#             self.pings[packet_id]['message'] = str(ex)
#             return


#         # Remove header size from packet size
#         psize = psize - 8

#         # Header is type (8), code (8), checksum (16), id (16), sequence (16)
#         my_checksum = 0

#         # Make a dummy heder with a 0 checksum.
#         header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, packet_id, 1)
#         bytes = struct.calcsize("d")
#         data = (psize - bytes) * "Q"
#         data = struct.pack("d", time.time()) + data

#         # Calculate the checksum on the data and the dummy header.
#         my_checksum = checksum(header + data)

#         # Now that we have the right checksum, we put that in. It's just easier
#         # to make up a new header than to stuff it into the dummy.
#         header = struct.pack(
#             "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packet_id, 1
#         )
#         packet = header + data
#         # note the send_time for checking for timeouts
#         self.pings[packet_id]['send_time'] = time.time()

#         # send the packet
#         self.socket.sendto(packet, (dest_ip, 1)) # Don't know about the 1

#         #mark the packet as sent
#         self.pings[packet_id]['sent'] = True


#     def __process_timeouts__(self):
#         """
#         check to see if any of our pings have timed out
#         """
#         while not self.die_event.is_set():
#             for i in self.pings:

#                 # Detect timeout
#                 if self.pings[i]['sent'] and time.time() - self.pings[i]['send_time'] > self.timeout:
#                     self.pings[i]['error'] = True
#                     self.pings[i]['message'] = 'Timeout after {} seconds'.format(self.timeout)

#                 # Handle all failures
#                 if self.pings[i]['error'] == True:
#                     if self.pings[i]['callback']:
#                         self.pings[i]['callback'](self.pings[i])
#                     self.failures.append(self.pings[i])
#                     del(self.pings[i])
#                     break

#             gevent.sleep()

#         print 'end of __process_timeouts__'


#     def __receive__(self):
#         """
#         receive response packets
#         """
#         while not self.die_event.is_set():
#             # wait till we can recv
#             try:
#                 socket.wait_read(self.socket.fileno(), timeout=0)
#             except (socket.error, socket.timeout) as e:
#                 if isinstance(e, socket.timeout):
#                     continue

#                 # socket.error
#                 if e.errno == socket.EBADF:
#                     print "interrupting wait_read"
#                     return
#                 # reraise original exceptions
#                 print "re-throwing socket exception on wait_read()"
#                 raise

#             time_received = time.time()
#             received_packet, addr = self.socket.recvfrom(1024)
#             icmpHeader = received_packet[20:28]
#             type, code, checksum, packet_id, sequence = struct.unpack(
#                 "bbHHh", icmpHeader
#             )

#             if packet_id in self.pings:
#                 bytes_received = struct.calcsize("d")
#                 time_sent = struct.unpack("d", received_packet[28:28 + bytes_received])[0]
#                 self.pings[packet_id]['delay'] = time_received - time_sent

#                 # i'd call that a success
#                 self.pings[packet_id]['success'] = True

#                 # call our callback if we've got one
#                 self.pings[packet_id]['callback'](self.pings[packet_id])

#                 # delete the ping
#                 del(self.pings[packet_id])

#         print 'end of __receive__'

#     def print_failures(self):
#         print >>sys.stderr
#         print >>sys.stderr, 'Failures:'
#         template = '{hostname:45}{message}'
#         for failure in self.failures:
#             message = template.format(hostname=failure['dest_addr'], message=failure.get('message', 'unknown error'))
#             print >>sys.stderr, message


# def ping(hostnames):
#     gp = GPing()

#     template = '{ip:20s}{delay:15s}{hostname:40s}{message}'
#     header = template.format(hostname='Hostname', ip='IP', delay='Delay', message='Message')
#     print >>sys.stderr, header

#     for hostname in hostnames:
#         gp.send(hostname, test_callback)
#     gp.join()
#     gp.print_failures()


############################
# refactor of GPing
############################


import random


# # from utils.thread_util
# def mthread_safe(**options):
#     """
#         options:
#             lock_name  -- the attribute name of thread lock
#         Usage:
#             class Test(object):
#                 @mthread_safe(lock_name='_lock1')
#                 def test11(self):
#                     print 'test11'

#                 @mthread_safe(lock_name='lock1')
#                 def test12(self):
#                     print 'test12'

#                 @mthread_safe(lock_name='lock2')
#                 def test21(self):
#                     print 'test21'

#     """

#     def decorator(method):
#         lock_name = options.get('lock_name', '_thread_lock_')
#         def new_method(self, *args, **kwargs):
#             lock = getattr(self, lock_name, nothing)
#             if lock is nothing:
#                 lock = threading.Lock()
#                 setattr(self, lock_name, lock)
#             assert isinstance(lock, thread.LockType), \
#                     "%s is not instance of threading.Lock, maybe a conflict" % lock_name

#             with lock:
#                 return method(self, *args, **kwargs)

#         return new_method

#     return decorator


# def id_gen():
#     """
#         generate a ID domain (iterator)
#     """
#     domain = random.sample(xrange(1, 0xffff + 1), 0xffff)
#     id_iter = iter(domain)
#     while 1:
#         try:
#             yield id_iter.next()
#         except StopIteration:
#             id_iter = iter(domain)
#             yield id_iter.next()


class GPing(object):
    """
        differences between GPing and GPing2:
            send requests when join/dispatch.
    """

    @staticmethod
    def id_domain_generator():
        domain = random.sample(xrange(1, 0xffff + 1), 0xffff)
        id_iter = iter(domain)
        while 1:
            try:
                yield id_iter.next()
            except StopIteration:
                id_iter = iter(domain)
                yield id_iter.next()

    def next_request_id(self):
        return self._id_domain.next()


    def __init__(self, timeout=2, max_outstanding=10):
        """
            :timeout - default ping timeout
            :max_outstanding - maximum number of outstanding ICMP echo requests without responses (limits traffic)
        """
        self._timeout = float(timeout)
        self._max_outstanding = int(max_outstanding)

        # request ID domain
        self._id_domain = self.id_domain_generator()

        # requests
        self._reqs = {}

        # processing requests
        self._ongoing_reqs = {}

        # Hold results
        self._results = {}

        # event to file when we want to shut down
        self._die_event = Event()

        # setup socket
        icmp = socket.getprotobyname("icmp")
        try:
            # self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, icmp)
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error, (errno, msg):
            if errno == 1:
                # Operation not permitted
                msg = msg + (
                    " - Note that ICMP messages can only be sent from processes"
                    " running as root."
                )
                raise socket.error(msg)
            raise # raise the original error

        self._receive_glet = gevent.spawn(self.__receive__)
        self._processto_glet = gevent.spawn(self.__process_timeouts__)


    def ping(self, dest_addr, callback=None, psize=64, timeout=None):
        """
            add/register a ping request
        """

        # figure out our id
        packet_id = self.next_request_id()

        # make a spot for this ping in self.pings
        self._reqs[packet_id] = {
            'sent': False,
            'success': False,
            'error': False,
            'dest_addr': dest_addr,
            'dest_ip': None,
            'callback':callback,
            'packet': None,
            'timeout': timeout or self._timeout,
            'message': '',
            'delay': None
        }

        # Resolve hostname
        try:
            dest_ip = socket.gethostbyname(dest_addr)
            self._reqs[packet_id]['dest_ip'] = dest_ip
        except socket.gaierror as ex:
            self._reqs[packet_id]['error'] = True
            self._reqs[packet_id]['message'] = str(ex)
            return packet_id

        # Remove header size from packet size
        psize = psize - 8

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        my_checksum = 0

        # Make a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, packet_id, 1)
        bytes = struct.calcsize("d")
        data = (psize - bytes) * "Q"
        data = struct.pack("d", time.time()) + data

        # Calculate the checksum on the data and the dummy header.
        my_checksum = checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packet_id, 1
        )
        packet = header + data
        self._reqs[packet_id]['packet'] = packet

        return packet_id


    def join(self):
        """
            does a lot of nothing until self._reqs is empty
        """
        while len(self._ongoing_reqs):
            gevent.sleep(0.01)


    def dispatch(self):
        """
            dispatch ping requests and wait them to finish
        """

        # Send requests
        for packet_id in self._reqs.keys():
            while len(self._ongoing_reqs) > self._max_outstanding:
                gevent.sleep(0.01)

            packet_info = self._reqs.pop(packet_id)

            self._ongoing_reqs[packet_id] = packet_info
            if not packet_info['error']:
                packet_info['send_time'] = time.time()
                self._sock.sendto(
                    packet_info['packet'],
                    (packet_info['dest_ip'], 1)   # Don't know about the 1
                )
                packet_info['sent'] = True

        self.join()

        results = self._results
        self._results = {}

        return results


    def __process_timeouts__(self):
        """
            check to see if any of our pings have timed out
        """
        while not self._die_event.is_set():
            for req_id in self._ongoing_reqs.keys():
                timeout = self._ongoing_reqs[req_id]['timeout'] or self._timeout
                # Detect timeout
                if time.time() - self._ongoing_reqs[req_id]['send_time'] > timeout:
                    self._ongoing_reqs[req_id]['error'] = True
                    self._ongoing_reqs[req_id]['message'] = 'Timeout after {} seconds'.format(timeout)

                # Handle all failures
                if self._ongoing_reqs[req_id]['error'] == True:
                    self._results[req_id] = self._ongoing_reqs.pop(req_id)

                    if self._results[req_id]['callback']:
                        self._results[req_id]['callback'](req_id, self._results[req_id])

                    # Handle one each time.
                    break

            gevent.sleep(0.01)


    def __receive__(self):
        """
            receive response packets
        """
        while not self._die_event.is_set():
            try:
                socket.wait_read(self._sock.fileno(), timeout=0.01)
            except (socket.error, socket.timeout) as e:
                if isinstance(e, socket.timeout):
                    continue

                # socket.error
                if e.errno == socket.EBADF:
                    return
                # reraise original exceptions
                raise

            time_received = time.time()
            received_packet, addr = self._sock.recvfrom(1024)
            icmpHeader = received_packet[20:28]
            type, code, checksum, packet_id, sequence = struct.unpack(
                "bbHHh", icmpHeader
            )

            if packet_id in self._ongoing_reqs:
                bytes_received = struct.calcsize("d")
                time_sent = struct.unpack("d", received_packet[28:28 + bytes_received])[0]
                self._ongoing_reqs[packet_id]['delay'] = time_received - time_sent

                # i'd call that a success
                self._ongoing_reqs[packet_id]['success'] = True

                self._results[packet_id] = self._ongoing_reqs.pop(packet_id)

                # call our callback if we've got one
                if self._results[packet_id]['callback']:
                    self._results[packet_id]['callback'](packet_id, self._results[packet_id])




    def die(self, timeout=2):
        """
            try to shut everything down gracefully:
                receiver greenlet
                timeout handler greenlet
        """
        self._die_event.set()
        gevent.joinall([self._receive_glet,self._processto_glet], timeout=timeout)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.die()

    def __del__(self):
        self.die()


# def ping(hostnames):
#     gp = GPing()

#     template = '{ip:20s}{delay:15s}{hostname:40s}{message}'
#     header = template.format(hostname='Hostname', ip='IP', delay='Delay', message='Message')
#     print >>sys.stderr, header

#     for hostname in hostnames:
#         gp.send(hostname, test_callback)
#     gp.join()
#     gp.print_failures()



# def run():

#     """
#     print 'Arguments passed in: ' + str(args.all)
#     print 'Flags detected: ' + str(args.flags)
#     print 'Files detected: ' + str(args.files)
#     print 'NOT files detected: ' + str(args.not_files)
#     print 'Grouped Arguments: ' + str(args.grouped)
#     print 'Assignments detected: ' + str(args.assignments)
#     """

#     if '--hostnames' in args.assignments:
#         hostnames_raw = args.assignments['--hostnames'].get(0)
#         hostnames = hostnames_raw.split(',')
#         ping(hostnames)


if __name__ == '__main__':
    top_100_domains = ['google.com','facebook.com','youtube.com','yahoo.com','baidu.com','wikipedia.org','live.com','qq.com','twitter.com','amazon.com','linkedin.com','blogspot.com','google.co.in','taobao.com','sina.com.cn','yahoo.co.jp','msn.com','google.com.hk','wordpress.com','google.de','google.co.jp','google.co.uk','ebay.com','yandex.ru','163.com','google.fr','weibo.com','googleusercontent.com','bing.com','microsoft.com','google.com.br','babylon.com','soso.com','apple.com','mail.ru','t.co','tumblr.com','vk.com','google.ru','sohu.com','google.es','pinterest.com','google.it','craigslist.org','bbc.co.uk','livejasmin.com','tudou.com','paypal.com','blogger.com','xhamster.com','ask.com','youku.com','fc2.com','google.com.mx','xvideos.com','google.ca','imdb.com','flickr.com','go.com','tmall.com','avg.com','ifeng.com','hao123.com','zedo.com','conduit.com','google.co.id','pornhub.com','adobe.com','blogspot.in','odnoklassniki.ru','google.com.tr','cnn.com','aol.com','360buy.com','google.com.au','rakuten.co.jp','about.com','mediafire.com','alibaba.com','ebay.de','espn.go.com','wordpress.org','chinaz.com','google.pl','stackoverflow.com','netflix.com','ebay.co.uk','uol.com.br','amazon.de','ameblo.jp','adf.ly','godaddy.com','huffingtonpost.com','amazon.co.jp','cnet.com','globo.com','youporn.com','4shared.com','thepiratebay.se','renren.com']
    ping(top_100_domains)

