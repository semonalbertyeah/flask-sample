# -*- coding:utf-8 -*-

import warnings
import threading

from pysnmp.hlapi import *
from pysnmp.hlapi import asyncore as asyncore_api

from pysnmp.entity import config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv


from pysnmp.proto import rfc1902
from pysnmp.proto.rfc1905 import endOfMibView, EndOfMibView
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
from pysnmp.smi.view import MibViewController
from pyasn1.type import univ
from pyasn1.type.base import AbstractSimpleAsn1Item
from pysnmp.proto.errind import RequestTimedOut

from pysnmp.hlapi import (
    # v3 auth protocol
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    # v3 private protocol
    usmDESPrivProtocol, usm3DESEDEPrivProtocol, usmAesCfb128Protocol,
    usmAesCfb192Protocol, usmAesCfb256Protocol
)

from utils.thread_util import threaded, wait_threads


class SnmpErr(Exception):
    def __init__(self, err_indication, err_status, err_idx):
        self.err_indication = err_indication
        self.err_status = err_status
        self.err_idx = err_idx
    
    def __str__(self):
        if self.err_indication:
            err_msg = str(self.err_indication)
        else:
            err_msg = "%s at %s" % (
                self.err_status.prettyPrint(), 
                self.err_idx and (self.err_idx-1) or '?'
            )

        return 'SnmpErr: %r' % err_msg

    def __repr__(self):
        return '<SnmpErr, indication=%r, status=%r, idx=%r>' % (self.err_indication, self.err_status, self.err_idx)

class SnmpErrNoSuch(Exception):
    pass


class SnmpBase(object):
    """
        base class of snmp client
    """

    AUTH_PROTOCOL_MAP = {
        'hmac-md5': usmHMACMD5AuthProtocol,
        'hmac-sha': usmHMACSHAAuthProtocol
    }
    PRIVACY_PROTOCOL_MAP = {
        'des': usmDESPrivProtocol,
        '3des-ede': usm3DESEDEPrivProtocol,
        'aes-128-cfb': usmAesCfb128Protocol,
        'aes-192-cfb': usmAesCfb192Protocol,
        'aes-256-cfb': usmAesCfb256Protocol
    }

    @staticmethod
    def cast_rfc1902(val):
        """
            cast rfc1902 (pysnmp.proto.rfc1902.*) types to python types:
                Bits        -> Bits (val)
                Counter32   -> int  (int(val))
                Counter64   -> int  (int(val))
                Integer32   -> int  (int(val))
                Integer     -> int  (int(val))
                OctetString -> str  (str(val))
                IpAddress   -> str  (str(val))
                ObjectIdentifier    -> tuple    (val.asTuple())
                Gauge32     -> int  (int(val))
                Unsigned32  -> int  (int(val))
                TimeTicks   -> int  (int(val))
                Opaque      -> str  (val.asOctets())

                ObjectType  -> tuple   (cast_rfc1902(val[0]), cast_rfc1902(val[1]))
                ObjectIdentity  -> tuple    (val.getOid().asTuple())

        """
        if isinstance(val, (tuple, list)):
            return type(val)([SnmpBase.cast_rfc1902(v) for v in val])
        if isinstance(val, ObjectType):
            return (SnmpBase.cast_rfc1902(val[0]), SnmpBase.cast_rfc1902(val[1]))

        elif isinstance(val, ObjectIdentity):
            return val.getOid().asTuple()

        elif isinstance(val, univ.ObjectIdentifier):
            return val.asTuple()

        elif isinstance(val, AbstractSimpleAsn1Item):

            if not val.hasValue():
                return None

            if isinstance(val, rfc1902.Bits):
                return val

            elif isinstance(
                val, 
                (rfc1902.Counter32, rfc1902.Counter64, rfc1902.Integer32, 
                rfc1902.Integer, rfc1902.Gauge32, rfc1902.Unsigned32,
                rfc1902.TimeTicks
                )
            ):
                return int(val)

            elif isinstance(
                val,
                (rfc1902.OctetString, rfc1902.IpAddress, rfc1902.Opaque)
            ):
                return str(val)

            elif isinstance(val, rfc1902.ObjectIdentifier):
                return val.asTuple()
            else:
                warnings.warn('SnmpBase.cast_rfc1902: unsupported rfc1902 type of value, return as-is: %r' % val)
                return val

        else:
            warnings.warn('unknown type return as-is: %r' % val)
            return val


    @staticmethod
    def cast_oid(oid):
        """
            transform oid to ObjectIdentity
            input:
                oid:
                    (1, 3, 6, 1, 2, 1, 1, 1, 0)
                        -> ObjectIdentity((1, 3, 6, 1, 2, 1, 1, 1, 0))
                    '1.3.6.1.2.1.1.1.0'
                        -> ObjectIdentity('1.3.6.1.2.1.1.1.0')
                    'iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0' 
                        -> ObjectIdentity('iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0')
                    ('SNMPv2-MIB', 'system') 
                        -> ObjectIdentity('SNMPv2-MIB', 'system')
                    ('SNMPv2-MIB', 'sysDescr', 0) 
                        -> ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)
                    ('IP-MIB', 'ipAdEntAddr', '127.0.0.1', 123)
                        -> ObjectIdentity('IP-MIB', 'ipAdEntAddr', '127.0.0.1', 123)

        """
        return (ObjectIdentity(*oid) 
                if isinstance(oid, tuple) 
                and isinstance(oid[0], (str, unicode)) 
                and isinstance(oid[1], (str, unicode))
            else oid 
                if isinstance(oid, ObjectIdentity)
            else ObjectIdentity(oid))

    @staticmethod
    def norm_oid(oid):
        """
            return ObjectIdentity
        """
        temp_engine = SnmpEngine()
        temp_mib_view_controller = MibViewController(temp_engine.getMibBuilder())

        oid = SnmpBase.cast_oid(oid)
        if not oid.isFullyResolved():
            oid.resolveWithMib(temp_mib_view_controller)

        return oid

    @staticmethod
    def is_sub_oid(sub_oid, oid):
        """
            check if sub_oid is sub oid of oid
        """
        sub_oid = SnmpBase.norm_oid(sub_oid)
        oid = SnmpBase.norm_oid(oid)

        # temp_engine = SnmpEngine()
        # temp_mib_view_controller = MibViewController(temp_engine.getMibBuilder())

        # sub_oid = SnmpBase.cast_oid(sub_oid)
        # if not sub_oid.isFullyResolved():
        #     sub_oid.resolveWithMib(temp_mib_view_controller)

        # oid = SnmpBase.cast_oid(oid)
        # if not oid.isFullyResolved():
        #     oid.resolveWithMib(temp_mib_view_controller)

        if len(sub_oid) < len(oid):
            return False

        domain_len = len(oid)

        return sub_oid[:domain_len] == oid[:domain_len]


    @staticmethod
    def get_transport_target(ipv4=None, ipv6=None, port=161, timeout=1, retries=5):
        transport_target = None

        port = int(port)
        if ipv4:
            transport_target = UdpTransportTarget(
                (ipv4, port), 
                timeout, 
                retries
            )
        elif ipv6:
            transport_target = Udp6TransportTarget(
                (ipv6, port), 
                timeout, 
                retries
            )

        return transport_target


    @staticmethod
    def get_auth_data(community=None, username=None, 
                      auth_key=None, privacy_key=None, 
                      auth_protocol=None, privacy_protocol=None):
        auth_data = None

        if community:
            auth_data = CommunityData(community)
        elif username:
            if auth_protocol:
                assert auth_protocol in SnmpBase.AUTH_PROTOCOL_MAP, "invalid auth protocol: %r" % auth_protocol
                auth_protocol = SnmpBase.AUTH_PROTOCOL_MAP[auth_protocol]

            if privacy_protocol:
                assert privacy_protocol in SnmpBase.PRIVACY_PROTOCOL_MAP, "invalid privacy protocol: %r" % privacy_protocol
                privacy_protocol = SnmpBase.PRIVACY_PROTOCOL_MAP[privacy_protocol]

            auth_data = UsmUserData(username, auth_key, privacy_key, auth_protocol, privacy_protocol)

        return auth_data


class SnmpV2Client(SnmpBase):
    def __init__(self, **kwargs):
        """
            input:
                engine -> SnmpEngine (optional)
                ro_community -> read-only community (default: 'public')
                rw_community -> read-write community (default: 'private')
                host -> target host
                port -> target port
                timeout -> snmp request timeout (default: 1 second)
                retries -> time of retries after timeout (default: 5)
        """

        # default values
        self.engine = SnmpEngine()
        self.ro_community = CommunityData('public', mpModel=1)
        self.rw_community = CommunityData('private', mpModel=1)
        self.udp_target = None

        self.context = ContextData()

        self.change_config(**kwargs)

        # assert self.udp_target is not None, 'host and port is required'


    def change_config(self, **kwargs):
        """
            input:
                engine -> SnmpEngine (optional)
                ro_community -> read-only community (default: 'public')
                rw_community -> read-write community (default: 'private')
                host -> target host
                port -> target port
                timeout -> snmp request timeout (default: 1 second)
                retries -> time of retries after timeout (default: 5)
        """

        if 'engine' in kwargs:
            self.engine = kwargs['engine']

        if 'ro_community' in kwargs:
            self.ro_community = CommunityData(kwargs['ro_community'], mpModel=1)

        if 'rw_community' in kwargs:
            self.rw_community = CommunityData(kwargs['rw_community'], mpModel=1)


        if 'host' in kwargs and 'port' in kwargs:
            self.udp_target = UdpTransportTarget(
                (kwargs['host'], kwargs['port']), 
                timeout=kwargs.get('timeout', 10),
                retries=kwargs.get('retries', 5)
            )


    def assure_ready(method):
        def new_method(self, *args, **kwargs):
            assert self.udp_target is not None, 'host and port is required'
            return method(self, *args, **kwargs)
        return new_method


    @assure_ready
    def ping(self, **kwargs):
        oid = "1.3.6.1.2.1.1.1.0"
        try:
            r = self.get(oid, **kwargs)
        except RequestTimedOut as e:
            return False

        if len(r) == 0:
            return False

        var_bind = r[0]
        if not var_bind:
            return False

        oid, val = var_bind
        if not isinstance(val, (str, unicode)):
            return False

        # check value
        return True


    @assure_ready
    def get(self, *oids, **kwargs):
        """
            oids, array of value like below:
                (1, 3, 6, 1, 2, 1, 1, 1, 0)
                    -> ObjectIdentity((1, 3, 6, 1, 2, 1, 1, 1, 0))
                '1.3.6.1.2.1.1.1.0'
                    -> ObjectIdentity('1.3.6.1.2.1.1.1.0')
                'iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0' 
                    -> ObjectIdentity('iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0')
                ('SNMPv2-MIB', 'system') 
                    -> ObjectIdentity('SNMPv2-MIB', 'system')
                ('SNMPv2-MIB', 'sysDescr', 0) 
                    -> ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)
                ('IP-MIB', 'ipAdEntAddr', '127.0.0.1', 123)
                    -> ObjectIdentity('IP-MIB', 'ipAdEntAddr', '127.0.0.1', 123)

            additional input:
                casted: 
                    if True, return value of python types
                    if False, return value of rfc1902 types
        """
        casted = kwargs.pop('casted', True)
        self.change_config(**kwargs)
        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]
        err_indication, err_status, err_idx, var_binds = next(
            getCmd(
                self.engine,
                self.ro_community,
                self.udp_target,
                self.context,
                *var_binds
            )
        )

        if err_indication or err_status:
            raise SnmpErr(err_indication, err_status, err_idx)

        if casted:
            var_binds = [self.cast_rfc1902(vb) for vb in var_binds]

        return var_binds


    @assure_ready
    def set(self, *var_binds, **kwargs):
        """
            input:
                var_binds
                    (castable_oid, val)
                    or
                    ObjectType
        """
        casted = kwargs.pop('casted', True)
        self.change_config(**kwargs)
        var_binds = [
            vb if isinstance(vb, ObjectType) else ObjectType(self.cast_oid(vb[0]), vb[1]) 
            for vb in var_binds
        ]

        err_indication, err_status, err_idx, var_binds = next(setCmd(
            self.engine,
            self.rw_community,
            self.udp_target,
            self.context,
            *var_binds
        ))

        if err_indication or err_status:
            raise SnmpErr(err_indication, err_status, err_idx)

        if casted:
            var_binds = [self.cast_rfc1902(vb) for vb in var_binds]

        return var_binds


    @assure_ready
    def getnext(self, *oids, **kwargs):
        casted = kwargs.pop('casted', True)
        self.change_config(**kwargs)
        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]
        err_indication, err_status, err_idx, var_binds = next(
            nextCmd(
                self.engine,
                self.ro_community,
                self.udp_target,
                self.context,
                *var_binds
            )
        )

        if err_indication or err_status:
            raise SnmpErr(err_indication, err_status, err_idx)

        if casted:
            var_binds = [self.cast_rfc1902(vb) for vb in var_binds]

        return var_binds



    @assure_ready
    def getbulk(self, *oids, **kwargs):
        """
            extra input:
                non_repeaters
                max_repetitions
                casted
        """
        casted = kwargs.pop('casted', True)
        non_repeaters = int(kwargs.pop('non_repeaters', 0))
        max_repetitions = int(kwargs.pop('max_repetitions', 10))
        self.change_config(**kwargs)
        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]

        g = bulkCmd(
            self.engine,
            self.ro_community,
            self.udp_target,
            self.context,
            non_repeaters, max_repetitions,
            *var_binds,
            maxRows=max_repetitions
        )

        result = []
        for (err_indication, err_status, err_idx, var_binds) in g:
            if err_indication or err_status:
                raise SnmpErr(err_indication, err_status, err_idx)
            if casted:
                var_binds = [self.cast_rfc1902(vb) for vb in var_binds]

            result.append(var_binds)

        return result


    @assure_ready
    def walk(self, *oids, **kwargs):
        """
        """
        casted = kwargs.pop('casted', True)
        non_repeaters = int(kwargs.pop('non_repeaters', 0))
        max_repetitions = int(kwargs.pop('max_repetitions', 10))
        self.change_config(**kwargs)
        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]

        g = bulkCmd(
            self.engine,
            self.ro_community,
            self.udp_target,
            self.context,
            non_repeaters, max_repetitions,
            *var_binds,
            lexicographicMode=False # end iteration when ~all~ col oid is out of scope (requested oid)
        )

        result = []
        for (err_indication, err_status, err_idx, var_binds) in g:
            if err_indication or err_status:
                raise SnmpErr(err_indication, err_status, err_idx)

            var_binds = map(lambda vb: None if vb[1] == endOfMibView else vb, var_binds)
            if casted:
                var_binds = [self.cast_rfc1902(vb) for vb in var_binds]

            result.append(var_binds)

        return result

    del assure_ready


class SnmpClient(SnmpBase):

    DEFAULT_PORT = 161
    DEFAULT_TIMEOUT = 1
    DEFAULT_RETRIES = 5

    DEFAULT_COMMUNITY = 'public'

    def __init__(self, engine=None, casted=True, **options):

        if isinstance(engine, SnmpEngine):
            self.engine = engine
        else:
            # is engine_id
            self.engine = SnmpEngine(engine)
        self._casted = casted


        # options.setdefault('context_engine_id', None)
        # options.setdefault('context_name', '')
        # self.context, self.transport_target, self.auth_data = \
        #                                 self.__parse_options(**options)


        self.ipv4 = options.get('ipv4', None)
        self.ipv6 = options.get('ipv6', None)
        assert not (self.ipv4 and self.ipv6), "both IPv4 and IPv6 address are configured."
        self.port = options.get('port', self.DEFAULT_PORT)
        self.timeout = options.get('timeout', self.DEFAULT_TIMEOUT)
        self.retries = options.get('retries', self.DEFAULT_RETRIES)

        self.community = options.get('community', None)
        self.username = options.get('username', None)
        assert not (self.community and self.username), "both community and username are configured."
        self.auth_key = options.get('auth_key', None)
        self.auth_protocol = options.get('auth_protocol', None)
        self.privacy_key = options.get('privacy_key', None)
        self.privacy_protocol = options.get('privacy_protocol', None)

        self.context_name = options.get('context_name', '')
        self.context_engine_id = options.get('context_engine_id', None)


        # {
        #     req_id1: var_binds,
        #     req_id2: var_binds,
        #     req_id3: SnmpErr
        # }
        self.__result = {}

    def set_timeout(self, timeout):
        self.timeout = int(timeout)


    def __parse_options(self, **options):
        """
            parse parameters
            input:
                ipv4=None, ipv6=None, port=None, timeout=1, retries=5,
                community=None, username=None, auth_key=None, privacy_key=None,
                auth_protocol=None, privacy_protocol=None,
                context_engine_id=None, context_name=None
            output:
                (context, transport_target, auth_data)
        """

        ################
        #  Context
        ################
        context_engine_id = options.get('context_engine_id', None) or self.context_engine_id
        context_name = options.get('context_name', None) or self.context_name
        context = ContextData(context_engine_id, context_name)
        # self.context = context # for debug

        #################
        # TransportTarget
        #################
        port = options.get('port', None) or self.port
        timeout = options.get('timeout', None) or self.timeout
        retries = options.get('retries', None) or self.retries
        if 'ipv4' in options:
            transport_target = self.get_transport_target(
                ipv4=options['ipv4'],
                port=port,
                timeout=timeout,
                retries=retries
            )
        elif 'ipv6' in options:
            transport_target = self.get_transport_target(
                ipv6=options['ipv6'],
                port=port,
                timeout=timeout,
                retries=retries
            )
        else:
            transport_target = self.get_transport_target(
                ipv4=self.ipv4, ipv6=self.ipv6,
                port=port, timeout=timeout,
                retries=retries
            )

        #####################################
        # AuthData
        #   snmp version is determined here
        #####################################
        auth_key = options.get('auth_key', None) or self.auth_key
        auth_protocol = options.get('auth_protocol', None) or self.auth_protocol
        privacy_key = options.get('privacy_key', None) or self.privacy_key
        privacy_protocol = options.get('privacy_protocol', None) or self.privacy_protocol
        if 'community' in options:
            auth_data = self.get_auth_data(community=options['community'])
        elif 'username' in options:
            auth_data = self.get_auth_data(
                username=options['username'],
                auth_key=options.get('auth_key', None) or self.auth_key,
                auth_protocol=options.get('auth_protocol', None) or self.auth_protocol,
                privacy_key=options.get('privacy_key', None) or self.privacy_key,
                privacy_protocol=options.get('privacy_protocol', None) or self.privacy_protocol
            )
        else:
            auth_data = self.get_auth_data(
                community=self.community, 
                username=self.username,
                auth_key=self.auth_key,
                privacy_key=self.privacy_key,
                auth_protocol=self.auth_protocol,
                privacy_protocol=self.privacy_protocol
            )

        return context, transport_target, auth_data


    def get_request(self, *oids, **options):
        """
            register a get command
        """
        callback = options.pop('callback', None)
        callback_context = options.pop('callback_context', None)

        context, transport_target, auth_data = self.__parse_options(**options)
        assert transport_target, "target host is needed"
        assert auth_data, "authentication is needed"

        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]

        def cb(engine, req_id, err_indication, err_status,
               err_idx, var_binds, callback_context):

            if err_indication or err_status:
                self.__result[req_id] = SnmpErr(err_indication, err_status, err_idx)
            else:
                if self._casted:
                    var_binds = [self.cast_rfc1902(vb) for vb in var_binds]
                self.__result[req_id] = var_binds

            if callback:
                callback(req_id, self.__result[req_id], callback_context)


        # register command here
        req_id = asyncore_api.getCmd(
            self.engine, 
            auth_data, 
            transport_target, 
            context,
            *var_binds, 
            cbFun=cb,
            cbCtx=callback_context
        )
        self.__result[req_id] = SnmpErr("never returned.", None, None)

        return req_id



    def set_request(self, *var_binds, **options):
        """
            register a set command
        """
        callback = options.pop('callback', None)
        callback_context = options.pop('callback_context', None)

        context, transport_target, auth_data = self.__parse_options(**options)
        assert transport_target, "target host is needed"
        assert auth_data, "authentication is needed"

        var_binds = [
            vb if isinstance(vb, ObjectType) else ObjectType(self.cast_oid(vb[0]), vb[1]) 
            for vb in var_binds
        ]

        def cb(engine, req_id, err_indication, err_status,
               err_idx, var_binds, callback_context):

            if err_indication or err_status:
                self.__result[req_id] = SnmpErr(err_indication, err_status, err_idx)
            else:
                if self._casted:
                    var_binds = [self.cast_rfc1902(vb) for vb in var_binds]
                self.__result[req_id] = var_binds

            if callback:
                callback(req_id, self.__result[req_id], callback_context)


        # register command here
        req_id = asyncore_api.setCmd(
            self.engine, 
            auth_data, 
            transport_target, 
            context,
            *var_binds, 
            cbFun=cb,
            cbCtx=callback_context
        )
        self.__result[req_id] = SnmpErr("never returned.", None, None)

        return req_id


    def getnext_request(self, *oids, **options):
        """
            register a getnext command
        """
        callback = options.pop('callback', None)
        callback_context = options.pop('callback_context', None)

        context, transport_target, auth_data = self.__parse_options(**options)
        assert transport_target, "target host is needed"
        assert auth_data, "authentication is needed"

        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]

        def cb(engine, req_id, err_indication, err_status,
               err_idx, var_binds, callback_context):

            if err_indication or err_status:
                self.__result[req_id] = SnmpErr(err_indication, err_status, err_idx)
            else:
                if self._casted:
                    var_binds = [self.cast_rfc1902(vb) for vb in var_binds]
                self.__result[req_id] = var_binds

            if callback:
                callback(req_id, self.__result[req_id], callback_context)


        # register command here
        req_id = asyncore_api.nextCmd(
            self.engine, 
            auth_data, 
            transport_target, 
            context,
            *var_binds, 
            cbFun=cb,
            cbCtx=callback_context
        )
        self.__result[req_id] = SnmpErr("never returned.", None, None)

        return req_id


    def getbulk_request(self, *oids, **options):
        """
            register a getbulk command
            extra input:
                non_repeaters   (default 0)
                max_repetitions (default 5)
        """
        callback = options.pop('callback', None)
        callback_context = options.pop('callback_context', None)

        non_repeaters = options.pop('non_repeaters', 0)
        max_repetitions = options.pop('max_repetitions', 5)

        context, transport_target, auth_data = self.__parse_options(**options)
        assert transport_target, "target host is needed"
        assert auth_data, "authentication is needed"

        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]

        def cb(engine, req_id, err_indication, err_status,
               err_idx, var_binds, callback_context):

            if err_indication or err_status:
                self.__result[req_id] = SnmpErr(err_indication, err_status, err_idx)
            else:
                result = var_binds
                if self._casted:
                    result = []
                    for row in var_binds:
                        result.append([self.cast_rfc1902(vb) for vb in row])

                self.__result[req_id] = result

            if callback:
                callback(req_id, self.__result[req_id], callback_context)


        # register command here
        req_id = asyncore_api.bulkCmd(
            self.engine, 
            auth_data, 
            transport_target, 
            context,
            non_repeaters,
            max_repetitions,
            *var_binds, 
            cbFun=cb,
            cbCtx=callback_context
        )
        self.__result[req_id] = SnmpErr("never returned.", None, None)

        return req_id


    def next_walk_request(self, *oids, **options):
        """
            register a walk command (walk by getnext)
        """
        callback = options.pop('callback', None)
        callback_context = options.pop('callback_context', None)

        context, transport_target, auth_data = self.__parse_options(**options)
        assert transport_target, "target host is needed"
        assert auth_data, "authentication is needed"

        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]

        first_req_id = None
        result = []
        def cb(engine, req_id, err_indication, err_status,
               err_idx, var_binds, callback_context):

            if err_indication or err_status:
                self.__result[first_req_id] = SnmpErr(err_indication, err_status, err_idx)
                if callback:
                    callback(first_req_id, self.__result[first_req_id], callback_context)

                return False

            else:
                for row in var_binds:
                    row_value = []
                    for vb in row:
                        idx = row.index(vb)
                        if isinstance(vb[1], EndOfMibView):
                            # print 'finished, end of Mib View.'
                            # self.__result[first_req_id] = result
                            # if callback:
                            #     callback(first_req_id, self.__result[first_req_id], callback_context)
                            # return False

                            # end of mib view
                            row_value.append(None)
                        elif self.is_sub_oid(vb[0], oids[idx]):
                            if self._casted:
                                row_value.append(self.cast_rfc1902(vb))
                            else:
                                row_value.append(vb)

                        else:
                            # out of range
                            row_value.append(None)

                    if all(vb is None for vb in row_value):
                        # all finished
                        self.__result[first_req_id] = result
                        if callback:
                            callback(first_req_id, self.__result[first_req_id], callback_context)
                        return False

                    else:
                        result.append(row_value)

                return True


        first_req_id = asyncore_api.nextCmd(
            self.engine, 
            auth_data, 
            transport_target, 
            context,
            *var_binds, 
            cbFun=cb,
            cbCtx=callback_context
        )
        self.__result[first_req_id] = SnmpErr("never returned.", None, None)

        return first_req_id


    def walk_request(self, *oids, **options):
        """
            register a walk command
            extra input:
                non_repeaters   (default 0)
                max_repetitions (default 5)
        """
        callback = options.pop('callback', None)
        callback_context = options.pop('callback_context', None)

        non_repeaters = options.pop('non_repeaters', 0)
        max_repetitions = options.pop('max_repetitions', 10)

        context, transport_target, auth_data = self.__parse_options(**options)
        assert transport_target, "target host is needed"
        assert auth_data, "authentication is needed"

        oids = [self.cast_oid(oid) for oid in oids]
        var_binds = [ObjectType(oid) for oid in oids]

        first_req_id = None
        result = []
        def cb(engine, req_id, err_indication, err_status,
               err_idx, var_binds, callback_context):

            if err_indication or err_status:
                # result.append(
                #     SnmpErr(err_indication, err_status, err_idx)
                # )
                # self.__result[first_req_id] = result
                self.__result[first_req_id] = SnmpErr(err_indication, err_status, err_idx)
                if callback:
                    callback(first_req_id, self.__result[first_req_id], callback_context)

                return False

            else:
                for row in var_binds:
                    row_value = []
                    for vb in row:
                        idx = row.index(vb)
                        if isinstance(vb[1], EndOfMibView):
                            # print 'finished, end of Mib View.'
                            # self.__result[first_req_id] = result
                            # if callback:
                            #     callback(first_req_id, self.__result[first_req_id], callback_context)
                            # return False

                            # end of mib view
                            row_value.append(None)
                        elif self.is_sub_oid(vb[0], oids[idx]):
                            if self._casted:
                                row_value.append(self.cast_rfc1902(vb))
                            else:
                                row_value.append(vb)

                        else:
                            # out of range
                            row_value.append(None)

                    if all(vb is None for vb in row_value):
                        # all finished
                        self.__result[first_req_id] = result
                        if callback:
                            callback(first_req_id, self.__result[first_req_id], callback_context)
                        return False

                    else:
                        result.append(row_value)

                return True


        first_req_id = asyncore_api.bulkCmd(
            self.engine, 
            auth_data, 
            transport_target, 
            context,
            non_repeaters,
            max_repetitions,
            *var_binds, 
            cbFun=cb,
            cbCtx=callback_context
        )
        self.__result[first_req_id] = SnmpErr("never returned.", None, None)

        return first_req_id


    def dispatch(self):
        """
            dispatch all requests(commands)
        """
        self.engine.transportDispatcher.runDispatcher()
        result = self.__result
        self.__result = {}
        return result


class TrapReceiver(SnmpBase):
    """
        A Trap Receiver
        Usage:
            tr = TrapReceiver()

            # link down
            @tr.on('1.3.6.1.6.3.1.1.5.3')
            def handle_link_down_trap(timestamp, oid, var_binds, ip, port, ctx_engine_id, ctx_name):
                print 'timestamp:', 
                # oid is the listened oid
                for oid, val in var_binds:
                    print oid, val

            tr.start()
    """
    # stat machine
    STAT_RUNNING = 'running'            # dispatcher running
    STAT_TERMINATING = 'terminating'    # terminating dispatcher
    STAT_READY = 'ready'                # dispatcher ready to run
    STAT_CLOSED = 'closed'              # dispatcher closed

    def __init__(self, engine=None, targets=[], community='public'):
        """
            engine -> mainly used when you wan to specify an engine ID
            targets -> [(ip, port), ...]
            community
        """
        self.engine = engine or SnmpEngine()
        if targets:
            idx = 0
            for ip, port in targets:
                config.addTransport(
                    self.engine,
                    udp.domainName + (idx,),
                    udp.UdpTransport().openServerMode((ip, port))
                )
                idx += 1
        else:
            config.addTransport(
                self.engine,
                udp.domainName,
                udp.UdpTransport().openServerMode(('0.0.0.0', 162))
            )

        config.addV1System(self.engine, 'my-area', community)

        ###################
        # {
        #     oid: func,
        #     ...
        # }
        ###################
        self._callbacks = {}
        self._callbacks_lock = threading.Lock()
        ntfrcv.NotificationReceiver(self.engine, self._cb)

        self._dispath_task = None
        self._stat = self.STAT_READY


    def _cb(self, engine, stat_ref, ctx_engine_id, 
            ctx_name, var_binds, cb_ctx):

        ctx_engine_id = ctx_engine_id.prettyPrint()
        ctx_name = ctx_name.prettyPrint()
        (transport_domain, (ip, port)) = engine.msgAndPduDsp.getTransportInfo(stat_ref)
        var_binds = [self.cast_rfc1902(vb) for vb in var_binds]

        if var_binds[0][0] != (1, 3, 6, 1, 2, 1, 1, 3, 0):
            warnings.warn("first OID should be sysUpTime.0, invalid: %s" % var_binds[0][0])
            return
        timestamp = var_binds[0][1]

        if var_binds[1][0] != (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0):
            warnings.warn("second OID should be snmpTrapOID.0, invalid: %s" % var_binds[1][0])
            return
        oid = var_binds[1][1]

        var_binds = var_binds[2:]

        oid_str = str(self.norm_oid(oid))
        with self._callbacks_lock:
            cb = self._callbacks.get(oid_str, None)

        if cb:
            cb(timestamp, oid, var_binds, ip, port, ctx_engine_id, ctx_name)
        else:
            # for test
            print "unregistered OID received:", oid_str
            print "sysUptTime:", timestamp
            print "varbinds:"
            for name, val in var_binds:
                print "%s = %s" % (name, val)


    def register(self, oid, cb):
        """
            cb -> function(
                    timestamp,
                    oid,
                    var_binds,
                    ip,
                    port,
                    ctx_engine_id,
                    ctx_name
                )
        """
        oid = str(self.norm_oid(oid))
        with self._callbacks_lock:
            if oid in self._callbacks:
                warnings.warn("TrapReceiver WARNING: register duplicate OID.")
            self._callbacks[oid] = cb


    def on(self, oid):
        def decorator(func):
            self.register(oid, func)
            return func

        return decorator


    @property
    def closed(self):
        return self._stat == self.STAT_CLOSED

    @property
    def ready(self):
        return self._stat == self.STAT_READY

    @property
    def running(self):
        return self._stat == self.STAT_RUNNING

    @property
    def terminating(self):
        return self._stat == self.STAT_TERMINATING


    @threaded(name='dispather', start=True, daemon=True)
    def _run_dispatch_task(self):
        if self._stat == self.STAT_READY:
            self._stat = self.STAT_RUNNING
            self.engine.transportDispatcher.jobStarted(1)
            self.engine.transportDispatcher.runDispatcher()
            self._stat = self.STAT_READY

    def start(self):
        if self._stat == self.STAT_READY:
            self._dispath_task = self._run_dispatch_task()
        else:
            warnings.warn("Cannot start dispather in stat: %s" % self._stat)

    def stop(self):
        if self._stat == self.STAT_RUNNING:
            self.engine.transportDispatcher.jobFinished(1)
            assert wait_threads(self._dispath_task, timeout=5), "timeout waiting dispatcher to exit."
            self._dispath_task = None

    def close(self):
        if self._stat == self.STAT_RUNNING:
            self.stop()

        if self._stat == self.STAT_READY:
            self.engine.transportDispatcher.closeDispatcher()

        self._stat = self.STAT_CLOSED

    def __del__(self):
        self.close()


#######################
# tests
#######################
import time

def get_test_client():
    host = '192.168.2.33'
    port = 161
    rw_comm = 'private'
    ro_comm = 'public'

    # engine -> SnmpEngine (optional)
    # ro_community -> read-only community (default: 'public')
    # rw_community -> read-write community (default: 'private')
    # host -> target host
    # port -> target port
    # timeout -> snmp request timeout (default: 1 second)
    # retries -> time of retries after timeout (default: 5)
    client = SnmpV2Client(
        ro_community=ro_comm,
        rw_community=rw_comm,
        host=host,
        port=port
    )

    return client


def test_next_walk_ports():
    sc = SnmpClient(ipv4='192.168.2.112', community='public')
    sc.next_walk_request(
        '1.3.6.1.4.1.37561.1.1.2.2.1.1',    # sIfIndex
        '1.3.6.1.4.1.37561.1.1.2.2.1.2',    # sIfDescr
        '1.3.6.1.4.1.37561.1.1.2.2.1.3',    # sIfSpeed
        '1.3.6.1.4.1.37561.1.1.2.2.1.4',    # sIfStatus
        '1.3.6.1.4.1.37561.1.1.2.2.1.5',    # sIfInOctets
        '1.3.6.1.4.1.37561.1.1.2.2.1.6',    # sIfInUcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.7',    # sIfInMcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.8',    # sIfInBcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.9',    # sIfOutOctets
        '1.3.6.1.4.1.37561.1.1.2.2.1.10',   # sIfOutUcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.11',   # sIfOutMcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.12',   # sIfOutBcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.13',   # sIfFiberRxPwr
        '1.3.6.1.4.1.37561.1.1.2.2.1.14'    # sIfFiberTxPwr
    )

    start = time.time()
    sc.dispatch()
    print 'next poll ports, cost:', time.time() - start

def test_bulk_walk_ports():
    sc = SnmpClient(ipv4='192.168.2.112', community='public')
    sc.walk_request(
        '1.3.6.1.4.1.37561.1.1.2.2.1.1',    # sIfIndex
        '1.3.6.1.4.1.37561.1.1.2.2.1.2',    # sIfDescr
        '1.3.6.1.4.1.37561.1.1.2.2.1.3',    # sIfSpeed
        '1.3.6.1.4.1.37561.1.1.2.2.1.4',    # sIfStatus
        '1.3.6.1.4.1.37561.1.1.2.2.1.5',    # sIfInOctets
        '1.3.6.1.4.1.37561.1.1.2.2.1.6',    # sIfInUcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.7',    # sIfInMcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.8',    # sIfInBcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.9',    # sIfOutOctets
        '1.3.6.1.4.1.37561.1.1.2.2.1.10',   # sIfOutUcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.11',   # sIfOutMcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.12',   # sIfOutBcastPkts
        '1.3.6.1.4.1.37561.1.1.2.2.1.13',   # sIfFiberRxPwr
        '1.3.6.1.4.1.37561.1.1.2.2.1.14'    # sIfFiberTxPwr
    )

    start = time.time()
    sc.dispatch()
    print 'bulk poll ports, cost:', time.time() - start


if __name__ == '__main__':
    test_next_walk_ports()
    test_bulk_walk_ports()

