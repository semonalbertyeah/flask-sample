# -*- coding:utf-8 -*-

from easysnmp.compat import urepr
from easysnmp.helpers import normalize_oid
from easysnmp.utils import strip_non_printable, tostr
from easysnmp.exceptions import *

def oid2tuple(oid):
    if isinstance(oid, (str, unicode)):
        oid = [int(i) if i.isdigit() else i for i in filter(bool, oid.split(u'.'))]
    elif isinstance(oid, tuple):
        pass
    else:
        raise ValueError("Invalid OID value %r" % oid)

    return oid

# monkey patch easysnmp
class SNMPVariable(object):
    """
    An SNMP variable binding which is used to represent a piece of
    information being retreived via SNMP.

    :param oid: the OID being manipulated
    :param oid_index: the index of the OID
    :param value: the OID value
    :param snmp_type: the snmp_type of data contained in val (please see
                      http://www.net-snmp.org/wiki/index.php/TUT:snmpset#Data_Types
                      for further information); in the case that an object
                      or instance is not found, the type will be set to
                      NOSUCHOBJECT and NOSUCHINSTANCE respectively
    """

    def __init__(self, oid=None, oid_index=None, value=None, snmp_type=None):
        self.oid, self.oid_index = normalize_oid(oid, oid_index)
        self.value = value
        self.snmp_type = snmp_type


    @property
    def full_oid(self):
        return self.oid + u'.' +self.oid_index

    @property
    def full_oid_tuple(self):
        return oid2tuple(self.full_oid)

    @property
    def casted_value(self):
        return self._cast_value(self.snmp_type, self.value)

    @staticmethod
    def _cast_value(_type, val):
        if _type in (u'OBJECTID', u'NETADDR', u'IPADDR'):
            pass

        elif _type in (u'OCTETSTR', u'OPAQUE'):
            val = val.encode(u'latin-1')

        elif _type in (
            u'INTEGER', u'INTEGER32', u'UINTEGER', u'UNSIGNED32', 
            u'GAUGE', u'COUNTER', u'COUNTER64', u'TICKS', u''
        ):
            val = int(val)

        elif _type in (u'BITS', ):
            val = val.encode('latin-1')

        elif _type in (
            u'ENDOFMIBVIEW', u'NOSUCHOBJECT', u'NOSUCHINSTANCE'
        ):
            pass

        return val

    def __repr__(self):
        printable_value = strip_non_printable(self.value)
        return (
            "<{0} value={1} (oid={2}, oid_index={3}, snmp_type={4})>".format(
                self.__class__.__name__,
                urepr(printable_value), urepr(self.oid),
                urepr(self.oid_index), urepr(self.snmp_type)
            )
        )

    def __setattr__(self, name, value):
        self.__dict__[name] = tostr(value)


import easysnmp.session
import easysnmp.variables
import easysnmp
setattr(easysnmp.session, 'SNMPVariable', SNMPVariable)
setattr(easysnmp.variables, 'SNMPVariable', SNMPVariable)
setattr(easysnmp, 'SNMPVariable', SNMPVariable)




from easysnmp import Session


# def cast_varbind(vb):
#     # assert isinstance(vb, SNMPVariable)
#     oid = vb.oid
#     if oid[0] == u'.':
#         oid = oid[1:]

#     oid = oid + vb.oid_index

#     val = vb.value

#     # OCTETSTR, OPAQUE
#     # INTEGER, INTEGER32, UNSIGNED32, COUNTER, TICKS, COUNTER64, UINTEGER,
#     # OBJECTID, NETADDR, IPADDR,
#     # NULL, ENDOFMIBVIEW, NOSUCHOBJECT, 
#     # NOSUCHINSTANCE, NOTIF, BITS, TRAP
#     if vb.snmp_type in (u'OBJECTID', u'NETADDR', u'IPADDR'):
#         pass

#     elif vb.snmp_type in (u'OCTETSTR', u'OPAQUE'):
#         val = val.encode(u'latin-1')

#     elif vb.snmp_type in (
#         u'INTEGER', u'INTEGER32', u'UINTEGER', u'UNSIGNED32', 
#         u'GAUGE', u'COUNTER', u'COUNTER64', u'TICKS', u''
#     ):
#         val = int(val)

#     elif vb.snmp_type in (u'BITS', ):
#         val = val.encode('latin-1')

#     elif vb.snmp_type in (
#         u'ENDOFMIBVIEW', u'NOSUCHOBJECT', u'NOSUCHINSTANCE'
#     ):
#         pass

#     return (oid, val)


# def cast_varbinds(vbs):
#     if isinstance(vbs, SNMPVariable):
#         return cast_varbind(vbs)
#     else:
#         return [cast_varbind(vb) for vb in vbs]


# def guess_type_by_value(val):
#     if isinstance(val, (unicode, str)):
#         return u'OCTETSTR'
#     elif isinstance(val, (int, float, long)):
#         return u'INTEGER'
#     else:
#         return None


def is_sub_oid(sub_oid, oid):
    """
        check if sub_oid is sub oid of oid
        input:
            oid -> '1.3.6.1.2.1.1.1.0'
    """

    sub_oid = filter(bool, sub_oid.split('.'))
    oid = filter(bool, oid.split('.'))

    if len(sub_oid) < len(oid):
        return False

    domain_len = len(oid)

    return sub_oid[:domain_len] == oid[:domain_len]


def oid_cmp(oid1, oid2):
    """
        if oid1 > oid2 -> 1
        elif oid1 == oid2 -> 0
        elif oid1 < oid2 -> -1

        oid1 > oid2, which means oid2 is next to oid1
    """
    oid1 = [
        int(i) for i in filter(bool, oid1.split('.'))
    ]

    oid2 = [
        int(i) for i in filter(bool, oid2.split('.'))
    ]

    oid1_len = len(oid1)
    oid2_len = len(oid2)
    less_len = min(oid1_len, oid2_len)
    idx = 0

    while idx < less_len:
        if oid1[idx] > oid2[idx]:
            return 1
        elif oid1[idx] < oid2[idx]:
            return -1

        idx += 1

    if oid1_len > oid2_len:
        return 1
    elif oid1_len < oid2_len:
        return -1

    return 0



class SetFailure(Exception):
    pass

class SnmpClient(Session):
    def __init__(self, **kwargs):
        kwargs['use_numeric'] = True
        kwargs['abort_on_nonexistent'] = True
        kwargs.setdefault('version', 2)

        super(SnmpClient, self).__init__(**kwargs)


    def get(self, *oids):
        """
            input:
                oids -> [oid]
                    oid -> u'1.3.6.1.2.1.1.1.0'
            return:
                [vb1, vb2, ...]
                vb -> instance of SNMPVariable
        """
        return super(SnmpClient, self).get(list(oids))

    # def ping(self, oid="1.3.6.1.2.1.1.1.0"):
    def ping(self, oid="1.3.6.1.2.1.2.1.0"):
        try:
            self.get(oid)
        except EasySNMPTimeoutError as e:
            return False
        return True



    def set(self, *var_binds):
        """
            input:
                var_binds -> [(oid, value, type), ...]
        """
        success = super(SnmpClient, self).set_multiple(list(var_binds))
        if not success:
            raise SetFailure

    def get_next(self, *oids):
        """
            input:
                oids -> [oid]
                    oid -> u'1.3.6.1.2.1.1.1.0'
            return:
                [vb1, vb2, ...]
                vb -> instance of SNMPVariable
        """
        return super(SnmpClient, self).get_next(list(oids))


    def get_bulk(self, *oids, **kwargs):
        """
            input:
                oids -> [oid]
                    oid -> u'1.3.6.1.2.1.1.1.0'
                non_repeaters -> default: 0
                max_repetitions -> default: 10
            output:
                [
                    [(oid11, value11), (oid12, value12), ...],
                    [(oid21, value21), (oid22, value22), ...],
                    ...
                ]
        """
        non_repeaters = int(kwargs.get(u'non_repeaters', 0))
        max_repetitions = int(kwargs.get(u'max_repetitions', 10))

        r = super(SnmpClient, self).get_bulk(
            list(oids), non_repeaters=non_repeaters,
            max_repetitions=max_repetitions
        )

        idx = 0
        ended = {}
        for oid in oids:
            # handle probable duplicated OIDs
            oid_key = u'%s-%d' % (oid, idx)
            ended[oid_key] = False
            idx += 1

        vb_len = len(r)
        idx = 0
        results = []

        while idx < vb_len:
            row = []
            for oid in ended.iterkeys():
                if ended[oid]:
                    row.append(None)
                else:
                    if r[idx].snmp_type == u'ENDOFMIBVIEW':
                        row.append(None)
                        ended[oid] = True
                    else:
                        row.append(r[idx])
                    idx += 1

            results.append(row)

        return results


    def walk(self, *oids):

        r = super(SnmpClient, self).walk(list(oids))

        idx = 0
        col_len = len(oids)
        vb_len = len(r)

        results = []
        while idx < vb_len:
            results.append(r[idx: idx+col_len])
            idx += col_len

        return results

    def bulkwalk(self, *oids, **kwargs):
        non_repeaters = kwargs.get('non_repeaters', 0)
        max_repetitions = kwargs.get('max_repetitions', 10)

        vbs = super(SnmpClient, self).bulkwalk(
            list(oids), 
            non_repeaters=non_repeaters, 
            max_repetitions=max_repetitions
        )

        col_idx = 0
        col_num = len(oids)
        vb_idx = 0
        vb_num = len(vbs)

        cols = {
            oid: {'recs': [], 'last_oid': oid} 
            for oid in oids
        }

        while (vb_idx < vb_num) and (col_idx < col_num):
            oid = oids[col_idx]
            vb = vbs[vb_idx]

            # if is_sub_oid(vb.full_oid, oid) and \
            #    oid_cmp(vb.full_oid, cols[oid]['last_oid']) >= 0:
            if is_sub_oid(vb.full_oid, oid):
                cols[oid]['recs'].append(vb)
                cols[oid]['last_oid'] = vb.full_oid
                vb_idx += 1
            else:
                col_idx += 1

        assert vb_idx == vb_num, "all variables should be collected"

        # the order matters
        ordered_cols = []
        longest_col_len = 0
        for oid in oids:
            col = cols[oid]['recs']
            ordered_cols.append(col)
            longest_col_len = max(longest_col_len, len(col))


        idx = 0
        while idx < len(ordered_cols):
            col = ordered_cols[idx]
            ordered_cols[idx] = col + [None] * (longest_col_len - len(col))
            idx += 1

        return zip(*ordered_cols)

    def best_walk(self, *oids, **kwargs):
        if self.version == 1:
            return self.walk(*oids)
        else:
            return self.bulkwalk(*oids, **kwargs)



# this is for net-snmp multithreding: 
#   call snmp_sess_init first in the main thread
sc = SnmpClient(version=3);



if __name__ == '__main__':
    # kns2000_last_oid = u'1.3.111.2.802.1.1.6.1.7.1.4.1'

    oid = "1.3.6.1.4.1.37561.1.1.1.1.0" # switchType
    sc = SnmpClient(hostname="192.168.2.111", community="public")
    print "get switchType:", sc.get(oid)





