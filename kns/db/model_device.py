# -*- coding:utf-8 -*-

"""
    device-related models.
"""

import base64
import netaddr
from netaddr import EUI

from utils.ip_util import valid_netmask


from sqlalchemy import String, Integer, Boolean, Enum
########################################################
# mysql integer: 
#   TINYINT: 1-byte  
#       (-128 ~ 127) 
#       (0 ~ 255)
#   SMALLINT: 2-byte  
#       (-32768 ~ 32767)
#       (0 ~ 65535)
#   MEDIUMINT: 3-byte  
#       (-8388608 ~ 8388607)
#       (0 ~ 16777215)
#   INT: 4-byte  
#       (-2147483648 ~ 2147483647)
#       (0 ~ 4294967295)
#   BIGINT: 8-byte  
#       (-9223372036854775808 ~ 9223372036854775807)
#       (0 ~ 18446744073709551615)
########################################################
from sqlalchemy.dialects.mysql import (
    TINYINT, SMALLINT, MEDIUMINT,
    INTEGER, BIGINT
)
from sqlalchemy import Column, ForeignKey
from sqlalchemy.orm import relationship


from .common import Base
from .types import (
    IpAddress, MacAddress, NamedIntEnum, IntegerList,
    KnsPorts, StpBridgeId, SnmpTruthValue, IntEnum
)





class Device(Base):
    __tablename__ = 'devices'

    mac = Column(MacAddress, primary_key=True)    # EUI format: 11-22-33-44-55-66
    flag = Column(TINYINT(unsigned=True))          # 8-bit integer, flag
    ip = Column(IpAddress)          # display of ip: 192.168.1.1
    netmask = Column(IpAddress)     # same as above
    gateway = Column(IpAddress)     # same as above
    vlan = Column(SMALLINT(unsigned=True))          # range: 0 ~ 4095
    device_name = Column(String(100))
    product_name = Column(String(100))
    from_nic = Column(String(64))   # the name of NIC from which the device is scanned.

    knmp_on = Column(Boolean, default=False)
    ip_on = Column(Boolean, default=False)
    snmp_on = Column(Boolean, default=False)

    def __repr__(self):
        return u"<Device mac=%s, ip=%s>" % (unicode(self.mac), self.ip)

    @classmethod
    def fill_default(cls, dev_info):
        """
            check dev_info validity and add default value for empty field
            input:
                dev_info -> {
                    mac: EUI mac,
                    flag: 1 or 0,
                    ip: "192.168.0.3",
                    netmask: "255.255.255.0",
                    gateway: "192.168.0.1",
                    vlan: 1 ~ 4095,
                    device_name: "deivce1",
                    product_name: "KNS5000",
                    from_nic: "eth0",
                    ip_on: True or False,
                    snmp_on: True or False
                }
        """
        try:
            dev_info = dict(dev_info)
        except Exception:
            return None, "Invalid device info %r" % dev_info

        # check mac
        if "mac" not in dev_info:
            return None, "device with no MAC address."

        try:
            mac = unicode(EUI(unicode(dev_info['mac'])))
        except AddrFormatError as e:
            return None, "invalid MAC address %r" % dev_info['mac']

        # check flag value
        try:
            flag = int(dev_info.get('flag') or 0)
        except Exception:
            return None, "invalid flag %r" % dev_info['flag']

        if flag not in (1,0):
            return None, "invalid flag value %d" % flag

        # check ip
        try:
            ip = IpAddress.ip_pretty(dev_info.get("ip") or "0.0.0.0")
        except Exception:
            return None, "Invalid IP %r" % dev_info['ip']

        # check netmask
        try:
            netmask = IpAddress.ip_pretty(dev_info.get("netmask") or "255.255.255.0")
        except Exception:
            return None, "Invalid netmask %r" % dev_info['netmask']

        if not valid_netmask(netmask):
            return None, "Invalid netmask %r" % netmask

        # check gateway
        try:
            gateway = IpAddress.ip_pretty(dev_info.get("gateway") or "0.0.0.0")
        except Exception:
            return None, "Invalid gateway %r" % dev_info["gateway"]

        # check vlan
        try:
            vlan = int(dev_info.get("vlan") or 1)
        except Exception:
            return None, "Invalid VLAN %r" % dev_info["vlan"]

        if vlan < 1 or vlan > 4095:
            return None, "Invalid VLAN value %r" % vlan

        # check device_name
        device_name_max = cls.device_name.property.columns[0].type.length
        try:
            device_name = unicode(dev_info.get("device_name") or u"")
        except Exception:
            return None, "Invalid device name %r" % dev_info["device_name"]

        if len(device_name) > device_name_max:
            return None, "device name is too long, max length is %d." % device_name_max

        # check product_name
        product_name_max = cls.product_name.property.columns[0].type.length
        try:
            product_name = unicode(dev_info.get("product_name") or u"")
        except Exception:
            return None, "Invalid product name %r" % dev_info["product_name"]

        if len(product_name) > product_name_max:
            return None, "Product name is toolong, max length is %d." % product_name_max

        # check ip_on
        try:
            ip_on = bool(dev_info.get('ip_on') or False)
        except Exception:
            return None, "Invalid ip_on value %r" % dev_info['ip_on']

        # check snmp_on
        try:
            snmp_on = bool(dev_info.get('snmp_on') or False)
        except Exception:
            return None, "Invalid snmp_on value %r" % dev_info['snmp_on']

        from_nic = dev_info.get("from_nic", "")

        # mac | flag | ip | netmask | gateway | vlan | device_name | product_name | from_nic | knmp_on | ip_on | snmp_on
        return {
            "mac": mac,
            "flag": flag,
            "ip": ip,
            "netmask": netmask,
            "gateway": gateway,
            "vlan": vlan,
            "device_name": device_name,
            "product_name": product_name,
            "ip_on": ip_on,
            "snmp_on": snmp_on,
            "from_nic": from_nic
        }, ""




    @staticmethod
    def encode_device_id(dev_mac, safe=False):
        try:
            return base64.urlsafe_b64encode(str(
                EUI(str(dev_mac))
            ))
        except (netaddr.core.AddrFormatError) as e:
            if safe:
                return None
            else:
                raise

    @staticmethod
    def decode_device_id(dev_id, safe=False):
        try:
            return str(EUI(
                base64.urlsafe_b64decode(str(dev_id))
            ))
        except (TypeError, netaddr.core.AddrFormatError) as e:
            if safe:
                return None
            else:
                raise

    @property
    def id(self):
        return self.encode_device_id(self.mac)

    def to_dict(self):
        d = super(Device, self).to_dict()
        d['id'] = self.id
        return d

    snmp = relationship(
        "SnmpConfig", 
        cascade='all, delete, delete-orphan', 
        backref='device', 
        uselist=False
    )

    information = relationship(
        "DeviceBaseInfo", 
        cascade='all, delete, delete-orphan', 
        backref='device', 
        uselist=False
    )

    mac_num = relationship(
        "DeviceMacNumber", 
        cascade='all, delete, delete-orphan', 
        backref='device', 
        uselist=False
    )

    mac_table = relationship(
        "DeviceMacTable", 
        cascade='all, delete, delete-orphan', 
        backref='device'
    )

    ports_num = relationship(
        "DevicePortNumber", 
        cascade='all, delete, delete-orphan', 
        backref='device', 
        uselist=False
    )

    ports = relationship(
        "DevicePortInterfaces", 
        cascade='all, delete, delete-orphan', 
        backref='device'
    )


    lldp_num = relationship(
        "DeviceLldpNum", 
        cascade='all, delete, delete-orphan', 
        backref='device', 
        uselist=False
    )

    lldp = relationship(
        "DeviceLldp", 
        cascade='all, delete, delete-orphan', 
        backref='device'
    )

    lldp_local_ports = relationship(
        "DeviceLldpLocalPortTable",
        cascade='all, delete, delete-orphan',
        backref='device'
    )

    lldp_remote_table = relationship(
        "DeviceLldpRemoteTable",
        cascade='all, delete, delete-orphan',
        backref='device'
    )

    mstp_config = relationship(
        "DeviceMstpConfig",
        cascade='all, delete, delete-orphan',
        backref='device',
        uselist=False
    )

    mstp_cist = relationship(
        "DeviceMstpCist",
        cascade="all, delete, delete-orphan",
        backref='device',
        uselist=False
    )

    mstp_cist_ports = relationship(
        "DeviceMstpCistPort",
        cascade='all, delete, delete-orphan',
        backref='device'
    )

    msti_table = relationship(
        "DeviceMstiTable",
        cascade="all, delete, delete-orphan",
        backref='device'
    )

    msti_ports = relationship(
        "DeviceMstiPort",
        cascade='all, delete, delete-orphan',
        backref='device'
    )

    vlan_table = relationship(
        "DeviceVlan",
        cascade='all, delete, delete-orphan',
        backref='device'
    )

    pvid_table = relationship(
        "DevicePvid",
        cascade='all, delete, delete-orphan',
        backref='device'
    )

class SnmpConfig(Base):
    """
        Devices' SNMP configuration information
            version: 
                1 -> SNMPv1
                2 -> SNMPv2c
                3 -> SNMPv3
    """
    v1 = 1
    v2c = 2
    v3  = 3
    supported_version = [v1, v2c, v3]

    __tablename__ = 'snmp_config'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    device_mac = Column(MacAddress, ForeignKey("devices.mac"), unique=True)

    version = Column(IntEnum(v1, v2c, v3), default=v2c)

    # SNMP v1/v2c
    v2c_community = Column(String(255))

    # SNMP v3
    v3_username = Column(String(255))
    v3_engine_id = Column(String(255))  # TODO: specific type for engine id, or checked by user
    v3_context_name = Column(String(255))
    auth_proto_enum = ("none", "MD5", "SHA")
    v3_auth_protocol = Column(Enum(*auth_proto_enum), default="none")
    v3_auth_password = Column(String(255))
    priv_proto_enum = ("none", "DES")
    v3_priv_protocol = Column(Enum(*priv_proto_enum), default="none")
    v3_priv_password = Column(String(255))



class DeviceBaseInfo(Base):
    """
        Basic information.
        sysDescr    1.3.6.1.2.1.1.1
        sysUpTime   1.3.6.1.2.1.1.3
        switchinformation   1.3.6.1.4.1.37561.1.1.1
    """
    PWR_STAT_ABSENT = 0
    PWR_STAT_NORMAL = 1
    PWR_STAT_FAULT = 2

    __tablename__ = 'mib_basic_info'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    sysDescr = Column(String(255))
    sysUpTime = Column(INTEGER(unsigned=True))
    switchType = Column(String(255))
    switchDescription = Column(String(255))
    switchCompany = Column(String(255))
    switchPortNum = Column(INTEGER(unsigned=True))
    switchHwVersion = Column(String(64))
    switchFwVersion = Column(String(64))
    switchSwVersion = Column(String(64))
    switchIP = Column(IpAddress)
    switchMAC = Column(MacAddress)
    switchTemperature = Column(INTEGER(unsigned=True))

    switchPwrState_enum = {'absent': 0, 'normal': 1, 'fault': 2}
    switchPwr1State = Column(
        NamedIntEnum(
            enums=switchPwrState_enum
        )
    )
    @property
    def switchPwr1State_val(self):
        if self.switchPwr1State is None:
            return None
        else:
            return self.switchPwrState_enum[self.switchPwr1State]

    switchPwr2State = Column(
        NamedIntEnum(
            enums=switchPwrState_enum
        )
    )
    @property
    def switchPwr2State_val(self):
        if self.switchPwr2State is None:
            return None
        else:
            return self.switchPwrState_enum[self.switchPwr2State]

    def to_dict(self):
        d = super(DeviceBaseInfo, self).to_dict()
        d['switchPwr1State_val'] = self.switchPwr1State_val
        d['switchPwr2State_val'] = self.switchPwr2State_val
        return d



class DeviceMacNumber(Base):
    """
        The number of MAC records.
        sfdbnumber  1.3.6.1.4.1.37561.1.1.4.1
    """
    __tablename__ = 'mib_mac_number'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    sfdbnumber = Column(INTEGER(unsigned=True))


class DeviceMacTable(Base):
    """
        MAC table.
        sfdbtable   1.3.6.1.4.1.37561.1.1.4.2
    """
    __tablename__ = 'mib_mac_table'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    mac = Column(MacAddress)
    vlan = Column(SMALLINT(unsigned=True))
    ports = Column(KnsPorts)
    state = Column(Enum('Dynamic', 'Static')) # "Dynamic"


    @property
    def ports_disp(self):
        if self.ports is None:
            return None
        else:
            return KnsPorts.list_to_display(self.ports)

    def to_dict(self):
        d = super(DeviceMacTable, self).to_dict()
        d['ports_disp'] = self.ports_disp
        return d


class DevicePortNumber(Base):
    """
        The number of ports.
        sIfNumber   1.3.6.1.4.1.37561.1.1.2.1
    """
    __tablename__ = 'mib_port_number'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    sIfNumber = Column(INTEGER(unsigned=True))


class DevicePortInterfaces(Base):
    """
        Status of all ports
        sIfTable    1.3.6.1.4.1.37561.1.1.2.2.1
    """
    __tablename__ = 'mib_port_interfaces'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    sIfIndex = Column(Integer)
    sIfDescr = Column(String(50))
    sIfSpeed = Column(Integer)

    sIfStatus_enum = {'up': 1, 'down': 2, 'testing': 3}
    sIfStatus = Column(NamedIntEnum(enums=sIfStatus_enum))
    @property
    def sIfStatus_val(self):
        if self.sIfStatus is None:
            return None
        else:
            return self.sIfStatus_enum[self.sIfStatus]

    sIfInOctets = Column(INTEGER(unsigned=True))
    sIfInUcastPkts = Column(INTEGER(unsigned=True))
    sIfInMcastPkts = Column(INTEGER(unsigned=True))
    sIfInBcastPkts = Column(INTEGER(unsigned=True))
    sIfOutOctets = Column(INTEGER(unsigned=True))
    sIfOutUcastPkts = Column(INTEGER(unsigned=True))
    sIfOutMcastPkts = Column(INTEGER(unsigned=True))
    sIfOutBcastPkts = Column(INTEGER(unsigned=True))
    sIfFiberRxPwr = Column(INTEGER(unsigned=True))
    sIfFiberTxPwr = Column(INTEGER(unsigned=True))

    def to_dict(self):
        d = super(DevicePortInterfaces, self).to_dict()
        d['sIfStatus_val'] = self.sIfStatus_val
        return d



class DeviceLldpNum(Base):
    """
        The number of records in LLDP table
        stoponeinumber  1.3.6.1.4.1.37561.1.1.3.1
    """
    __tablename__ = 'mib_lldp_num'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    sTopoNeiNumber = Column(Integer)


class DeviceLldp(Base):
    """
        The LLDP records.
        stoponeitable   1.3.6.1.4.1.37561.1.1.3.2.1
    """
    __tablename__ = 'mib_lldp'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    sTopoNeiIndex = Column(Integer)
    sLocalIfIndex = Column(Integer)
    sLocalPortID = Column(String(100))
    sRemoteIP = Column(IpAddress)
    sRemoteMAC = Column(MacAddress)
    sRemotePortID = Column(String(100))
    sRemoteDeviceType = Column(String(100))
    sRemoteDeviceDesc = Column(String(500))


lldp_chassis_id_subtype_enum = {
    'chassisComponent': 1,
    'interfaceAlias': 2,
    'portComponent': 3,
    'macAddress': 4,
    'networkAddress': 5,
    'interfaceName': 6,
    'local': 7
}
lldp_port_id_subtype_enum = {
    'interfaceAlias': 1,
    'portComponent': 2,
    'macAddress': 3,
    'networkAddress': 4,
    'interfaceName': 5,
    'agentCircuitId': 6,
    'local': 7
}

class DeviceLldpLocalPortTable(Base):
    """
        lldpLocPortTable - 1.0.8802.1.1.2.1.3.7
    """
    __tablename__ = 'mib_lldp_loc_port_table'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    lldpLocPortNum = Column(Integer)

    lldpLocPortIdSubtype = Column(NamedIntEnum(enums=lldp_port_id_subtype_enum))
    @property
    def lldpLocPortIdSubtype_val(self):
        if self.lldpLocPortIdSubtype is None:
            return None
        else:
            return lldp_port_id_subtype_enum[self.lldpLocPortIdSubtype]

    lldpLocPortId = Column(String(50))
    lldpLocPortDesc = Column(String(50))

    def to_dict(self):
        d = super(DeviceLldpLocalPortTable, self).to_dict()
        d['lldpLocPortIdSubtype_val'] = self.lldpLocPortIdSubtype_val
        return d


class DeviceLldpRemoteTable(Base):
    """
        lldpRemTable - 1.0.8802.1.1.2.1.4.1
    """
    __tablename__ = 'mib_lldp_remote_table'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    lldpRemTimeMark = Column(Integer)
    lldpRemLocalPortNum = Column(Integer)
    lldpRemIndex = Column(Integer)

    lldpRemChassisIdSubtype = Column(NamedIntEnum(enums=lldp_chassis_id_subtype_enum))
    @property
    def lldpRemChassisIdSubtype_val(self):
        if self.lldpRemChassisIdSubtype is None:
            return None
        else:
            return lldp_chassis_id_subtype_enum[self.lldpRemChassisIdSubtype]

    lldpRemChassisId = Column(MacAddress)

    lldpRemPortIdSubtype = Column(NamedIntEnum(enums=lldp_port_id_subtype_enum))
    @property
    def lldpRemPortIdSubtype_val(self):
        if self.lldpRemPortIdSubtype is None:
            return None
        else:
            return lldp_port_id_subtype_enum[self.lldpRemPortIdSubtype]

    lldpRemPortId = Column(String(50))
    lldpRemPortDesc = Column(String(255))
    lldpRemSysName = Column(String(255))
    lldpRemSysDesc = Column(String(255))
    lldpRemSysCapSupported = Column(Integer)
    lldpRemSysCapEnabled = Column(Integer)

    def to_dict(self):
        d = super(DeviceLldpRemoteTable, self).to_dict()
        d['lldpRemChassisIdSubtype_val'] = self.lldpRemChassisIdSubtype_val
        d['lldpRemPortIdSubtype_val'] = self.lldpRemPortIdSubtype_val
        return d



class DeviceMstpConfig(Base):
    """
        ieee8021MstpConfigIdTable - 1.3.111.2.802.1.1.6.1.7
    """
    __tablename__ = 'mib_mstp_config'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    format_selector = Column(Integer)
    config_name = Column(String(100))
    revision = Column(INTEGER(unsigned=True))
    digest = Column(String(100))    # show digest in display string



class DeviceMstpCist(Base):
    """
        ieee8021MstpCistTable - 1.3.111.2.802.1.1.6.1.1
    """
    __tablename__ = 'mib_mstp_cist'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    bridge_id = Column(StpBridgeId)
    topology_change = Column(SnmpTruthValue)
    regional_root_id = Column(StpBridgeId)
    path_cost = Column(INTEGER(unsigned=True))
    max_hops = Column(Integer)


class DeviceMstpCistPort(Base):
    """
        ieee8021MstpCistPortTable - 1.3.111.2.802.1.1.6.1.3
    """
    __tablename__ = 'mib_mstp_cist_port'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    port_id = Column(INTEGER(unsigned=True))
    up_time = Column(INTEGER(unsigned=True))
    admin_path_cost = Column(Integer)
    designated_root = Column(StpBridgeId)
    topology_change_ack = Column(SnmpTruthValue)
    hello_time = Column(Integer)
    admin_edge_port = Column(SnmpTruthValue)
    operational_edge_port = Column(SnmpTruthValue)
    mac_enabled = Column(SnmpTruthValue)
    mac_operational = Column(SnmpTruthValue)
    restricted_role = Column(SnmpTruthValue)
    restricted_tcn = Column(SnmpTruthValue)

    role_enum = {
        'root':1,
        'alternate': 2,
        'designated': 3,
        'backup': 4,
        'disabled': 0
    }
    role = Column(NamedIntEnum(enums=role_enum))
    @property
    def role_val(self):
        if self.role is None:
            return None
        else:
            return self.role_enum[self.role]

    disputed = Column(SnmpTruthValue)
    cist_regional_root_id = Column(StpBridgeId)
    cist_path_cost = Column(INTEGER(unsigned=True))
    protocol_migration = Column(SnmpTruthValue)
    rx_bpdu = Column(SnmpTruthValue)
    tx_bpdu = Column(SnmpTruthValue)
    pseudo_root_id = Column(StpBridgeId)
    is_l2gp = Column(SnmpTruthValue)

    def to_dict(self):
        d = super(DeviceMstpCistPort, self).to_dict()
        d['role_val'] = self.role_val
        return d



class DeviceMstiTable(Base):
    """
        ieee8021MstpTable - 1.3.111.2.802.1.1.6.1.2
    """
    __tablename__ = 'mib_mstp_msti'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    mstid = Column(INTEGER(unsigned=True)) # form last index
    bridge_id = Column(StpBridgeId)
    time_since_tcn = Column(INTEGER(unsigned=True))
    topology_changes = Column(BIGINT(unsigned=True))
    topology_change = Column(SnmpTruthValue)
    designated_root = Column(StpBridgeId)
    root_path_cost = Column(Integer)
    root_port = Column(INTEGER(unsigned=True))
    bridge_pri = Column(Integer)
    vids = Column(IntegerList(length=4*2048))   # vlan assigned to such MSTI

    @property
    def vids_disp(self):
        if self.vids is None:
            return None
        else:
            return IntegerList.list_to_display(self.vids)

    def to_dict(self):
        d = super(DeviceMstiTable, self).to_dict()
        d['vids_disp'] = self.vids_disp
        return d


class DeviceMstiPort(Base):
    """
        ieee8021MstpPortTable - 1.3.111.2.802.1.1.6.1.4
    """
    __tablename__ = 'mib_mstp_msti_port'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    port_number = Column(INTEGER(unsigned=True))
    up_time = Column(INTEGER(unsigned=True))

    state_enum = {
        'unknown': 0,
        'disabled': 1, 
        'listening': 2, 
        'learning': 3, 
        'forwarding': 4, 
        'blocking': 5
    }
    state = Column(NamedIntEnum(enums=state_enum))
    @property
    def state_val(self):
        if self.state is None:
            return None
        else:
            return self.state_enum[self.state]

    priority = Column(Integer)
    path_cost = Column(Integer)
    designated_root = Column(StpBridgeId)
    designated_cost = Column(Integer)
    designated_bridge = Column(StpBridgeId)
    designated_port = Column(INTEGER(unsigned=True))

    role_enum = {
        "root": 1,
        'alternate': 2,
        'designated': 3,
        'backup': 4,
        'disabled': 5
    }
    role = Column(NamedIntEnum(enums=role_enum))

    @property
    def role_val(self):
        if self.role is None:
            return None
        else:
            return self.role_enum[self.role]

    disputed = Column(SnmpTruthValue)

    def to_dict(self):
        d = super(DeviceMstiPort, self).to_dict()
        d['role_val'] = self.role_val
        return d



class DeviceVlan(Base):
    """
        ieee8021QBridgeVlanStaticTable - 1.3.111.2.802.1.1.4.1.4.3
    """
    __tablename__ = 'mib_vlan'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    vlan_id = Column(INTEGER(unsigned=True))
    vlan_name = Column(String(64))
    egress_ports = Column(KnsPorts)
    untagged_ports = Column(KnsPorts)

    @property
    def egress_ports_disp(self):
        if self.egress_ports is None:
            return None
        else:
            return KnsPorts.list_to_display(self.egress_ports)

    @property
    def untagged_ports_disp(self):
        if self.untagged_ports is None:
            return None
        else:
            return KnsPorts.list_to_display(self.untagged_ports)

    @property
    def tagged_ports(self):
        if not self.egress_ports:
            return []
        elif not self.untagged_ports:
            return self.egress_ports
        else:
            return list(set(self.egress_ports) - set(self.untagged_ports))

    @property
    def tagged_ports_disp(self):
        if self.tagged_ports is None:
            return None
        else:
            return KnsPorts.list_to_display(self.tagged_ports)

    def to_dict(self):
        d = super(DeviceVlan, self).to_dict()
        d['egress_ports_disp'] = self.egress_ports_disp
        d['untagged_ports_disp'] = self.untagged_ports_disp
        d['tagged_ports'] = self.tagged_ports
        d['tagged_ports_disp'] = self.tagged_ports_disp
        return d


class DevicePvid(Base):
    """
        ieee8021QBridgePortVlanTable - 1.3.111.2.802.1.1.4.1.4.5
    """
    __tablename__ = 'mib_pvid'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    polled_at = Column(INTEGER(unsigned=True)) # utc timestamp
    device_mac = Column(MacAddress, ForeignKey("devices.mac"))

    port_number = Column(INTEGER(unsigned=True))
    pvid = Column(INTEGER(unsigned=True))

    accepted_frame_type_enum = {'admit_all': 1, 'admit_untagged_and_priority': 2, 'admit_tagged': 3}
    accepted_frame_type = Column(
        NamedIntEnum(
            enums=accepted_frame_type_enum
        )
    )
    @property
    def accepted_frame_type_val(self):
        if self.accepted_frame_type is None:
            return None
        else:
            return self.accepted_frame_type_enum[self.accepted_frame_type]

    ingress_filtering = Column(SnmpTruthValue)

    def to_dict(self):
        d = super(DevicePvid, self).to_dict()
        d['accepted_frame_type_val'] = self.accepted_frame_type_val
        return d


class Test(Base):
    __tablename__ = 'test'

    id = Column(Integer, primary_key=True)    # EUI format: 11-22-33-44-55-66
    val = Column(String(256))




