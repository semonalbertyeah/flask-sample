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


    @property
    def id(self):
        return self.encode_device_id(self.mac)

    def to_dict(self):
        d = super(Device, self).to_dict()
        d['id'] = self.id
        return d

    information = relationship(
        "DeviceBaseInfo", 
        cascade='all, delete, delete-orphan', 
        backref='device', 
        uselist=False
    )

    mac_table = relationship(
        "DeviceMacTable", 
        cascade='all, delete, delete-orphan', 
        backref='device'
    )



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





class Test(Base):
    __tablename__ = 'test'

    id = Column(Integer, primary_key=True)    # EUI format: 11-22-33-44-55-66
    val = Column(String(256))
