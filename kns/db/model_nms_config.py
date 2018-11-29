# -*- coding:utf-8 -*-

"""
    NMS config properties
"""

from sqlalchemy import (
    Column, String, PickleType, event
)

# from knmp import KNMP
from .common import Base, ThreadSession

def comparator(a, b):
    return a == b

AUTO_REBOOT_VAL_NO_REBOOT = 0
AUTO_REBOOT_VAL_EVERY_DAY = 1
AUTO_REBOOT_VAL_EVERY_WEEK = 2
AUTO_REBOOT_VAL_EVERY_MONTH = 3

class NMSConfig(Base):
    __tablename__ = 'nmsconfig'
    name = Column(String(255), primary_key=True)
    value = Column(PickleType(comparator=comparator))   # any python types

    keys = {
        "KNMP_NIC_NAME": {
            "default_value": "any"
        },
        "KNMP_AGENT_SCAN_TIMEOUT": {
            "default_value": 5
        },
        "SNMP_TIMEOUT": {
            "default_value": 5
        },
        "SNMP_RETRIES": {
            "default_value": 3
        },
        "SNMP_POLLER_CONCURRENCY": {
            "default_value": 4
        },
        "SNMP_POLLER_PERIOD": {
            "default_value": 3*60
        },
        "TRAP_COMMUNITY": {
            "default_value": "public"
        },
        "PING_TIMEOUT": {
            "default_value": 5
        },

        ################################
        # Automatic Reboot Parameters
        ################################
        "AUTO_REBOOT_SYS": {
            "default_value": AUTO_REBOOT_VAL_EVERY_WEEK
        },

        # 0 ~ 23 (unit: clock)
        "AUTO_REBOOT_SYS_AT": {
            "default_value": 0
        },

        # 0 ~ 6 (Monday ~ Sunday)
        "AUTO_REBOOT_SYS_AT_WEEK_DAY": {
            "default_value": 0
        },

        # 1 ~ 31
        "AUTO_REBOOT_SYS_AT_MONTH_DAY": {
            "default_value": 1
        }
    }

    @staticmethod
    def assure_all():
        try:
            for name, opts in NMSConfig.keys.iteritems():
                rec = ThreadSession.query(NMSConfig).filter(
                    NMSConfig.name == name
                ).scalar()
                if not rec:
                    ThreadSession.add(NMSConfig(name=name, value=opts['default_value']))
                    ThreadSession.commit()
        finally:
            ThreadSession.rollback()
            ThreadSession.remove()

    #############################
    # supported by metaclass
    # defined in nms.db.common
    #############################
    @staticmethod
    def __getitem__(name):
        try:
            rec = ThreadSession.query(NMSConfig).filter(
                NMSConfig.name == name
            ).scalar()

            if rec:
                return rec.value
            else:
                if name in NMSConfig.keys:
                    default_value = NMSConfig.keys[name]['default_value']
                    ThreadSession.add(NMSConfig(name=name, value=default_value))
                    ThreadSession.commit()
                    return default_value
                else:
                    raise KeyError, "%r" % name
        finally:
            ThreadSession.rollback()
            ThreadSession.remove()

    @staticmethod
    def __setitem__(name, value):
        """
            Change value of a config item.
        """
        try:
            rec = ThreadSession.query(NMSConfig).filter(
                NMSConfig.name == name
            ).scalar()

            if rec:
                rec.value = value
                ThreadSession.commit()
            else:
                if name in NMSConfig.keys:
                    ThreadSession.add(NMSConfig(name=name, value=value))
                    ThreadSession.commit()
                else:
                    raise KeyError, "%r" % name
        finally:
            ThreadSession.rollback()
            ThreadSession.remove()


@event.listens_for(NMSConfig.__table__, 'after_create')
def initial_nmsconfig_items(*args, **kwargs):
    """
        Add default configuration items.
    """
    # nics = KNMP.all_netifs()
    # if nics:
    #     nic_name = nics[0].name
    # else:
    #     nic_name = None

    # # add NMS config items on creation of table.
    # ThreadSession.add(NMSConfig(name='KNMP_NIC_NAME', value='any'))
    # ThreadSession.add(NMSConfig(name='KNMP_AGENT_SCAN_TIMEOUT', value=5))
    # # ThreadSession.add(NMSConfig(name="SNMP_READ_COMMUNITY", value='public'))
    # # ThreadSession.add(NMSConfig(name="SNMP_WRITE_COMMUNITY", value='private'))
    # ThreadSession.add(NMSConfig(name="SNMP_TIMEOUT", value=5))
    # ThreadSession.add(NMSConfig(name="SNMP_RETRIES", value=3))
    # ThreadSession.add(NMSConfig(name='SNMP_POLLER_CONCURRENCY', value=4))
    # ThreadSession.add(NMSConfig(name='SNMP_POLLER_PERIOD', value=3*60))
    # ThreadSession.add(NMSConfig(name='TRAP_COMMUNITY', value="public"))
    # # ThreadSession.add(NMSConfig(name="PING_CONCURRENCY", value=255))
    # ThreadSession.add(NMSConfig(name="PING_TIMEOUT", value=5))


    # ################################
    # # Automatic Reboot Parameters
    # ################################
    # ThreadSession.add(NMSConfig(name="AUTO_REBOOT_SYS", value=AUTO_REBOOT_VAL_EVERY_WEEK))
    # # 0 ~ 23 (unit: clock)
    # ThreadSession.add(NMSConfig(name="AUTO_REBOOT_SYS_AT", value=0))
    # # 0 ~ 6 (Monday ~ Sunday)
    # ThreadSession.add(NMSConfig(name="AUTO_REBOOT_SYS_AT_WEEK_DAY", value=0))
    # # 1 ~ 31
    # ThreadSession.add(NMSConfig(name="AUTO_REBOOT_SYS_AT_MONTH_DAY", value=1))

    for name, opts in NMSConfig.keys.iteritems():
        ThreadSession.add(NMSConfig(name=name, value=opts['default_value']))


    ThreadSession.commit()
    ThreadSession.remove()
