# -*- coding:utf-8 -*-

"""
    KNMS logic (url handlers).
"""

#######################
# roles (or user type)
#######################
# admin: all
# guest: only retrieve




import os
import base64
import time
import shutil
import datetime
import warnings
from cStringIO import StringIO
from netaddr import EUI, AddrFormatError
from sqlalchemy import bindparam, func, desc
# from werkzeug import secure_filename
# from werkzeug.exceptions import HTTPException
from flask import (
    Blueprint, request, stream_with_context, 
    send_file, safe_join
)

from utils.dict_util import merge_dicts

from kns.db import db_session, engine, insert_or_update
from kns.db.types import *
from kns.db.model_device import *
from kns.db.model_nms_config import NMSConfig
from kns.logger import logger as root_logger


from ..wrappers import (
    json_response, empty_response, 
    abort, jabort
)

from ..globals import event_poller

from ..auth import policy

logger = root_logger.getChild('rest.knms')

CUR_DIR = os.path.dirname(os.path.abspath(__file__))


mod = Blueprint('kema_nms', __name__)




#############
# macros
#############
KNMP_EXEC_STAT_TIMEOUT = None
KNMP_EXEC_STAT_SUCCESS = 0x00
KNMP_EXEC_STAT_FAILURE = 0x01
KNMP_EXEC_STAT_NO_SUCH = 0xff

KNMP_EXEC_STAT_DISP = {
    KNMP_EXEC_STAT_TIMEOUT: 'timeout',
    KNMP_EXEC_STAT_SUCCESS: 'success',
    KNMP_EXEC_STAT_FAILURE: 'failure',
    KNMP_EXEC_STAT_NO_SUCH: 'no such'
}



#########################################
#   devices
#       id: urlsafe_b64encode(mac)
#########################################
@policy.allow('guest', methods=['GET'])
@mod.route(r'/devices', methods=['GET', 'PUT'])
def devices():
    """
        GET:
            response application/json
                {
                    'devices': [
                        {dev1_info}, {dev2_info}, ...
                    ]
                }

        POST(add), PUT(update or add):
            request application/json
                {
                    'devices': [{dev1_info}, {dev2_info}, ...]
                }
            or 
                {
                    'device': {dev_info}
                }
            or both
            PUT will update existing devices, and "id" could be used.
            POST will cause error on creating existing devices.
    """
    if request.method == 'GET':
        recs = db_session.query(Device).all()
        devs = []
        for rec in recs:
            dev = rec.to_dict()
            devs.append(dev)

        return json_response({'devices': devs})

    elif request.method == "PUT":
        """
            PUT data
            application/json
            {
                // mac is primary key
                "devices": [
                    {"mac": mac, other fields},
                    ...
                ]
            }
        """
        devs_info = request.json['devices']
        if not isinstance(devs_info, (tuple, list, set)):
            devs_info = [devs_info]
        values = []
        for info in devs_info:
            dev_info, err_msg = Device.fill_default(info)
            if dev_info is None:
                jabort({"msg": err_msg}, 400)


            values.append(dev_info)


        if not values:
            return empty_response()

        conn = engine.connect()

        # update devices
        conn.execute(
            insert_or_update(
                Device.__table__, 
                'mac', 'flag', 'ip', 'netmask',
                'gateway', 'vlan', 'device_name',
                'product_name', 'ip_on', 'snmp_on',
                "from_nic"
            ),
            values
        )

        conn.close()
        return empty_response()







@mod.route(r'/devices/information', methods=['GET'])
def devices_info():
    """
        GET: all devices information
    """
    recs = db_session.query(DeviceBaseInfo).all()
    return json_response({'informations': [rec.to_dict() for rec in recs]})



@mod.route(r'/devices/macs', methods=["GET"])
def devices_mac_table():
    """
        all devices mac table.
    """
    recs = db_session.query(
        DeviceMacTable, Device.device_name, Device.ip
    ).filter(
        DeviceMacTable.device_mac == Device.mac
    ).all()
    macs = [
        merge_dicts(
            rec.DeviceMacTable.to_dict(), 
            {'device_ip': rec.ip, 'device_name': rec.device_name}
        )
        for rec in recs
    ]
    return json_response({'macs': macs})





#######################
# NMS Config options
#######################
@mod.route(r'/config/', methods=['GET', 'POST'])
def nms_config():
    """
        GET /config/   -> return all configurations
        POST /config/
            application/json
            {
                "config": {
                    "cfg_name1": cfg_value1,
                    "cfg_name2": cfg_value2
                    ...
                }
            }
    """
    NMSConfig.assure_all()
    cfg_recs = db_session.query(NMSConfig).all()

    if request.method == 'POST':
        # update config
        new_cfgs = request.json['config']
        assert isinstance(new_cfgs, dict), 'Wrong posted configurations: %r' % new_cfgs

        for rec in cfg_recs:
            if rec.name in new_cfgs:
                rec.value = new_cfgs[rec.name]

        db_session.commit()

    return json_response({"config": [rec.to_dict() for rec in cfg_recs]})



@event_poller.on(name="alarm", methods=["POST"])
def alarm():
    """
        Test alarm.
        This is used retrieve alarm from web server.
        Using of POST is to request with some optional variables.
    """

    return ["alarm1", "alarm2", "alarm3"]

