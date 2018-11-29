# -*- coding:utf-8 -*-

"""
    KNMS logic (url handlers).
"""

#######################
# roles (or user type)
#######################
# admin: all
# guest: only retrieve


#################################
# frontend, backend url handling
#################################
# "/{resources}/" GET
# store: {
#     proxy: {
#         type: 'ajax',
#         url: '/{resources}/',
#         reader: {
#             type: 'json',
#             rootProperty: '{resources}'
#         }
#     }
# }

# "/{resources}/" POST
# Utils.request.Ajax.post({
#     url: '/{resources}/',
#     json: {resource: ..various resource info...},
#     success: function(response) {
#         console.log(response.json);
#     }
# })

# "/{resources}/{id}" PUT
# Utils.request.Ajax.put({
#     url: "/{resources}/{id}",
#     json: {resource: {...newly_added_resource_info...}},
#     success: function(response) {...}
# })

# "/{resources}/{id}" GET
# Utils.request.Ajax.post({
#     url: "/{resources}/{id}",
#     success: function(response) {...}
# })

# "/{resources}/{id}" PATCH
# Utils.request.Ajax.patch({
#     url: "/{resources}/{id}",
#     json: {resource: ...updated_resource_attr...},
#     success: function(response) {...}
# })

# "/{resources}/{id}" DELETE
# Utils.request.Ajax.delete({
#     url: "/{resources}/{id}",
#     success: function(response) {...}
# })


# ERROR response
# show in dialog


import os
import base64
import time
import shutil
import datetime
import warnings
from cStringIO import StringIO
from netaddr import EUI, AddrFormatError
from sqlalchemy import bindparam, func, desc
from werkzeug import secure_filename
from werkzeug.exceptions import HTTPException
from flask import (
    Blueprint, request, stream_with_context, 
    send_file, safe_join
)

from utils.ip_util import same_net
from utils.xml_util import valid_xml
from utils.time_util import wait, datetime_utc_2_local
from utils.dict_util import merge_dicts
from utils.data import ip_2_int, ip_pretty

from kns.db import db_session, engine, insert_or_update
from kns.db.types import *
from kns.db.model_device import *
from kns.db.model_nms_config import NMSConfig
from kns.db.model_s import *
from kns.logger import logger as root_logger


from ..wrappers import (
    json_response, empty_response, 
    abort, jabort,
    knmp_client,
    snmp_client
)

from ..globals import event_poller

from ..auth import policy

from .cfgfile import (
    ConfigFile, ConfigFileBundle, assure_dev_cfg_dir,
    get_device_config_files_info, get_config_file_info
)


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

            # version = Column(IntEnum(v2c, v3), default=v3)

            # # SNMP v2c
            # v2c_community = Column(String(255))

            # # SNMP v3
            # v3_username = Column(String(255))
            # v3_engine_id = Column(String(255))  # TODO: specific type for engine id, or checked by user
            # v3_context_name = Column(String(255))
            # v3_auth_protocol = Column(Enum(*auth_proto_enum), default="none")
            # v3_auth_password = Column(String(255))
            # v3_priv_protocol = Column(Enum(*priv_proto_enum), default="none")
            # v3_priv_password = Column(String(255))

            snmp_cfg = {
                "snmp_version": None,
                "snmp_v3_engine_id": "",
                "snmp_v3_context_name": "",
                "snmp_v3_auth_protocol": "none",
                "snmp_v3_priv_protocol": "none"
            }

            if rec.snmp:
                snmp_cfg = {
                    "snmp_version": rec.snmp.version,
                    "snmp_v3_engine_id": rec.snmp.v3_engine_id,
                    "snmp_v3_context_name": rec.snmp.v3_context_name,
                    "snmp_v3_auth_protocol": rec.snmp.v3_auth_protocol,
                    "snmp_v3_priv_protocol": rec.snmp.v3_priv_protocol
                }

            dev.update(snmp_cfg)
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
        snmp_cfgs = []
        for info in devs_info:
            # 
            dev_info, err_msg = Device.fill_default(info)
            if dev_info is None:
                jabort({"msg": err_msg}, 400)


            values.append(dev_info)

            snmp_cfgs.append({
                "device_mac": dev_info['mac'],
                "version": info.get("snmp_version") or SnmpConfig.v2c,
                "v2c_community": info.get("snmp_v2c_community") or "public",
                "v3_username": info.get("snmp_v3_username") or None,
                "v3_engine_id": info.get("snmp_v3_engine_id") or None,
                "v3_context_name": info.get("snmp_v3_context_name") or None,
                "v3_auth_protocol": info.get("snmp_v3_auth_protocol") or None,
                "v3_auth_password": info.get("snmp_v3_auth_password") or None,
                "v3_priv_protocol": info.get("snmp_v3_priv_protocol") or None,
                "v3_priv_password": info.get("snmp_v3_priv_password") or None
            })

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

        # update snmp_config
        conn.execute(
            insert_or_update(
                SnmpConfig.__table__, 
                "device_mac", "version", "v2c_community",
                "v3_username", "v3_engine_id", "v3_context_name",
                "v3_auth_protocol", "v3_auth_password", "v3_priv_protocol",
                "v3_priv_password"
            ),
            snmp_cfgs
        )

        conn.close()
        return empty_response()




from sqlalchemy import select
@mod.route(r"/devices/csv", methods=["GET", "POST"])
def device_csv():
    """
        GET /devices/csv
    """

    if request.method == "GET":
        conn = engine.connect()
        try:
            snmp_config = SnmpConfig.__table__
            devices = Device.__table__
            stmt = select([
                    devices.c.mac, 
                    devices.c.ip,
                    devices.c.netmask,
                    devices.c.gateway,
                    devices.c.vlan,
                    devices.c.device_name,
                    devices.c.product_name,
                    snmp_config.c.version.label("snmp_version"),
                    snmp_config.c.v2c_community.label("snmp_v2c_community"),
                    snmp_config.c.v3_username.label("snmp_v3_username"),
                    snmp_config.c.v3_engine_id.label("snmp_v3_engine_id"),
                    snmp_config.c.v3_context_name.label("snmp_v3_context_name"),
                    snmp_config.c.v3_auth_protocol.label("snmp_v3_auth_protocol"),
                    snmp_config.c.v3_auth_password.label("snmp_v3_auth_password"),
                    snmp_config.c.v3_priv_protocol.label("snmp_v3_priv_protocol"),
                    snmp_config.c.v3_priv_password.label("snmp_v3_priv_password")
                ]).select_from(
                    devices.outerjoin(snmp_config, devices.c.mac == snmp_config.c.device_mac)
                )
            recs = conn.execute(stmt).fetchall()

            ##############################
            # some day, v3 will be here
            ##############################
            
            csv_arr = [
                "mac,ip,netmask,gateway,vlan,device_name,product_name,snmp_version,snmp_v2c_community,snmp_v3_username,snmp_v3_engine_id,snmp_v3_context_name,snmp_v3_auth_protocol,snmp_v3_auth_password,snmp_v3_priv_protocol,snmp_v3_priv_password"
            ]
            csv_arr.extend( [
                ','.join((
                    rec['mac'],
                    rec['ip'] or "",
                    rec['netmask'] or "",
                    rec['gateway'] or "",
                    str(rec['vlan']) if rec['vlan'] else "",
                    rec['device_name'] or "",
                    rec['product_name'] or "",
                    str(rec['snmp_version']) if rec['snmp_version'] else "",
                    rec['snmp_v2c_community'] or "",
                    rec['snmp_v3_username'] or "",
                    rec['snmp_v3_engine_id'] or "",
                    rec['snmp_v3_context_name'] or "",
                    rec['snmp_v3_auth_protocol'] or "",
                    rec['snmp_v3_auth_password'] or "",
                    rec['snmp_v3_priv_protocol'] or "",
                    rec['snmp_v3_priv_password'] or ""
                ))
                for rec in recs
            ] )

            # csv_arr = [
            #     "mac,ip,netmask,gateway,vlan,device_name,product_name,snmp_version,snmp_community"
            # ]
            # csv_arr.extend( [
            #     ','.join((
            #         rec['mac'],
            #         rec['ip'] or "",
            #         rec['netmask'] or "",
            #         rec['gateway'] or "",
            #         str(rec['vlan']) if rec['vlan'] else "",
            #         rec['device_name'] or "",
            #         rec['product_name'] or "",
            #         str(rec['snmp_version']) if rec['snmp_version'] else "",
            #         rec['snmp_v2c_community'] or ""
            #     ))
            #     for rec in recs
            # ] )

            csv = '\n'.join(csv_arr)
        finally:
            conn.close()

        f = StringIO(csv)
        return send_file(f, mimetype='text/csv', as_attachment=True, attachment_filename='devices.csv')
    else:
        csv_file = request.files['device_csv']
        csv = csv_file.read()
        dev_values = []
        snmp_values = []
        for row in csv.split("\n"):
            row = row.replace("\r", "").split(",")

            # MAC
            mac = row[0]
            if not MacAddress.is_unicast(mac):
                logger.warn("Import CSV: not unicast MAC %r" % mac)
                continue

            # IP
            ip = row[1] or None
            if ip and not IpAddress.valid(ip):
                logger.warn("Import CSV: wrong IP %r" % ip)
                continue

            # netmask
            netmask = row[2] or None
            if netmask and not IpAddress.valid(netmask):
                logger.warn("Import CSV: wrong netmask %r" % netmask)
                continue

            # gateway
            gateway = row[3] or None
            if gateway and not IpAddress.valid(gateway):
                logger.warn("Import CSV: wrong gateway %r" % gateway)
                continue

            # VLAN
            try:
                vlan = int(row[4]) if row[4] else 1
            except Exception:
                logger.warn("Import CSV: wrong vlan %r" % row[4])
                continue

            if vlan < 1 or vlan > 4095:
                logger.warn("Import CSV: invalid vlan %r" % vlan)
                continue

            # Device Name
            device_name = row[5]
            if len(device_name) > Device.device_name.property.columns[0].type.length:
                logger.warn("Import CSV: device_name too long %r" % device_name)
                continue

            # Product Name
            product_name = row[6]
            if len(product_name) > Device.product_name.property.columns[0].type.length:
                logger.warn("Import CSV: product_name too long %r" % product_name)
                continue

            # SNMP Version
            try:
                snmp_version = int(row[7]) if row[7] else SnmpConfig.v2c
            except Exception:
                logger.warn("Import CSV: invalid snmp_version %r" % row[7])
                continue

            # if snmp_version not in (SnmpConfig.v1, SnmpConfig.v2c, SnmpConfig.v3):
            if snmp_version not in SnmpConfig.supported_version:
                logger.warn("Import CSV: invalid snmp_version %r" % snmp_version)
                continue

            # SNMPv2c Community
            snmp_v2c_community = row[8]
            if len(snmp_v2c_community) > SnmpConfig.v2c_community.property.columns[0].type.length:
                logger.warn("Import CSV: snmp_v2c_community too long %r" % snmp_v2c_community)
                continue


            #################################
            # someday, SNMPv3 will be here
            #################################

            # SNMPv3 Username
            snmp_v3_username = row[9]
            if len(snmp_v3_username) > SnmpConfig.v3_username.property.columns[0].type.length:
                logger.warn("Import CSV: snmp_v3_username too long %r" % snmp_v3_username)
                continue

            # SNMPv3 Engine ID
            snmp_v3_engine_id = row[10]
            if len(snmp_v3_engine_id) > SnmpConfig.v3_engine_id.property.columns[0].type.length:
                logger.warn("Import CSV: snmp_v3_engine_id too long %r" % snmp_v3_engine_id)
                continue

            # SNMPv3 Context Name
            snmp_v3_context_name = row[11]
            if len(snmp_v3_context_name) > SnmpConfig.v3_context_name.property.columns[0].type.length:
                logger.warn("Import CSV: snmp_v3_context_name too long %r" % snmp_v3_context_name)
                continue

            # SNMPv3 Authentication Protocol
            snmp_v3_auth_protocol = row[12] or "none"
            if snmp_v3_auth_protocol not in SnmpConfig.auth_proto_enum:
                logger.warn("Import CSV: invalid auth protocol %r" % snmp_v3_auth_protocol)
                continue

            # SNMPv3 Authentication Password
            snmp_v3_auth_password = row[13]
            if len(snmp_v3_auth_password) > SnmpConfig.v3_auth_password.property.columns[0].type.length:
                logger.warn("Import CSV: snmp_v3_auth_password too long %r" % snmp_v3_auth_password)
                continue

            # SNMPv3 Privacy Protocol
            snmp_v3_priv_protocol = row[14] or "none"
            if snmp_v3_priv_protocol not in SnmpConfig.priv_proto_enum:
                logger.warn("Import CSV: invalid privacy protocol %r" % snmp_v3_priv_protocol)
                continue

            # SNMPv3 Privacy Password
            snmp_v3_priv_password = row[15]
            if len(snmp_v3_priv_password) > SnmpConfig.v3_priv_password.property.columns[0].type.length:
                logger.warn("Import CSV: privacy password too long %r" % snmp_v3_priv_password)
                continue

            dev_values.append({
                "mac": mac,
                "ip": ip,
                "netmask": netmask,
                "gateway": gateway,
                "vlan": vlan,
                "device_name": device_name,
                "product_name": product_name,
            })


            #############################
            # SNMPv3
            #############################

            snmp_values.append({
                "device_mac": mac,
                "version": snmp_version,
                "v2c_community": snmp_v2c_community,
                "v3_username": snmp_v3_username,
                "v3_engine_id": snmp_v3_engine_id,
                "v3_context_name": snmp_v3_context_name,
                "v3_auth_protocol": snmp_v3_auth_protocol,
                "v3_auth_password": snmp_v3_auth_password,
                "v3_priv_protocol": snmp_v3_priv_protocol,
                "v3_priv_password": snmp_v3_priv_password
            })

            # snmp_values.append({
            #     "device_mac": mac,
            #     "version": snmp_version,
            #     "v2c_community": snmp_v2c_community
            # })


        conn = engine.connect()
        try:
            # update devices
            conn.execute(
                insert_or_update(
                    Device.__table__, 
                    'mac', 'ip', 'netmask',
                    'gateway', 'vlan', 'device_name',
                    'product_name'
                ),
                dev_values
            )

            #############################
            # SNMPv3
            #############################

            # # update snmp_config
            # conn.execute(
            #     insert_or_update(
            #         SnmpConfig.__table__, 
            #         "device_mac", "version", "v2c_community",
            #         "v3_username", "v3_engine_id", "v3_context_name",
            #         "v3_auth_protocol", "v3_auth_password", "v3_priv_protocol",
            #         "v3_priv_password"
            #     ),
            #     snmp_values
            # )

            # update snmp_config
            conn.execute(
                insert_or_update(
                    SnmpConfig.__table__, 
                    "device_mac", "version", "v2c_community"
                ),
                snmp_values
            )

        finally:
            conn.close()

        return json_response({"success": True}) # specific for ext file upload

@mod.route(r'/devices/del_multi', methods=['POST'])
def delete_multi_devices():
    """
        POST:
            application/json
            {
                'devices': ['dev1_id', 'dev2_id', 'dev3_id', ...]
            }
        note:
            non-existing devices are discarded
    """
    devs = request.json['devices']
    macs = [
        str(EUI(
            base64.urlsafe_b64decode(str(dev_id))
        ))
        for dev_id in devs
    ]

    try:
        recs = db_session.query(Device).with_for_update().filter(
            Device.mac.in_(macs)
        ).all()
        for rec in recs:
            ConfigFile.delete_device(rec.id)
            db_session.delete(rec)

        db_session.commit()
    finally:
        db_session.rollback()


    # or
    # delete all cats records associated with target devices (macs).
    # r = engine.execute(Device.__table__.delete().where(Device.__table__.c.mac.in_(macs)))
    return empty_response()


@mod.route(r'/devices/commit_info', methods=['POST'])
def commit_devices_info():
    """
        POST:
            application/json
            {
                'devices': [
                    {'id': dev1_id, **other_changed_fields,...},
                    ...
                ]
            }
    """
    devs_info = request.json['devices']

    # build the mappings
    mappings = []

    new_values = {}
    for info in devs_info:
        try:
            mac = str(EUI(
                base64.urlsafe_b64decode(str(info['id']))
            ))
        except Exception as e:
            jabort({'msg': 'invalid device id %r' % device_id}, 400)

        rec = db_session.query(Device).filter(Device.mac == mac).scalar()
        if not rec:
            jabort({'msg': "device %r doesn't exist." % mac}, 400)

        new_info = {
            'device_name': rec.device_name,
            'ip': rec.ip,
            'netmask': rec.netmask,
            'gateway': rec.gateway,
            'vlan': rec.vlan
        }

        #
        # TODO:
        #   verify value
        #   
        cmds = []
        if 'device_name' in info:
            if len(info['device_name']) > 32 or len(info['device_name']) < 1:
                continue

            cmds.append("System Name %s" % info['device_name'])
            new_info['device_name'] = info['device_name']

        if 'ip' in info or \
           'netmask' in info or \
           'gateway' in info or \
           'vlan' in info:

            if "ip" in info:
                if not IpAddress.valid(info['ip']):
                    continue
                new_info['ip'] = info['ip']

            if "netmask" in info:
                if not valid_netmask(info['netmask']):
                    continue
                new_info['netmask'] = info['netmask']

            if "gateway" in info:
                if not IpAddress.valid(info["gateway"]):
                    continue
                new_info['gateway'] = info['gateway']

            if "vlan" in info:
                try:
                    vlan = int(info["vlan"])
                except Exception:
                    continue

                if vlan > 4095 or vlan < 1:
                    continue

                new_info['vlan'] = vlan

            cmds.append('/IP DHCP disable')
            cmds.append('/IP Setup %s %s %s %d' % (
                new_info['ip'], 
                new_info['netmask'], 
                new_info['gateway'], 
                new_info['vlan']
            ))

        new_values[mac] = new_info

        mappings.append((mac, cmds))


    with knmp_client() as kc:
        r = kc.safe_execute(mappings)

    failure = {}
    values = []
    # modified_macs = []
    for info in devs_info:
        mac = str(EUI(
            base64.urlsafe_b64decode(str(info['id']))
        ))

        status = r[mac]
        if status != KNMP_EXEC_STAT_SUCCESS:
            failure[mac] = KNMP_EXEC_STAT_DISP[status]
        else:
            info = new_values[mac]
            info['_mac'] = mac
            values.append(info)

    if values:
        conn = engine.connect()
        table = Device.__table__
        stmt = table.update().where(
            table.c.mac == bindparam('_mac')
        ).values(
            {
                "device_name": bindparam("device_name"),
                "ip": bindparam("ip"),
                "netmask": bindparam("netmask"),
                "gateway": bindparam("gateway"),
                "vlan": bindparam("vlan")
            }
        )
        conn.execute(stmt, values)
        conn.close()

    if failure:
        msg = '<br/>'.join("%s: %s" % (mac, fmsg) for mac, fmsg in failure.iteritems())
        jabort({'msg': msg}, 500)

    return empty_response()





# @policy.allow('guest', methods=['GET'])
# @mod.route(r'/devices/<device_id>', methods=['GET', 'PATCH', 'DELETE'])
# def device(device_id):
#     try:
#         mac = str(EUI(
#             base64.urlsafe_b64decode(str(device_id))
#         ))
#     except Exception as e:
#         jabort({'msg': 'invalid device id %r' % device_id}, 400)

#     rec = db_session.query(Device).with_for_update().filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)


#     if request.method == 'GET':
#         db_session.commit()
#         return json_response({'device': rec.to_dict()})

#     elif request.method == 'DELETE':
#         ConfigFile.delete_device(rec.id)
#         db_session.delete(rec)
#         db_session.commit()
#         return empty_response()

#     elif request.method == 'PATCH':
#         # update device
#         info = request.json['device']
#         if 'flag' in info:
#             rec.flag = info['flag']
#         if 'ip' in info:
#             rec.ip = info['ip']
#         if 'netmask' in info:
#             rec.netmask = info['netmask']
#         if 'gateway' in info:
#             rec.gateway = info['gateway']
#         if 'vlan' in info:
#             rec.vlan = info['vlan']
#         if 'device_name' in info:
#             rec.device_name = info['device_name']
#         if 'product_name' in info:
#             rec.product_name = info['product_name']

#         db_session.commit()
#         return json_response({'device': rec.to_dict()})


@mod.route(r'/knmp/scan', methods=["POST"])
def knmp_scan():
    """
        scan specific devices
    """
    macs = None
    if request.json and 'macs' in request.json:
        macs = request.json['macs']
        if not isinstance(macs, (tuple, list, set)):
            macs = [macs]

    with knmp_client() as kc:
        devs_info = kc.scan(macs=macs)

    for info in devs_info:
        info['from_nic'] = info['from_nic']['name']

    return json_response({"devices": devs_info})


# @mod.route(r'/devices/scan', methods=['POST'])
# def scan_devices():
#     """
#         scan devices with KNMP
#     """

#     # KNMP Scan
#     with knmp_client() as kc:
#         devs_info = kc.scan_devices(update=False)

#     # return empty_response()
#     return json_response({'devices': devs_info}, 200)


# @mod.route(r'/devices/scan_specified', methods=['POST'])
# def scan_specified_devices():
#     """
#         POST:
#             application/json
#             {
#                 'devices': ['dev1_id', 'dev2_id', ...]
#             }
#     """
#     devs_id = request.json['devices']

#     macs = [
#         str(EUI(
#             base64.urlsafe_b64decode(str(dev_id))
#         ))
#         for dev_id in devs_id
#     ]

#     with knmp_client() as kc:
#         kc.update_devices(macs)

#     with snmp_client() as sc:
#         sc.ping(macs)

#     return empty_response()

@mod.route(r'/devices/ping', methods=["POST"])
def ping_devices():
    dev_ids = request.json['devices']
    macs = filter(
        lambda v: v, 
        [Device.decode_device_id(dev_id) for dev_id in dev_ids]
    )

    with snmp_client() as sc:
        sc.ping(macs)

    return empty_response()


def __generate_dev_snmp_v3_engine_id(mac):
    """
        to generate Engine ID for each device
        input:
            mac -> EUI mac address
        return:
            an unique engine id
    """
    # 800092b903+MAC
    engine_id_prefix = "800092b903"
    mac = EUI(mac)
    return engine_id_prefix + "".join(["%02x" % i for i in mac])


def __generate_snmp_config_cmd(mac, snmp_cfg):
    """
        input:
            mac -> EUI mac address
            snmp_cfg -> snmp configuration

            // v2c
            {
                "snmp": {
                    "mode": bool,
                    "version": 2,
                    "v2c_community": xxxx
                }
            }

            // v3 noAuthNoPriv
            {
                "snmp": {
                    "mode": bool,
                    "version": 3,
                    "v3_username": xxxx,
                    "v3_auth_proto": "none"
                }
            }

            // v3 authNoPriv
            {
                "snmp": {
                    "mode": bool,
                    "version": 3,
                    "v3_username": xxxx,
                    "v3_auth_proto": "MD5" | "SHA",
                    "v3_auth_password": xxxx
                    "v3_priv_proto": "none"
                }
            }

            // v3 authPriv
            {
                "snmp": {
                    "mode": bool,
                    "version": 3,
                    "v3_username": xxxx,
                    "v3_auth_proto": "MD5" | "SHA",
                    "v3_auth_password": xxxx,
                    "v3_priv_proto": "DES",
                    "v3_priv_password": xxxxxx
                }
            }

        #
        # v3 command
        #
        SNMP Mode disable
        SNMP Version 3

        SNMP Engine ID 800092b903983000020001
            # this will remove all local user, so call it first

        SNMP View Add  nms_view included .1
            # nms_view -> view name

        SNMP User Add 800092b903983000020001 nms_user SHA 12345678 DES 12345678
            # 800092b903983000020001 ->
                engine id, here use device engine id, 
                as the user is on the local device

            # nms_user -> username


        SNMP Group Add usm nms_user nms_group
            # nms_user -> 
                security name, which is username here
            # nms_group -> group name


        SNMP Access Add nms_group usm AuthPriv nms_view nms_view
            # nms_group -> group name
            # 1st nms_view -> read view name
            # 2nd nms_view -> write view name

        # if need enabled
        SNMP Mode enable


        #
        # v2c command
        # 
        SNMP Mode disable
        SNMP Version 2c
        SNMP Community Add private
        SNMP Write Community private

        SNMP Mode enable # if needed
    """
    cmds = []

    info = {
        "version": 2,
        "v2c_community": None,
        "v3_username": None,
        "v3_engine_id": None,
        "v3_context_name": "",
        "v3_auth_protocol": None,
        "v3_auth_password": None,
        "v3_priv_protocol": None,
        "v3_priv_password": None
    }

    try:
        mac = EUI(mac)
    except Exceptino:
        logger.error("invalid mac: %r" % mac)
        return None

    # info["_mac"] = str(mac)
    info["device_mac"] = str(mac)

    if not isinstance(snmp_cfg, dict):
        logger.error("invalid snmp_cfg: %r" % snmp_cfg)
        return None

    if "snmp" not in snmp_cfg:
        logger.warn("No snmp_cfg")
        return None

    snmp_cfg = snmp_cfg['snmp']

    #
    # for trap
    # 
    # trap_community = NMSConfig['TRAP_COMMUNITY']
    if snmp_cfg['trap_mode']:
        cmds.append("/SNMP Trap Mode enable")
        if snmp_cfg['trap_dest_ip_auto_detect']:
            try:
                server_ip = __get_device_pingable_ip(mac)
            except DevicePingableError as e:
                cmds.append("/SNMP Trap Mode disable")
                logger.warn(
                    "no pingable IP for device %r, msg: %r. trap is not configured." % mac, str(e)
                )

        else:
            server_ip = snmp_cfg['trap_dest_ip']


        if snmp_cfg['trap_version'] == 1:
            version_str = "1"
        elif snmp_cfg['trap_version'] == 2:
            version_str = "2c"
        else:
            raise ValueError, "not supported trap version %r" % snmp_cfg['trap_version']

        cmds.append("/SNMP Trap Version %s" % version_str)
        cmds.append("/SNMP Trap Community %s" % snmp_cfg['trap_community'])
        cmds.append("/SNMP Trap Destination %s" % server_ip)

    else:
        cmds.append("/SNMP Trap Mode disable")

    # try:
    #     server_ip = __get_device_pingable_ip(mac)
    #     cmds.append("/SNMP Trap Mode enable")
    #     cmds.append("/SNMP Trap Version 2c")
    #     cmds.append("/SNMP Trap Community %s" % trap_community)
    #     cmds.append("/SNMP Trap Destination %s" % server_ip)
    # except DevicePingableError as e:
    #     logger.warn(
    #         "no pingable IP for device %r, msg: %r. trap is not configured." % mac, str(e)
    #     )



    #
    # mode
    # 
    if "mode" not in snmp_cfg:
        logger.error("no \"mode\" in snmp_cfg")
        return None

    mode = bool(snmp_cfg['mode'])
    cmds.append("/SNMP Mode %s" % ("enable" if mode else "disable"))

    #
    # version
    # 
    if "version" not in snmp_cfg:
        logger.error("no \"version\" in snmp_cfg")
        return None

    if snmp_cfg['version'] not in SnmpConfig.supported_version:
        logger.error("invalid version: %r" % snmp_cfg["version"])
        return None

    version = int(snmp_cfg['version'])
    info['version'] = version


    #
    # v2c
    # 
    if version == 2 or version == 1:
        cmds.append("/SNMP Version %s" % ("1" if version == 1 else "2c"))

        #
        # community
        #
        if "v2c_community" not in snmp_cfg:
            logger.error("v2c_community not in snmp_cfg")
            return None

        community = str(snmp_cfg['v2c_community'])
        if len(community) == 0:
            logger.error("community is empty")
            return None

        if len(community) > 32:
            logger.error("community is too long, max length is 32.")
            return None

        info['v2c_community'] = community
        cmds.append("/SNMP Community Add %s" % community)
        cmds.append("/SNMP Write Community %s" % community)
    else:
        # v3
        cmds.append("/SNMP Version 3")

        #
        # engine id
        #
        engine_id = __generate_dev_snmp_v3_engine_id(mac)
        info["v3_engine_id"] = engine_id
        cmds.append("/SNMP Engine ID %s" % engine_id)

        #
        # view
        #
        cmds.append("/SNMP View Add nms_view included .1")

        #
        # username
        #
        if "v3_username" not in snmp_cfg:
            logger.error("no v3_username in snmp_cfg")
            return None

        username = str(snmp_cfg['v3_username'])
        if username == 'None':
            logger.error("username \"None\" is reserved.")
            return None

        if len(username) == 0:
            logger.error("zero length username")
            return None

        if len(username) > 32:
            logger.error("username is too long, max length is 32.")
            return None

        info["v3_username"] = username

        #
        # auth protocol
        # 
        auth_proto = snmp_cfg.get("v3_auth_proto", "none")
        if auth_proto not in SnmpConfig.auth_proto_enum:
            logger.error("invalid auth protocol: %r" % auth_proto)
            return None

        info["v3_auth_protocol"] = auth_proto

        if auth_proto == 'none':
            sec_level = "noAuthNoPriv"
            cmds.append("/SNMP User Add %s %s" % (engine_id, username))
        else:
            #
            # auth password
            # 
            if "v3_auth_password" not in snmp_cfg:
                logger.error("no v3_auth_password in snmp_cfg.")
                return None

            auth_password = str(snmp_cfg['v3_auth_password'])
            if len(auth_password) < 8:
                logger.error("auth password too short, min len is 8.")
                return None

            elif len(auth_password) > 32:
                logger.error("auth password too long, max len is 32.")
                return None

            info['v3_auth_password'] = auth_password

            #
            # priv protocol
            # 
            priv_proto = snmp_cfg.get("v3_priv_proto", "none")
            if priv_proto not in SnmpConfig.priv_proto_enum:
                logger.error("invalid priv protocol: %r" % priv_proto)
                return None

            info['v3_priv_protocol'] = priv_proto

            if priv_proto == 'none':
                sec_level = "AuthNoPriv"
                cmds.append(
                    "/SNMP User Add %s %s %s %s" % (
                        engine_id, 
                        username, 
                        auth_proto, 
                        auth_password
                    )
                )
            else:
                #
                # priv password
                # 
                if "v3_priv_password" not in snmp_cfg:
                    logger.error("no v3_priv_password in snmp_cfg")
                    return None

                priv_password = str(snmp_cfg["v3_priv_password"])
                if len(priv_password) < 8:
                    logger.error("priv password is too short, min len is 8")
                    return None

                elif len(priv_password) > 40:
                    logger.error("priv password is too long, max len is 40")
                    return None

                info["v3_priv_password"] = priv_password

                sec_level = "AuthPriv"
                cmds.append(
                    "/SNMP User Add %s %s %s %s %s %s" % (
                        engine_id, 
                        username, 
                        auth_proto, 
                        auth_password,
                        priv_proto,
                        priv_password
                    )
                )

        cmds.append("/SNMP Group Add usm %s nms_group" % username)
        cmds.append("/SNMP Access Add nms_group usm %s nms_view nms_view" % sec_level)

    # if mode:
    #     cmds.append("/SNMP Mode enable")

    return {"info": info, "cmds": cmds}


def __generate_cmd_from_knmp_temp(mac, cfg):
    info = __generate_snmp_config_cmd(mac, cfg)
    if not info:
        return None

    if 'lldp' in cfg:
        lldp_cfg = cfg['lldp']
        mode = bool(lldp_cfg.get('mode', True))
        info["cmds"].append("/LLDP Mode all %s" % ("enable" if mode else "disable"))

    if 'save' in cfg:
        if cfg['save']:
            info['cmds'].append("/Config Save Flash")

    return info



@mod.route(r'/trap_temp_info', methods=["GET"])
def trap_temp_cfg_info():

    first_ipv4 = "0.0.0.0"

    with knmp_client() as kc:
        nifs = kc.all_nifs()

    # for nif in nifs:
    #     for ip,netmask in nif['ipv4s']:
    #         if same_net(ip, rec.ip, netmask):
    #             return ip

    if nifs:
        nif = nifs[0]
        if nif['ipv4s']:
            first_ipv4 = nif['ipv4s'][0][0]

    return json_response({
        "trap_dest_ip": first_ipv4,
        "trap_version": 2,
        "trap_community": NMSConfig['TRAP_COMMUNITY']
    })




@mod.route(r'/devices/config', methods=['POST'])
def devices_config():
    """
        POST:
            application/json
            {
                "devices": [dev1_id, dev2_id, ...]
                "config": {
                    "snmp": {
                        "mode": bool,
                        "version": 2|3,
                        "v2c_community": xxx,
                        "v3_username": xxx,
                        "v3_auth_proto": "none"|"MD5"|"SHA",
                        "v3_auth_password": xxx,
                        "v3_priv_proto": "none"|"DES",
                        "v3_priv_password": xxx,
                        "trap_mode": bool,
                        "trap_version": 1|2,
                        "trap_community": xxx,
                        "trap_dest_ip_auto_detect": bool,
                        "trap_dest_ip": ip_addr,
                    },
                    "lldp": {
                        "mode": bool
                    },
                    "save": bool
                }
            }

            every config and config items are optional.
    """
    cfg = request.json['config']
    devs = request.json['devices']
    macs = [
        str(EUI(
            base64.urlsafe_b64decode(str(dev_id))
        ))
        for dev_id in devs
    ]

    new_confs = {}   # {mac: info}
    mappings = {}
    # success = []
    success = {}
    failure = []
    # trap_community = NMSConfig['TRAP_COMMUNITY']
    for mac in macs:
        info = __generate_cmd_from_knmp_temp(mac, cfg)
        if not info:
            failure.append((mac, "invalid config"))
            continue
        mappings[mac] = info["cmds"]
        new_confs[mac] = info["info"]


    if mappings:

        logger.debug("mappings: %r" % mappings)
        with knmp_client() as kc:
            r = kc.safe_execute(mappings)

        for mac, status in r.iteritems():
            if status == KNMP_EXEC_STAT_SUCCESS:
                # success.append(new_confs[mac])
                success[mac] = new_confs[mac]
            else:
                failure.append((mac, KNMP_EXEC_STAT_DISP[status]))


    # commented for test: is this results in that snmp packet malformed

    if success:
        conn = engine.connect()
        table = SnmpConfig.__table__
        try:
            # conn.execute(
            #     table.update().where(
            #         table.c.device_mac==bindparam("_mac")
            #     ).values(
            #         {
            #             "version": bindparam("version"),
            #             "v2c_community": bindparam("v2c_community"),
            #             "v3_username": bindparam("v3_username"),
            #             "v3_engine_id": bindparam("v3_engine_id"),
            #             "v3_context_name": bindparam("v3_context_name"),
            #             "v3_auth_protocol": bindparam("v3_auth_protocol"),
            #             "v3_auth_password": bindparam("v3_auth_password"),
            #             "v3_priv_protocol": bindparam("v3_priv_protocol"),
            #             "v3_priv_password": bindparam("v3_priv_password")
            #         }
            #     ),
            #     success
            # )
            conn.execute(
                insert_or_update(
                    table, 
                    "device_mac", "version", "v2c_community",
                    "v3_username", "v3_engine_id", "v3_context_name",
                    "v3_auth_protocol", "v3_auth_password", "v3_priv_protocol",
                    "v3_priv_password"
                ),
                # success
                success.values()
            )
        finally:
            conn.close()


        ###################################
        # test: use ORM instead of core,
        #   still not snmppingable?
        ###################################

        # try:
        #     recs = db_session.query(Device).with_for_update().filter(
        #         Device.mac.in_(success.iterkeys())
        #     ).all()

        #     print "recs:", recs     # expect rec with `mac` in success.iterkys()

        #     for rec in recs:
        #         new_cfg = success[rec.mac]
        #         print "new config:", rec.mac, new_cfg   # expect newly configured snmp config

        #         snmp = SnmpConfig(
        #             version=new_cfg['version'],
        #             v2c_community=new_cfg['v2c_community'],
        #             v3_engine_id=new_cfg['v3_engine_id'],
        #             v3_username=new_cfg['v3_username'],
        #             v3_context_name=new_cfg['v3_context_name'],
        #             v3_auth_protocol=new_cfg['v3_auth_protocol'],
        #             v3_auth_password=new_cfg['v3_auth_password'],
        #             v3_priv_protocol=new_cfg['v3_priv_protocol'],
        #             v3_priv_password=new_cfg['v3_priv_password']
        #         )

        #         rec.snmp = snmp

        #         # db_session.commit()
        #         try:
        #             db_session.commit()
        #         except Exception as e:
        #             logger.exception("Fail to commit DeviceBaseInfo polling result.")
        #             db_session.rollback()

        # finally:
        #     db_session.rollback()


    if failure:
        fmsg = '<br/>'.join(
            "%s: %s" % (mac, msg) 
            for mac, msg in failure
        )
        jabort({'msg': fmsg}, 500)

    return empty_response()





@mod.route(r'/devices/<device_id>/poll', methods=['POST'])
def poll_device(device_id):
    """
        poll device
        POST:
            application/json
            {
                "poll": {
                    "categories": ["info", "mac", ...]  # optional,
                                                        # available categories:
                                                        # "info", "port", "port_num", "port_table",
                                                        # "mac", "mac_num", "mac_table",
                                                        # "vlan", "vlan_table", "pvid_table",
                                                        # "lldp", "lldp_num", "lldp_table",
                                                        # "mstp", "mstp_config", "cist", "cist_port",
                                                        # "msti", "msti_port"
                }
            }
    """
    mac = str(EUI(
        base64.urlsafe_b64decode(str(device_id))
    ))
    cats = None
    if request.json:
        params = request.json['poll']
        cats = params.get('categories', None)

    with snmp_client() as sc:
        sc.poll(mac, cats)

    return empty_response()


@mod.route(r'/devices/poll', methods=["POST"])
def poll_devices():
    """
        poll multiple devices
        POST:
            application/json
            {
                "poll": {
                    "devices": [dev_id1, dev_id2, ...], # optional, default: all devices

                    "categories": ["info", "mac", ...]  # optional, default: all categories
                                                        # available categories:
                                                        # "info", "port", "port_num", "port_table",
                                                        # "mac", "mac_num", "mac_table",
                                                        # "vlan", "vlan_table", "pvid_table",
                                                        # "lldp", "lldp_num", "lldp_table",
                                                        # "mstp", "mstp_config", "cist", "cist_port",
                                                        # "msti", "msti_port"
                }
            }
    """
    dev_macs = None
    cats = None
    if request.json:
        params = request.json['poll']
        cats = params.get('categories', None)
        if 'devices' in params:
            dev_macs = [Device.decode_device_id(dev_id) for dev_id in params['devices']]

    with snmp_client() as sc:
        sc.poll(dev_macs, cats)

    return empty_response()




# @mod.route(r'/devices/<device_id>/information', methods=['GET'])
# def device_info(device_id):
#     """
#         GET: get basic information of device.
#     """
#     mac = str(EUI(
#         base64.urlsafe_b64decode(str(device_id))
#     ))

#     rec = db_session.query(Device).filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)

#     return json_response({'information': rec.information.to_dict()})

@mod.route(r'/devices/information', methods=['GET'])
def devices_info():
    """
        GET: all devices information
    """
    recs = db_session.query(DeviceBaseInfo).all()
    return json_response({'informations': [rec.to_dict() for rec in recs]})


# @mod.route(r'/devices/<device_id>/macs', methods=['GET'])
# def device_mac_table(device_id):
#     """
#         GET: get mac table of a device.
#     """
#     mac = str(EUI(
#         base64.urlsafe_b64decode(str(device_id))
#     ))

#     rec = db_session.query(Device).filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)

#     return json_response({'macs': [mac_rec.to_dict() for mac_rec in rec.mac_table]})


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



# @mod.route(r'/devices/mac_num', methods=['GET'])
# def devices_mac_num():
#     """
#         get all devices mac number
#     """
#     recs = db_session.query(DeviceMacNumber).all()
#     return json_response({'mac_nums': [rec.to_dict() for rec in recs]})


# @mod.route(r'/devices/port_num', methods=['GET'])
# def devices_port_num():
#     recs = db_session.query(DevicePortNumber).all()
#     return json_response({'port_nums': [rec.to_dict() for rec in recs]})


@mod.route(r'/devices/ports', methods=['GET'])
def devices_ports():
    recs = db_session.query(
        DevicePortInterfaces, Device.ip, Device.device_name
    ).filter(
        DevicePortInterfaces.device_mac == Device.mac
    ).all()

    ports =  [
        merge_dicts(
            rec.DevicePortInterfaces.to_dict(),
            {'device_name': rec.device_name, 'device_ip': rec.ip}
        )
        for rec in recs
    ]
    return json_response({'ports': ports})



@mod.route(r'/devices/lldp_for_topo', methods=['GET'])
def devices_lldp_for_topo():
    """
        return {
            'topo': {
                'links': [
                    {
                        id: link_id <- join(minor_dev_mac, minor_dev_port, prio_dev_mac, prio_dev_port),
                        source: source_id <- device_id,
                        target: target_id <- device_id,
                        source_port: port desc <- display string,
                        target_port: port desc <- display string,
                    },
                    ...
                ],
                'nodes': [
                    {
                        Device.to_dict()
                    },
                    ...
                ]
            }
        }
    """

    nodes = [rec.to_dict() for rec in db_session.query(Device).all()]
    nodes_by_mac = {info['mac']: info for info in nodes}

    lldp_info = [rec.to_dict() for rec in db_session.query(DeviceLldpRemoteTable).all()]
    links_by_id = {}
    for info in lldp_info:
        ordered_dev = [
            '|'.join([info['device_mac'], str(info['lldpRemLocalPortNum'])]),
            '|'.join([info['lldpRemChassisId'], str(info['lldpRemPortId'])])
        ]
        ordered_dev.sort()

        # minor_dev, prior_dev = ordered_dev
        link_id = '-'.join(ordered_dev)
        if (link_id not in links_by_id) and (info['lldpRemChassisId'] in nodes_by_mac):
            links_by_id[link_id] = {
                'id': link_id,
                'source': nodes_by_mac[info['device_mac']]['id'],
                'target': nodes_by_mac[info['lldpRemChassisId']]['id'],
                'source_port_disp': 'Port %s' % str(info['lldpRemLocalPortNum']),
                'target_port_disp': 'Port %s' % str(info['lldpRemPortId'])
            }

    return json_response({'topo': {
            'nodes': nodes,
            'links': links_by_id.values()
        }})




# @mod.route(r'/devices/<device_id>/mstp_config', methods=["GET"])
# def device_mstp_config(device_id):
#     mac = str(EUI(
#         base64.urlsafe_b64decode(str(device_id))
#     ))

#     rec = db_session.query(Device).filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)

#     return json_response({'mstp_config': rec.mstp_config.to_dict()})


# @mod.route(r'/devices/mstp_config', methods=["GET"])
# def devices_mstp_config():
#     recs = db_session.query(DeviceMstpConfig).all()
#     return json_response({'mstp_configs': [rec.to_dict() for rec in recs]})



# @mod.route(r'/devices/<device_id>/mstp_cist', methods=["GET"])
# def device_mstp_cist(device_id):
#     mac = str(EUI(
#         base64.urlsafe_b64decode(str(device_id))
#     ))

#     rec = db_session.query(Device).filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)

#     return json_response({'mstp_cist': rec.mstp_cist.to_dict()})


# @mod.route(r'/devices/mstp_cist', methods=["GET"])
# def devices_mstp_cist():
#     recs = db_session.query(DeviceMstpCist).all()
#     return json_response({'mstp_cists': [rec.to_dict() for rec in recs]})



# @mod.route(r'/devices/<device_id>/mstp_cist_ports', methods=["GET"])
# def device_mstp_cist_ports(device_id):
#     mac = str(EUI(
#         base64.urlsafe_b64decode(str(device_id))
#     ))

#     rec = db_session.query(Device).filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)

#     return json_response({'mstp_cist_ports': [mcp_rec.to_dict() for mcp_rec in rec.mstp_cist_ports]})


# @mod.route(r'/devices/mstp_cist_ports', methods=["GET"])
# def devices_mstp_cist_ports():
#     recs = db_session.query(DeviceMstpCistPort).all()
#     return json_response({'mstp_cist_ports': [rec.to_dict() for rec in recs]})



# @mod.route(r'/devices/<device_id>/msti_table', methods=["GET"])
# def device_msti_table(device_id):
#     mac = str(EUI(
#         base64.urlsafe_b64decode(str(device_id))
#     ))

#     rec = db_session.query(Device).filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)

#     return json_response({'msti_table': [msti_rec.to_dict() for msti_rec in rec.msti_table]})


# @mod.route(r'/devices/msti_table', methods=["GET"])
# def devices_msti_table():
#     recs = db_session.query(DeviceMstiTable).all()
#     return json_response({'msti_tables': [rec.to_dict() for rec in recs]})



# @mod.route(r'/devices/<device_id>/msti_ports', methods=["GET"])
# def device_msti_ports(device_id):
#     mac = str(EUI(
#         base64.urlsafe_b64decode(str(device_id))
#     ))

#     rec = db_session.query(Device).filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)

#     return json_response({"msti_ports": [mp_rec.to_dict() for mp_rec in rec.msti_ports]})


# @mod.route(r'/devices/msti_ports', methods=["GET"])
# def devices_msti_ports():
#     recs = db_session.query(DeviceMstiPort).all()
#     return json_response({'msti_ports': [rec.to_dict() for rec in recs]})



# @mod.route(r'/devices/<device_id>/vlans', methods=["GET"])
# def device_vlans(device_id):
#     mac = str(EUI(
#         base64.urlsafe_b64decode(str(device_id))
#     ))

#     rec = db_session.query(Device).filter(Device.mac == mac).scalar()
#     if not rec:
#         jabort({'msg': 'no such device %r' % device_id}, 404)

#     return json_response({"vlans": [vlan_rec.to_dict() for vlan_rec in rec.vlan_table]})


@mod.route(r'/devices/vlans', methods=["GET"])
def devices_vlans():
    recs = db_session.query(
        DeviceVlan, Device.device_name, Device.ip
    ).filter(
        DeviceVlan.device_mac == Device.mac
    ).all()

    vlans = [
        merge_dicts(
            rec.DeviceVlan.to_dict(),
            {'device_name': rec.device_name, 'device_ip': rec.ip}
        )
        for rec in recs
    ]
    return json_response({'vlans': vlans})


@mod.route(r'/devices/pvids', methods=["GET"])
def devices_pvids():
    recs = db_session.query(
        DevicePvid, Device.device_name, Device.ip
    ).filter(
        DevicePvid.device_mac == Device.mac
    ).all()

    pvids = [
        merge_dicts(
            rec.DevicePvid.to_dict(),
            {'device_name': rec.device_name, 'device_ip': rec.ip}
        )
        for rec in recs
    ]
    return json_response({'pvids': pvids})



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


@mod.route(r'/config/knmp_netifs', methods=["GET"])
def knmp_netifs():
    """
        return all monitorable Net interfaces.
    """
    with knmp_client() as kc:
        nif_names = kc.netif_names()

    netifs = []
    if request.args.get('with_any', 'no').lower() == 'yes':
        netifs.append({'name': 'any'})
    netifs.extend([{'name': nif_name} for nif_name in nif_names])
    return json_response({'netifs': netifs})


##################################
# Config File Management
##################################

class DevicePingableError(Exception):
    """
        raised from __get_device_pingable_ip
    """
    pass


def __get_device_pingable_ip(dev):
    """
        return host IP which may be pingable to target device.
        input:
            dev -> kns.db.model_device.Device or mac_address or device_id
        output:
            pingable IP
    """
    if isinstance(dev, Device):
        mac = str(dev.mac)
    else:
        # try decode device ID to get device MAC
        mac = Device.decode_device_id(dev, safe=True)
        if not mac:
            # not device ID: treat it as MAC
            mac = str(EUI(dev))

    rec = db_session.query(Device).filter(Device.mac==mac).first()
    if not rec:
        raise DevicePingableError, "no such device."

    if not rec.ip:
        raise DevicePingableError, "device record without an IP address."

    netmask = rec.netmask
    if (not netmask) or (not valid_netmask(netmask)):
        netmask = "255.255.255.0"

    # 
    # get all NIC IP address,netmask pairs
    # return the first host IP within the same netmask
    # 
    with knmp_client() as kc:
        nifs = kc.all_nifs()

    for nif in nifs:
        for ip,_ in nif['ipv4s']:
            if same_net(ip, rec.ip, netmask):
                return ip

    raise DevicePingableError, "device is not pingable"




@mod.route(r'/devices/<device_id>/config.xml', methods=['GET'])
def device_config_file(device_id):
    """
        GET:
            download device config file
            args:
                ?timeout=int -> tftp downloading timeout
    """

    mac = str(EUI(
        base64.urlsafe_b64decode(str(device_id))
    ))

    kc = knmp_client()

    try:
        host_ip = __get_device_pingable_ip(mac)
    except DevicePingableError as e:
        jabort({'msg': str(e)})

    cfg_fn = 'config_%s_%d.xml' % (mac, time.time())
    cfg_fpath = os.path.join(ConfigFile.TFTPBOOT_DIR, cfg_fn)
    if os.path.exists(cfg_fpath):
        if os.path.isdir(cfg_fpath):
            shutil.rmtree(cfg_fpath)
        else:
            os.remove(cfg_fpath)

    # TODO: delete if exist.
    r = kc.execute_command(
        "Config Save Tftp %s %s" % (host_ip, cfg_fn), 
        mac
    )
    kc.close()

    timeout = int(request.args.get('timeout', ConfigFile.TFTP_TIMEOUT))   # timeout of tftp downloading
    if not wait(
        timeout, 
        break_cond=lambda: os.path.isfile(cfg_fpath) and valid_xml(cfg_fpath)
    ):
        jabort({'msg': 'timeout of tftp downloading'}, 400)


    f = open(cfg_fpath, 'r')
    os.remove(cfg_fpath)

    return send_file(f, mimetype='text/xml', as_attachment=True, attachment_filename='config.xml')


@mod.route(r'/devices/cfgfiles/get_info', methods=['POST'])
def devices_cfgfiles_info():
    """
        POST:
            Get device config files information.
            application/json: 
                {
                    targets: {
                        devices: ['dev_id1', 'dev_id2', 'dev_id3', ...],
                        config_files: ['file_id1', 'file_id2', ...]
                    }
                }

            return:
                config_files: [
                    {'device_id'},
                    ......
                ]
    """
    target_dev_ids = []
    target_file_ids = []

    if request.json and 'targets' in request.json:
        target_dev_ids = request.json['targets'].get('devices', [])
        target_file_ids = request.json['targets'].get('config_files', [])

    if not (target_dev_ids or target_file_ids):
        # all devices config files' info
        #   if no config file for a device, return an empty one for it.
        recs = db_session.query(Device).all()
        target_dev_ids = [rec.id for rec in recs]

    added_file_ids = set()
    cfg_file_infos = []
    for dev_id in target_dev_ids:
        cfg_files = get_device_config_files_info(dev_id)
        cfg_file_infos.extend(cf.to_dict() for cf in cfg_files)
        added_file_ids = added_file_ids.union(cf.id for cf in cfg_files)

    for file_id in target_file_ids:
        if file_id in added_file_ids:
            continue

        cf = get_config_file_info(file_id)
        if cf:
            cfg_file_infos.append(cf.to_dict())

    for info in cfg_file_infos:
        rec = db_session.query(Device).filter(Device.mac == info['device_mac']).first()
        info['device_ip'] = rec.ip

    return json_response({'config_files': cfg_file_infos})


@mod.route(r'/devices/cfgfiles/get_new', methods=['POST'])
def devices_cfgfiles_get_new():
    """
        POST
            save config file through TFTP.
            application/json
            {
                "devices": ['dev_id1', 'dev_id2', 'dev_id3'],
                "filename": target_file_name # optional
            }
    """

    target_dev_ids = []
    cfg_file_name = "config.xml"
    if request.json:
        target_dev_ids = request.json.get('devices', [])
        cfg_file_name = request.json.get('filename', 'config.xml')

    if not target_dev_ids:
        recs = db_session.query(Device).all()
        target_dev_ids = [rec.id for rec in recs]
        # return empty_response()

    err_msgs = []
    with knmp_client() as kc:
        mappings = {}
        for device_id in target_dev_ids:
            # KNMP request (cmd: "Config Save Tftp {host_ip} {config_file_name}")
            # on target devices
            assure_dev_cfg_dir(device_id)

            mac = Device.decode_device_id(device_id)

            try:
                host_ip = __get_device_pingable_ip(mac)
            except DevicePingableError as e:
                msg = str(e)
                warnings.warn(msg)
                err_msgs.append(msg)
                continue

            cfg_fpath = ConfigFile.get_tftp_rel_path(device_id, cfg_file_name)
            if os.path.exists(cfg_fpath):
                if os.path.isdir(cfg_fpath):
                    shutil.rmtree(cfg_fpath)
                else:
                    os.remove(cfg_fpath)

            mappings[mac] = "Config Save Tftp %s %s" % (host_ip, cfg_fpath)

        results = kc.safe_execute(mappings)
        err_msgs.extend(
            "device %s: %s" % (mac, KNMP_EXEC_STAT_DISP[status])
            for mac, status in results.iteritems() 
            if status != KNMP_EXEC_STAT_SUCCESS
        )

        if err_msgs:
            jabort({'msg': '<br/>'.join(err_msgs)})

    return empty_response()


@mod.route(r'/devices/cfgfiles/<file_id>', methods=["GET"])
def devices_cfgfiles_download(file_id):
    """
        just download one config file.
    """
    file_id = str(file_id)
    if not ConfigFile.exists(file_id):
        jabort({"msg": "no such config file: %r" % file_id}, 404)

    cfg_file = ConfigFile(file_id=file_id)
    return send_file(
        cfg_file.abspath, 
        mimetype='text/xml', 
        as_attachment=True, 
        attachment_filename=cfg_file.name
    )



@mod.route(r'/devices/cfgfiles/bundle/<bundle_name>', methods=['GET', 'POST'])
def devices_cfgfiles_bundle(bundle_name):
    """
        GET:
            query params:
            delete=no    # if True: delete after downloading.(optional, defalut no)

        POST:
            build a bundle of several config files.
            application/json
            {
                "targets": {
                    "devices": ['id1', 'id2', ...],
                    "config_files": ['fid1', 'fid2', ...]
                }
            }
    """
    if request.method == 'POST':
        target_dev_ids = []
        target_file_ids = []

        if request.json and 'targets' in request.json:
            target_dev_ids = request.json['targets'].get('devices', [])
            target_file_ids = request.json['targets'].get('config_files', [])

        if not (target_dev_ids or target_file_ids):
            recs = db_session.query(Device).all()
            target_dev_ids = [rec.id for rec in recs]

        cfg_bundle = ConfigFileBundle(
            bundle_name, 
            device_ids=target_dev_ids, 
            config_files=target_file_ids
        )
        cfg_bundle.save()

        return empty_response()

    elif request.method == 'GET':
        del_after_download = request.args.get('delete', 'no').lower() == 'yes'

        if not ConfigFileBundle.exists(bundle_name):
            jabort({'msg': 'no such or not valid, config bundle file: %r' % bundle_name}, 404)

        bundle_path = ConfigFileBundle.get_path(bundle_name)
        if del_after_download:
            f = open(bundle_path, 'r')
            os.remove(bundle_path)
        else:
            f = bundle_path

        return send_file(
            f, 
            mimetype=ConfigFileBundle.MIME_TYPE, 
            as_attachment=True,
            attachment_filename=bundle_name
        )



@mod.route(r'/devices/cfgfiles/rename', methods=['POST'])
def devices_cfgfiles_rename():
    """
        POST
            rename multi
            application/json
            {
                'targets': [['file_id1', 'new_name'], ['file_id2', 'new_name2']]
            }
    """
    targets = request.json['targets']

    err_msgs = []
    for file_id, new_name in targets:
        if not ConfigFile.exists(file_id):
            err_msgs.append("no such config file: %r" % file_id)
            continue

        if secure_filename(new_name) != new_name:
            err_msgs.append("invalid new name: %r" % new_name)
            continue

        ConfigFile.rename_config_file(file_id, new_name)

    if err_msgs:
        jabort({'msg': '<br/>'.join(err_msgs)})
    else:
        return empty_response()



@mod.route(r'/devices/cfgfiles/delete', methods=['POST'])
def devices_cfgfiles_delete():
    """
        POST:
            delete devices' config files
            application/json
            {
                "targets": {
                    "devices": ['id1', 'id2', ...],
                    "config_files": ['fid1', 'fid2', ...]
                }
            }
    """
    targets = request.json['targets']

    target_dev_ids = targets.get('devices', [])
    for dev_id in target_dev_ids:
        ConfigFile.delete_device_config_files(dev_id)

    target_file_ids = targets.get('config_files', [])
    for file_id in target_file_ids:
        ConfigFile.delete_config_file(file_id)

    return empty_response()


@mod.route(r'/devices/cfgfiles/<file_id>/load', methods=['POST'])
def device_load_config_file(file_id):
    """
        device load config file.
    """
    if not ConfigFile.exists(file_id):
        jabort({"msg": "no such config file: %r" % file_id}, 404)

    cfg_file = ConfigFile(file_id=file_id)

    try:
        host_ip = __get_device_pingable_ip(cfg_file.device_mac)
    except DevicePingableError as e:
        jabort({'msg': str(e)})

    with knmp_client() as kc:
        r = kc.execute_command(
            "/Config Load Tftp %s %s" % (host_ip, cfg_file.tftp_relpath), 
            cfg_file.device_mac
        )
        status = r[cfg_file.device_mac]
        if status != KNMP_EXEC_STAT_SUCCESS:
            jabort({'msg': "KNMP execution failure: %r" %KNMP_EXEC_STAT_DISP[status]})

    return empty_response()


@mod.route(r'/devices/cfgfiles/directly_load', methods=["POST"])
def device_directly_load_config_file():
    """
        update load config files to devices.
            files: target config file
            device:  tartet device id
    """
    dev_mac = Device.decode_device_id(request.form['device'], safe=True)
    if not dev_mac:
        jabort({'msg': 'no such device - %r' % request.form['device']})

    temp_cfg, temp_cfg_rel = ConfigFile.get_random_temp_cfgfile_path()

    request.files['cfgfile'].save(temp_cfg)

    try:
        if not valid_xml(temp_cfg):
            jabort({'msg': 'not a valid config file'})

        try:
            host_ip = __get_device_pingable_ip(dev_mac)
        except DevicePingableError as e:
            jabort({'msg': str(e)})

        with knmp_client() as kc:
            r = kc.execute_command(
                "/Config Load Tftp %s %s" % (host_ip, temp_cfg_rel),
                dev_mac
            )
            status = r[dev_mac]
            if status != KNMP_EXEC_STAT_SUCCESS:
                jabort({'msg': "KNMP execution failure: %r" %KNMP_EXEC_STAT_DISP[status]})
    finally:
        os.remove(temp_cfg)

    return json_response({'success': True})


@mod.route(r'/tool/arpscan', methods=['POST'])
def tool_arpscan():
    """
        POST:
            request: application/json
            {
                "expression": "xxxx",
                "nif": "eth0"
            }

            response: appication/json
            {
                "result": [{"ip": 'xx', "mac": xx}, ...]
            }
    """
    exp = request.json['expression']
    nif = request.json['nif']

    with knmp_client() as kc:
        r = kc.arpscan(exp, nif)

    result = [{'ip': ip, 'mac': mac} for ip, mac in r.iteritems()]

    return json_response({'result': result})


@mod.route(r'/alarmlog', methods=['GET'])
def handle_alarmlog():
    # recs = db_session.query(AlarmLog).all()

    start_idx = int(request.args['start'])
    limit = int(request.args['limit'])

    table = AlarmLog.__table__
    conn = engine.connect()
    try:
        recs = conn.execute(
            select([table]).order_by(
                desc(table.c.id)
            ).limit(limit).offset(start_idx)
        ).fetchall()

        count = conn.execute(
            select([func.count()]).select_from(table)
        ).fetchall()
        count = count[0][0]

        last_id = conn.execute(select([table.c.id]).order_by(desc(table.c.id)).limit(1)).fetchall()
        if last_id:
            last_id = last_id[0][0]
        else:
            last_id = 0
    finally:
        conn.close();

    return json_response({'success': True, 'total': count, 'root': [merge_dicts(dict(rec), {"last_id": last_id}) for rec in recs]})

@mod.route(r'/alarmlog/csv', methods=['GET'])
def handle_alarmlog_csv():

    table = AlarmLog.__table__
    conn = engine.connect()
    try:
        recs = conn.execute(
            select([table]).order_by(desc(table.c.id))
        ).fetchall()
    finally:
        conn.close();

    csv = ["level,message,date"]
    for rec in recs:
        lvl = rec['lvl'] or ''
        msg = rec['msg'] or ''
        date_str = ''
        if rec['date']:
            dt = datetime.datetime.utcfromtimestamp(rec['date'])
            dt = datetime_utc_2_local(dt)
            date_str = dt.strftime('%Y-%m-%d %H:%M:%S')
        csv.append(','.join((lvl, msg, date_str)))

    csv = '\n'.join(csv)

    f = StringIO(csv)
    return send_file(f, mimetype='text/csv', as_attachment=True, attachment_filename='alarmlog.csv')


@event_poller.on(name="alarm", methods=["POST"])
def alarm():
    """
        GET on this event.
        args: last_id -> int, 
            the ID of the log item starting from which to get new log items.
    """
    if request.json and 'alarm' in request.json and 'last_id' in request.json['alarm']:
        last_id = int(request.json['alarm']['last_id'])
        conn = engine.connect()
        try:
            table = AlarmLog.__table__
            r = conn.execute(
                select([table]).where(table.c.id > last_id)
            ).fetchall()

        finally:
            conn.close()

        return [dict(rec) for rec in r]
    else:
        return None

