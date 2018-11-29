# -*- coding:utf-8 -*-

"""
    API about KNS deivces' config files.
"""

import os
import time
import base64
import shutil
import warnings
import tarfile
import random
from netaddr import EUI

from utils.xml_util import valid_xml
from utils.thread_util import thread_safe

#############################################
# device id encoder, decoder (outer logic)
#############################################
def encode_device_id(dev_mac):
    return base64.urlsafe_b64encode(str(EUI(dev_mac)))

def decode_device_id(dev_id):
    return str(EUI(
        base64.urlsafe_b64decode(str(dev_id))
    ))




class ConfigFileBase(object):
    """
        Shared methods
    """
    TFTP_TIMEOUT = 5    # timeout of downloading a config file
    TFTPBOOT_DIR = os.path.normpath('/data/tftpboot/')
    DEV_DIR_NAME = 'devices'
    DEV_DATA_DIR = os.path.join(TFTPBOOT_DIR, DEV_DIR_NAME)
    TEMP_CFGFILE_DIR_NAME = 'temp'
    TEMP_CFGFILE_DIR = os.path.join(DEV_DATA_DIR, TEMP_CFGFILE_DIR_NAME)
    
    def _gen_random_id_domain():
        domain = random.sample(xrange(65536), 65536)
        id_iter = iter(domain)
        while 1:
            try:
                yield id_iter.next()
            except StopIteration:
                id_iter = iter(domain)
                yield id_iter.next()
    id_domain = _gen_random_id_domain()
    del _gen_random_id_domain

    @staticmethod
    @thread_safe
    def next_id():
        return next(ConfigFileBase.id_domain)

    #######################################
    # temporary config files directory
    #######################################

    @staticmethod
    def assure_temp_cfg_dir():
        temp_cfg_dir = ConfigFileBase.TEMP_CFGFILE_DIR

        if os.path.exists(temp_cfg_dir):
            if not os.path.isdir(temp_cfg_dir):
                warnings.warn("device dir %r is not a direcotry, which is not expected. Will replace it.")
                os.remove(temp_cfg_dir)
                os.makedirs(temp_cfg_dir, mode=0777)
                os.chmod(temp_cfg_dir, 0777)
        else:
            os.makedirs(temp_cfg_dir, mode=0777)
            os.chmod(temp_cfg_dir, 0777)

        return temp_cfg_dir

    @staticmethod
    def get_random_temp_cfgfile_name():
        return "temp%s.xml" % ConfigFileBase.next_id()

    @staticmethod
    def get_random_temp_cfgfile_path():
        """
            return random temporary config file path
            output:
                (absolute path, path relative to tftpboot)
        """
        ConfigFileBase.assure_temp_cfg_dir()
        fname = ConfigFileBase.get_random_temp_cfgfile_name()
        return (
            os.path.join(ConfigFileBase.TEMP_CFGFILE_DIR, fname),   # abspath
            os.path.join(ConfigFileBase.DEV_DIR_NAME, ConfigFileBase.TEMP_CFGFILE_DIR_NAME, fname) # relpath
        )



class ConfigFile(ConfigFileBase):
    """
        Offer:
            device config file info.

        Usage:
            cfg = ConfigFile('dev_id1', 'config.xml')
            print cfg.atime
            print cfg.path
            print cfg.mtime
            ...
            print cfg.state

            # update info (sync)
            cfg.load()
    """

    DEV_CFG_DIR_NAME = 'cfgfile'

    # config file state
    STATE_DOWNLOADING = 'downloading'
    STATE_BROKEN = 'broken'
    STATE_NORMAL = 'normal'
    STATE_NO_SUCH = 'no_such'


    @staticmethod
    def decode_file_id(file_id):
        return base64.urlsafe_b64decode(str(file_id)).split('_', 1)

    @staticmethod
    def encode_file_id(device_id, file_name):
        return base64.urlsafe_b64encode("%s_%s" % (device_id, file_name))

    @staticmethod
    def get_path(device_id=None, file_name=None, file_id=None):
        """
            return absolute path of a device's config file.
        """
        if file_id:
            device_id, file_name = ConfigFile.decode_file_id(file_id)
        else:
            assert device_id and file_name

        dst_path = os.path.join(
            ConfigFile.DEV_DATA_DIR, 
            device_id, 
            ConfigFile.DEV_CFG_DIR_NAME, 
            file_name
        )
        return dst_path

    @staticmethod
    def get_tftp_rel_path(device_id, file_name):
        """
            return a device's config file path relative to tftpboot.
        """
        return os.path.join(
            ConfigFile.DEV_DIR_NAME, 
            device_id, 
            ConfigFile.DEV_CFG_DIR_NAME, 
            file_name
        )

    @staticmethod
    def exists(file_id):
        try:
            device_id, file_name = ConfigFile.decode_file_id(file_id)
        except (TypeError, ValueError) as e:
            # invalid file id
            warnings.warn("invalid config file id: %r" % file_id)
            return False

        abspath = ConfigFile.get_path(device_id, file_name)
        if os.path.isfile(abspath):
            return True
        else:
            if os.path.exists(abspath):
                warnings.warn('non regular file(%r) in device(%r) config dir. Remove' % (file_name, device_id))
                shutil.rmtree(abspath)
            return False


    @staticmethod
    def parse_config_file_state(fpath, file_stat=None):
        """
            check state of a device config file.
            input:
                fpath -> path of target config file
        """
        if valid_xml(fpath):
            return ConfigFile.STATE_NORMAL
        else:
            file_stat = file_stat or os.stat(fpath)
            mtime = file_stat.st_mtime
            if time.time() - mtime > ConfigFile.TFTP_TIMEOUT:
                return ConfigFile.STATE_BROKEN
            else:
                return ConfigFile.STATE_DOWNLOADING


    @staticmethod
    def assure_dev_cfg_dir(device_id):
        """
            create device config directory if not exists or not a dir.
            input:
                device_id
            output:
                the full path of device config file directory.
        """
        dev_cfg_dir = os.path.join(
            ConfigFile.DEV_DATA_DIR, 
            device_id, 
            ConfigFile.DEV_CFG_DIR_NAME
        )

        if os.path.exists(dev_cfg_dir):
            if not os.path.isdir(dev_cfg_dir):
                warnings.warn("device dir %r is not a direcotry, which is not expected. Will replace it.")
                os.remove(dev_cfg_dir)
                os.makedirs(dev_cfg_dir, mode=0777)
                os.chmod(dev_cfg_dir, 0777)
        else:
            os.makedirs(dev_cfg_dir, mode=0777)
            os.chmod(dev_cfg_dir, 0777)

        return dev_cfg_dir


    @staticmethod
    def delete_config_file(file_id):
        """
            delete config file if exists
        """
        device_id, file_name = ConfigFile.decode_file_id(file_id)
        abspath = ConfigFile.get_path(device_id, file_name)
        if os.path.exists(abspath):
            if os.path.isfile(abspath):
                os.remove(abspath)
            else:
                warnings.warn('non regular file(%r) in device(%r) config dir.' % (file_name, device_id))
                shutil.rmtree(abspath)

    @staticmethod
    def delete_device_config_files(device_id):
        """
            delete all config files of target device.
        """

        dev_cfg_dir = ConfigFile.assure_dev_cfg_dir(device_id)
        fnames = os.listdir(dev_cfg_dir)
        for fn in fnames:
            abspath = ConfigFile.get_path(device_id, fn)
            if os.path.isfile(abspath):
                os.remove(abspath)
            else:
                warnings.warn("%s is not a regular file in device %s config dir." % (fn, device_id))
                shutil.rmtree(abspath)

    @staticmethod
    def delete_device(device_id):
        dev_cfg_dir = os.path.join(
            ConfigFile.DEV_DATA_DIR, 
            device_id
        )

        if os.path.exists(dev_cfg_dir):
            if os.path.isfile(dev_cfg_dir):
                os.remove(dev_cfg_dir)
            else:
                shutil.rmtree(dev_cfg_dir)


    @staticmethod
    def rename_config_file(file_id, new_name):
        """
            rename config file
        """
        assert ConfigFile.exists(file_id)
        old_path = ConfigFile.get_path(file_id=file_id)
        new_path = os.path.join(os.path.dirname(old_path), new_name)
        os.rename(old_path, new_path)


    def __init__(self, device_id=None, file_name=None, file_id=None):
        if file_id:
            self._id = file_id
            self._dev_id, self._name = self.decode_file_id(file_id)
        else:
            assert device_id and file_name
            self._dev_id = device_id
            self._name = file_name
            self._id = self.encode_file_id(device_id, file_name)

        self._dev_mac = decode_device_id(self._dev_id)

        self._abspath = self.get_path(self._dev_id, self._name)
        assert os.path.isfile(self._abspath), 'config file path %r is not a regular file. Or does not exist.' % dst_path
        self._tftp_relpath = self.get_tftp_rel_path(self._dev_id, self._name)
        self.reload()

    def __eq__(self, another):
        return self._id == another._id

    def __ne__(self, another):
        return not self.__eq__(another)

    def __hash__(self):
        return hash(self._id)


    def __repr__(self):
        return "<ConfigFile device_id=%r, name=%r>" % (self._dev_id, self._name)

    def __str__(self):
        return self.__repr__()


    def reload(self):
        """
            reload info.
        """
        info = os.stat(self._abspath)

        self._inode = info.st_ino
        self._dev = info.st_dev
        self._size = info.st_size
        self._mtime = info.st_mtime
        self._ctime = info.st_ctime
        self._atime = info.st_atime
        self._blksize = info.st_blksize
        self._blocks = info.st_blocks
        self._uid = info.st_uid
        self._gid = info.st_gid
        self._mode = info.st_mode
        self._nlink = info.st_nlink
        self._rdev = info.st_rdev
        self._state = self.parse_config_file_state(self._abspath, info)


    @property
    def id(self):
        return self._id

    @property
    def device_id(self):
        return self._dev_id

    @property
    def device_mac(self):
        return self._dev_mac

    @property
    def name(self):
        return self._name

    @property
    def abspath(self):
        return self._abspath

    @property
    def tftp_relpath(self):
        return self._tftp_relpath

    @property
    def inode(self):
        return self._inode

    @property
    def dev(self):
        return self._dev

    @property
    def size(self):
        return self._size

    @property
    def mtime(self):
        return self._mtime

    @property
    def ctime(self):
        return self._ctime

    @property
    def atime(self):
        return self._atime

    @property
    def blksize(self):
        return self._blksize

    @property
    def blocks(self):
        return self._blocks

    @property
    def uid(self):
        return self._uid

    @property
    def gid(self):
        return self._gid

    @property
    def mode(self):
        return self._mode

    @property
    def nlink(self):
        return self._nlink

    @property
    def rdev(self):
        return self._rdev

    @property
    def state(self):
        return self._state

    def to_dict(self):
        """
            jsonable dict
        """
        return {
            "id": self._id,
            "device_id": self._dev_id,
            "device_mac": self._dev_mac,
            "name": self._name,

            "inode": self._inode,
            "dev": self._dev,
            "size": self._size,
            "mtime": self._mtime,
            "ctime": self._ctime,
            "atime": self._atime,
            "blksize": self._blksize,
            "blocks": self._blocks,
            "uid": self._uid,
            "gid": self._gid,
            "mode": self._mode,
            "nlink": self._nlink,
            "rdev": self._rdev,
            "state": self._state
        }


assure_dev_cfg_dir = ConfigFile.assure_dev_cfg_dir


def get_device_config_files_info(device_id):
    """
        get config files for devices
    """
    dev_cfg_dir = assure_dev_cfg_dir(device_id)

    fnames = os.listdir(dev_cfg_dir)
    cfg_files = []
    for fn in fnames:
        abspath = ConfigFile.get_path(device_id, fn)
        if not os.path.isfile(abspath):
            warnings.warn("%s is not a regular file in device %s config dir." % (fn, device_id))
            continue
        cfg_files.append(ConfigFile(device_id=device_id, file_name=fn))
    return cfg_files


def get_config_file_info(file_id):
    """
        return target device config file info.
    """
    if ConfigFile.exists(file_id):
        return ConfigFile(file_id=file_id)
    else:
        return None



class ConfigFileBundle(ConfigFileBase):
    """
        To build a bundle of several config files.
        Usage:
            config_bundle = ConfigFileBundle(
                'test_bundle', 
                device_ids=['dev_id1', 'dev_id2'], 
                config_files=['cf_id1', 'cf_id2', ConfigFile(xxx)]
            )
    """

    DEV_CFG_BUNDLE_DIR_NAME = 'config_bundle'
    MIME_TYPE = 'application/x-tar'

    @staticmethod
    def assure_config_bundle_dir():
        """
            create config bundle directory if not exists or not a dir.
            output:
                the full path of device config file directory.
        """
        config_bundle_dir = os.path.join(
            ConfigFileBundle.DEV_DATA_DIR, 
            ConfigFileBundle.DEV_CFG_BUNDLE_DIR_NAME
        )

        if os.path.exists(config_bundle_dir):
            if not os.path.isdir(config_bundle_dir):
                warnings.warn("config bundle dir %r is not a direcotry, which is not expected. Will replace it.")
                os.remove(config_bundle_dir)
                os.makedirs(config_bundle_dir, mode=0777)
                os.chmod(config_bundle_dir, 0777)
        else:
            os.makedirs(config_bundle_dir, mode=0777)
            os.chmod(config_bundle_dir, 0777)

        return config_bundle_dir


    @staticmethod
    def get_path(name):
        """
            return the absolute path of a device.
        """
        return os.path.join(
            ConfigFileBase.DEV_DATA_DIR, 
            ConfigFileBundle.DEV_CFG_BUNDLE_DIR_NAME, 
            name
        )

    @staticmethod
    def exists(name):
        """
            check if the bundle exists and a valid one.
        """
        bundle_path = ConfigFileBundle.get_path(name)
        if os.path.exists(bundle_path):
            return tarfile.is_tarfile(bundle_path)
        else:
            return False


    def __init__(self, name, device_ids=None, config_files=None):
        """
            input:
                name -> bundle name (not a path, just name)
                device_ids -> [device_id], include config files of devices.
                config_files ->  [file_id|ConfigFile,], include config files.
        """
        self._abspath = self.get_path(name)
        self._members = set()

        if device_ids:
            self.add_devices(device_ids)

        if config_files:
            self.add(config_files)


    def add(self, config_files):
        """
            add one or multiple config files.
        """
        if not config_files:
            return

        if not isinstance(config_files, (list, set, tuple)):
            config_files = [config_files]

        for cf in config_files:
            if not isinstance(cf, ConfigFile):
                cf = ConfigFile(file_id=cf)
            self._members.add(cf)


    def remove(self, config_files):
        """
            remove one or multiple config files.
            input:
                config_files 
                    -> [cfg_file_id|ConfigFile(xxx)]
                        or
                        cfg_file_id|ConfigFile(xxx)
        """
        if not config_files:
            return

        if not isinstance(config_files, (list, set, tuple)):
            config_files = [config_files]

        config_files = [cf if isinstance(cf, ConfigFile) else ConfigFile(file_id=cf)
                        for cf in config_files]

        self._members = self._members.difference(config_files)


    def add_devices(self, device_ids):
        """
            add config files of devices.
        """

        if not device_ids:
            return

        if not isinstance(device_ids, (list, tuple, set)):
            device_ids = [device_ids]

        for dev_id in device_ids:
            cfg_files = get_device_config_files_info(dev_id)
            self._members = self._members.union(cfg_files)


    def remove_devices(self, device_ids):
        """
            remove devices' config files from bundle.
        """
        if not device_ids:
            return

        if not isinstance(device_ids, (list, tuple, set)):
            device_ids = [device_ids]

        for dev_id in device_ids:
            cfg_files = get_device_config_files_info(dev_id)
            self._members = self._members.difference(cfg_files)


    def save(self):
        """
            build a tar file.
        """
        self.assure_config_bundle_dir()
        with tarfile.open(self._abspath, 'w') as tf:
            for cf in self._members:
                dev_mac = decode_device_id(cf.device_id)
                tf.add(
                    cf.abspath, 
                    arcname=os.path.join(self.DEV_CFG_BUNDLE_DIR_NAME, dev_mac, cf.name)
                )





