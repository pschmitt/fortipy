'''
FortiManager
Author: Philipp Schmitt <philipp.schmitt@post.lu>
URLs: https://fndn.fortinet.net/index.php?/topic/52-an-incomplete-list-of-url-parameters-for-use-with-the-json-api/
'''

from __future__ import print_function
from collections import namedtuple
from pprint import pprint
from suds.client import Client
import atexit
import datetime
import json
# import logging
import suds
import sys
import requests
import urllib2
import warnings


DEBUG = False
# How long a token should be considered valid (in minutes)
TOKEN_TIMEOUT = 2


# Custom exceptions
class LockException(Exception):
    pass


class CommitException(Exception):
    pass


def commonerrorhandler(f):
    '''
    Centralized exception handling for common errors such as invalid
    credentials or connection timeouts
    Credits: http://stackoverflow.com/a/7589537
    '''
    def wrapped(*args, **kw):
        '''
        Wrapper function
        '''
        try:
            result = f(*args, **kw)
            # if result.errorMsg.errorCode != 0:
            #     print(f.__name__, ': Something went wrong!',
            #           result.errorMsg.errorMsg, file=sys.stderr)
            # else:
            #     print('Success!')
            return result
        except suds.WebFault as e:
            if e.fault.faultstring == "Invalid admin user name '(null)'":
                print('Invalid credentials!', file=sys.stderr)
        except Exception as e:
            print('Caught exception', e)
    return wrapped


def login_required(f):
    '''
    Definition decorator for all function requiring an auth token
    Credit: http://stackoverflow.com/a/7590709
    '''
    def _wrapper(self, *args, **kwargs):
        '''
        Function to be applied on top of all decorated methods
        '''
        timediff = self._token_age - datetime.datetime.now()
        if timediff.total_seconds() / 60 > TOKEN_TIMEOUT:
            self.logout()  # Log out to invalidate previous token
            self.login()  # Request new token
        return f(self, *args, **kwargs)
    return _wrapper


def toggle_lock(f):
    '''
    Decorator that locks an ADOM before performing the requested
    action, and then unlocks it again
    '''
    def _wrapper(self, *args, **kwargs):
        '''
        Function to be applied on top of all deorated methods
        '''
        adom = kwargs['adom']
        lock = self.lock_adom(adom=adom)
        if DEBUG:
            print(lock)
        if lock['result'][0]['status']['code'] != 0:
            raise LockException('Unable to lock ADOM')
        res = f(self, *args, **kwargs)
        commit = self.commit(adom=adom)
        if DEBUG:
            print(commit)
        if commit['result'][0]['status']['code'] != 0:
            raise CommitException('Unable to commit changes')
        unlock = self.unlock_adom(adom=adom)
        if DEBUG:
            print(unlock)
        return res
    return _wrapper


class FortiManager(object):
    '''
    FortiManager class (SOAP/XML API)
    '''

    def __init__(self, host, port=8080, username=None, password=None):
        self.client = None
        try:
            self.client = Client('https://{}:{}'.format(host, port), timeout=3)
        except urllib2.URLError:
            warnings.warn('Could not initialize client. XML API methods ' +
                          "won't be accessible. Please make sure Web " +
                          'Services are activated in the System settings ' +
                          '(under Network)',
                          RuntimeWarning)
        self.json_url = 'https://{}/jsonrpc'.format(host)
        self.token = None
        self.client = None
        if self.client is None:
            credentials = namedtuple('Credentials', 'userID password')
            self.credentials = credentials(username, password)
        else:
            self.credentials = self.client.factory.create('servicePass')
            self.credentials.userID = username
            self.credentials.password = password
        # Actual age of the login token
        self._token_age = None
        self.login()

    # JSON requests

    # FIXME Implement an ID checking method to make sure the answer we are
    # getting is the one we are waiting for

    def __request(self, data):
        '''
        Perform a JSON request
        '''
        try:
            # Set verify to True to verify SSL certificates
            r = requests.post(self.json_url, data, verify=False)
            return r.json()
        except Exception as e:
            print('Exception:', e, file=sys.stderr)

    @login_required
    def syntax(self, url, id=1):
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": url,
                        "option": "syntax"
                    }
                ],
                "id": id,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get(self, url, id=11):
        '''
        Generic "get" function
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": url
                    }
                ],
                "id": id,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def add(self, url, data, id=12):
        '''
        Generic "add" function
        '''
        data = json.dumps(
            {
                "method": "add",
                "params": [
                    {
                        "url": url,
                        "data": data
                    }
                ],
                "id": id,
                "session": self.token
            }
        )
        return self.__request(data)


    @login_required
    def set(self, url, data, id=14):
        '''
        Generic "set" method
        '''
        data = json.dumps(
            {
                "method": "set",
                "params": [
                    {
                        "url": url,
                        "data": data
                    }
                ],
                "id": id,
                "session": self.token
            }
        )
        return self.__request(data)


    @login_required
    def delete(self, url, data, id=13):
        '''
        Generic "delete" function
        '''
        data = json.dumps(
            {
                "method": "delete",
                "params": [
                    {
                        "url": url,
                        "data": data
                    }
                ],
                "id": id,
                "session": self.token
            }
        )
        return self.__request(data)

    def login(self, username=None, password=None):
        '''
        Login using given credentials
        Return the session token
        '''
        if username is None:
            username = self.credentials.userID
        if password is None:
            password = self.credentials.password
        data = json.dumps(
            {
                "params": [
                    {
                        "url": "sys/login/user",
                        "data": [
                            {
                                "passwd": password,
                                "user": username
                            }
                        ]
                    }
                ],
                "session": 1,
                "id": 1,
                "method": "exec"
            }
        )
        self.token = self.__request(data)['session']
        # Automatically log out at program exit
        atexit.register(self.logout)
        self._token_age = datetime.datetime.now()
        return self.token

    @login_required
    def logout(self):
        '''
        Log out, invalidate the session token
        '''
        data = json.dumps(
            {
                "params": [
                    {
                        "url": "sys/logout"
                    }
                ],
                "session": self.token,
                "id": 3,
                "method": "exec"
            }
        )
        self.token = None
        return self.__request(data)

    @login_required
    def get_adom_vdom_list(self, verbose=False, skip=False):
        '''
        Get a list of all ADOMs and their assigned VDOMs
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "dvmdb/adom",
                        "option": "object member"
                    }
                ],
                "id": 42,
                "session": self.token,
                "verbose": verbose,
                "skip": skip
            }
        )
        return self.__request(data)

    @login_required
    @toggle_lock
    def add_policy_package(self, adom, data):
        '''
        Add a new device policy package
        adom: Name of the parent ADOM (ie. the destination)
        TODO
        '''
        data = json.dumps(
            {
                "method": "set",
                "params": [
                    {
                        "url": "pm/pkg/adom/{}".format(adom),
                        "data": [
                            {
                                "name": "test1",
                                "type": "pkg"
                            },
                            {
                                "name": "folder1",
                                "type": "folder",
                                "subobj": [
                                    {
                                        "name": "pkg01",
                                        "type": "pkg"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "id": 5,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_policy(self, policy_id=None, adom='root',
                   policy_package='default'):
        '''
        Read a policy
        If policy_id is supplied retrieve only the corresponding policy
        Otherwise get all policies in package
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url":
                            "pm/config/adom/{}/pkg/{}/firewall/policy/{}".format(
                                adom,
                                policy_package,
                                policy_id if policy_id else ''
                            )
                    }
                ],
                "id": 13789,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def json_get_policy_packages(self, adom):
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/pkg/adom/{}/".format(adom)
                    }
                ],
                "id": 90001,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def rename_device(self, device):
        '''
        Rename a device
        '''
        pass

    @login_required
    def add_vdom(self, vdom):
        '''
        Create a new VDOM
        '''
        pass

    @login_required
    def assign_vdom_to_adom(self, adom, vdom):
        '''
        Assign an ADOM to a VDOM
        '''
        pass

    @login_required
    def get_adom_revision_list(self, adom='default',
                               verbose=False, skip=False):
        '''
        Get a list of all revisions for a given ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "dvmdb/adom/{}/revision".format(adom)
                    }
                ],
                "id": 899,
                "session": self.token,
                "verbose": verbose,
                "skip": skip
            }
        )
        return self.__request(data)

    @login_required
    def create_revision(self, adom, name=None, created_by=None,
                        description=None, locked=False):
        '''
        Create a new revision for a given ADOM
        '''
        if created_by is None:
            created_by = self.credentials.userID
        data = json.dumps(
            {
                "method": "set",
                "params": [
                    {
                        "url": "dvmdb/adom/{}/revision".format(adom),
                        "data": {
                            "created_by": created_by,
                            "desc": description,
                            "locked": locked,
                            "name": name
                        }
                    }
                ],
                "id": 12015,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def delete_adom_revision(self, adom, revision_id):
        return self.delete(
            url='dvmdb/adom/{}/revision/{}'.format(
                adom, revision_id
            ),
            data=None
        )

    @login_required
    def revert_revision(self, adom, revision_id, name=None, created_by=None,
                        locked=False, description=None):
        '''
        Revert ADOM to a previous revision
        '''
        if created_by is None:
            created_by = self.credentials.userID
        data = json.dumps(
            {
                "method": "clone",
                "params": [
                    {
                        "url": "dvmdb/adom/{}/revision/{}".format(adom, revision_id),
                        "data": {
                            "created_by": created_by,
                            "desc": description,
                            "locked": locked,
                            "name": name
                        }
                    }
                ],
                "id": 8921,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    @toggle_lock
    def add_policy(self, adom='root', policy_pkg='default',
                   data=None):
        return self.add(
            url='pm/config/adom/{}/pkg/{}/firewall/policy'.format(
                adom, policy_pkg
            ),
            data=data,
            id=666
        )

    @login_required
    @toggle_lock
    def edit_policy(self, adom, policy_id):
        pass

    # Add objects
    @login_required
    @toggle_lock
    def add_interface(self, adom='root', data=None):
        return self.add(
            url='pm/config/adom/{}/obj/dynamic/interface'.format(adom),
            data=data,
            id=667
        )

    @login_required
    @toggle_lock
    def delete_policy(self, policy_id, adom='root', policy_pkg='default'):
        '''
        Delete a policy
        '''
        data = json.dumps(
            {
                "method": "delete",
                "params": [
                    {
                        "url": "pm/config/adom/{}/pkg/{}/firewall/policy/{}".format(
                            adom, policy_pkg, policy_id
                        )
                    }
                ],
                "id": 89561,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    @toggle_lock
    def delete_interface(self, interface, adom='root'):
        '''
        Delete an interface
        '''
        return self.delete(
            'pm/config/adom/{}/obj/dynamic/interface/{}'.format(adom, interface),
            None
        )

    @login_required
    def get_security_profiles(self, adom):
        '''
        test
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall".format(adom)
                    }
                ],
                "id": 5623,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_firewall_addresses(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/address".format(adom)
                    }
                ],
                "id": 5623,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_firewall_addresses6(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/address6".format(adom)
                    }
                ],
                "id": 562,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_firewall_address6_groups(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/addrgrp6".format(adom)
                    }
                ],
                "id": 5622,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_firewall_address_groups(self, adom):
        '''
        Get all firewall adress groups defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/addrgrp".format(adom)
                    }
                ],
                "id": 56227,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_interfaces(self, adom):
        '''
        Get all interfaces defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/dynamic/interface".format(adom)
                    }
                ],
                "id": 5682,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_services(self, adom):
        '''
        Get all (firewall) services defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/service/custom".format(adom)
                    }
                ],
                "id": 5617,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_firewall_service_groups(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/service/group".format(adom)
                    }
                ],
                "id": 5616,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_schedules(self, adom):
        '''
        Get all scheduless defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/schedule/recurring".format(adom)
                    }
                ],
                "id": 5620,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_firewall_schedule_groups(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/schedule/group".format(adom)
                    }
                ],
                "id": 5620,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_firewall_vips(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/vip".format(adom)
                    }
                ],
                "id": 5632,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_firewall_vip_groups(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "pm/config/adom/{}/obj/firewall/vipgrp".format(adom)
                    }
                ],
                "id": 5633,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def json_get_devices(self, adom):
        '''
        Get all devices defined for an ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "dvmdb/adom/{}/device".format(adom)
                    }
                ],
                "id": 7465,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def get_traffic_shapers(self, adom):
        '''
        Get all traffic shapers for an ADOM
        '''
        return self.get(
            url='pm/config/adom/{}/obj/firewall/shaper/traffic-shaper'.format(adom),
            id=5037
        )

    # Profiles

    @login_required
    def get_antivirus_profiles(self, adom):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self.get(
            url='pm/config/adom/root/obj/antivirus/profile'.format(adom),
            id=8175
        )

    def get_webfilters(self, adom):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self.get(
            url='pm/config/adom/{}/obj/webfilter/profile'.format(adom),
            id=8177
        )

    @login_required
    def get_ips_sensors(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self.get(
            url='pm/config/adom/{}/obj/ips/sensor'.format(adom),
            id=9846
        )

    @login_required
    def get_application_sensors(self, adom):
        '''
        Get a list of all applications defined for an ADOM
        '''
        return self.get(
            url='pm/config/adom/{}/obj/application/list'.format(adom),
            id=7850
        )

    @login_required
    def get_users(self, adom):
        '''
        Get a list of all local users defined for an ADOM
        '''
        return self.get(
            url='pm/config/adom/{}/obj/user/local'.format(adom),
            id=9123
        )

    @login_required
    def json_get_groups(self, adom):
        '''
        Get a list of all user groups defined for an ADOM
        '''
        return self.get(
            url='pm/config/adom/{}/obj/user/group'.format(adom),
            id=9124
        )

    # Workspace functions (FortiManager 5 Patch Release 3)

    @login_required
    def lock_adom(self, adom):
        '''
        Lock an ADOM
        '''
        data = json.dumps(
            {
                "method": "exec",
                "params": [
                    {
                        "url": "pm/config/adom/{}/_workspace/lock".format(adom)
                    }
                ],
                "id": 5612,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def unlock_adom(self, adom):
        '''
        Unclock an ADOM
        '''
        data = json.dumps(
            {
                "method": "exec",
                "params": [
                    {
                        "url": "pm/config/adom/{}/_workspace/unlock".format(adom)
                    }
                ],
                "id": 5613,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def commit(self, adom):
        '''
        Commit changes made to ADOM
        '''
        data = json.dumps(
            {
                "method": "exec",
                "params": [
                    {
                        "url": "pm/config/adom/{}/_workspace/commit".format(adom)
                    }
                ],
                "id": 5614,
                "session": self.token
            }
        )
        return self.__request(data)

    # SOAP/XML function

    @commonerrorhandler
    def add_adom(self, name, firmware_version, firmware_major_release,
                 backup_mode=False, vpn_management=False,
                 device_serial_vdom=None, device_id_vdom=None):
        '''
        Create a new adom
        name: Name of the adom
        firmware_version: FortiOS version (either 400 or 500)
        firmware_major_release: Firmware major release version
        # FIXME: What's the difference between firmware and mr?
        backup_mode: Adom backup mode
        vpn_management: Whether to activate the ADOM VPN console
        device_serial_vdom: XML structure (list of devIDVdom)
        device_id_vdom: XML structure (lsit of devSNVdom)
        # FIXME: What's the difference between VDOM ID and identifier?
        '''
        return self.client.service.addAdom(
            servicePass=self.credentials,
            name=name,
            version=firmware_version,
            mr=firmware_major_release,
            isBackupMode=backup_mode,
            VPNManagement=vpn_management,
            deviceSNVdom=device_serial_vdom,
            deviceIDVdom=device_id_vdom,
        )

    @commonerrorhandler
    def add_device(self, ip, admin_user, adom=None, auto_discovery='False',
                   device_type=None, name=None,
                   password=None, firmware_version=None,
                   firmware_major_release=None, device_model=None,
                   flags=None, description=None, device_id=None,
                   serial=None, serial_prefix=None):
        '''
        Add a new device to an ADOM
        adom: In which ADOM to add the device (defaults to the admin's)
        ip: IP address of the device
        device_type: Type of device (FortiGate, FortiCarrier or FortiSwitch)
        name: Name of the device
        admin_user: Name of the administrator
        password: Administrator password
        firmware_version: FortiOS version (either 400 or 500)
        firmware_major_release: Firmware major release version
        # FIXME: What's the difference between firmware and mr?
        device_model: Device model number (eg: FGT-60C)
        flags: harddisk (if the device has a HDD installed) or None
        description: Desription of the device
        serial: Serial number of the device
        serial_prefix: Serial number prefix of the device
        '''
        return self.client.service.addDevice(
            servicePass=self.credentials,
            adom=adom,
            ip=ip,
            autod=auto_discovery,
            deviceType=device_type,
            name=name,
            adminUser=admin_user,
            password=password,
            version=firmware_version,
            mr=firmware_major_release,
            model=device_model,
            flags=flags,
            description=description,
            devId=device_id,
            SN=serial,
            SNprefix=serial_prefix
        )

    @commonerrorhandler
    def add_group(self, name, adom=None, description=None, device_serials=None,
                  device_ids=None, sub_groups=None, sub_group_ids=None):
        '''
        Create a new group
        adom: In which ADOM to add the group (defaults to the admin's)
        name: Name of the group
        description: Description of the group
        device_serials: List of device serial numbers that belong to this group
        device_ids: List of device IDs that belong to this group
        sub_groups: List of names of the subgroups that belong to this group
        sub_group_ids: List of IDs of the subgroups that belong to this group
        '''
        return self.client.service.addGroup(
            servicePass=self.credentials,
            adom=adom,
            name=name,
            description=description,
            deviceSN=device_serials,
            deviceID=device_ids,
            groupName=sub_groups,
            groupID=sub_group_ids
        )

    @commonerrorhandler
    def delete_adom(self, adom=None, adom_oid=None):
        '''
        Delete an adom
        adom: Name of the ADOM to delete
        adom_oid: Object Identifier of the ADOM to delete
        '''
        return self.client.service.deleteAdom(
            servicePass=self.credentials,
            adomName=adom,
            adomOid=adom_oid
        )

    @commonerrorhandler
    def delete_config_revision(self, device_id=None, serial=None,
                               revision_name=None, revision_id=None):
        '''
        Delete a configuration revision
        device_id: ID of the target device
        serial: Serial number of the target device
        revision_name: Name of the revision to delete
        revision_id: ID of the revision to delete
        '''
        return self.client.service.deleteConfigRev(
            servicePass=self.credentials,
            devId=device_id,
            serialNumber=serial,
            revName=revision_name,
            revId=revision_id
        )

    @commonerrorhandler
    def delete_device(self, device_id=None, serial=None):
        '''
        Delete a device
        device_id: ID of the device to delete
        serial: Serial number of the device to delete
        '''
        return self.client.service.deleteDevice(
            servicePass=self.credentials,
            devId=device_id,
            serialNumber=serial
        )

    @commonerrorhandler
    def edit_adom(self, adom=None, firmware_version=None,
                  firmware_major_release=None, disable=False,
                  backup_mode=False, vpn_management=False,
                  metafields=None, device_serial_vdom=None,
                  device_id_vdom=None):
        '''
        Edit an adom
        adom: Name of the adom to edit
        firmware_version: FortiOS version (either 400 or 500)
        firmware_major_release: Firmware major release version
        # FIXME: What's the difference between firmware and mr?
        disable: Whether to enable or disable ADOMs
        backup_mode: Whether to activate backup mode
        vpn_management: Whether to activate the VPN console
        metafields: list of key-value pairs
        device_serial_vdom: list of devSNVdom
        device_id_vdom: list devIDVdom
        '''
        return self.client.service.editAdom(
            servicePass=self.credentials,
            name=adom,
            version=firmware_version,
            mr=firmware_major_release,
            state=disable,
            isBackupMode=backup_mode,
            VPNManagement=vpn_management,
            metafields=metafields,
            addDeviceSNVdom=device_serial_vdom,
            addDeviceIDVdom=device_id_vdom
        )

    @login_required
    def json_get_adom_list(self):
        '''
        Get a list of ADOMs via the JSON API
        '''
        return self.get(url='dvmdb/adom', id=1)

    @commonerrorhandler
    def get_adom_list(self, detail=False):
        '''
        Get a list of the ADOMs defined on your FortiManager unit
        Only a superuser is allowed to run this command
        '''
        return self.client.service.getAdomList(
            servicePass=self.credentials,
            detail=detail
        )

    @commonerrorhandler
    def get_adoms(self, names=None, adom_ids=None):
        '''
        Get a list of ADOMs
        FIXME How does this differ from get_adom_list?
        '''
        return self.client.service.getAdoms(
            servicePass=self.credentials,
            names=names,
            adomIds=adom_ids
        )

    @commonerrorhandler
    def get_config(self, device_id=None, serial=None, adom=None,
                   revision=-1):
        '''
        Get a particular revision of a device's configuration
        Revision: Which revision to display (-1: latest)
        '''
        return self.client.service.getConfig(
            servicePass=self.credentials,
            devId=device_id,
            serialNumber=serial,
            adom=adom,
            revisionNumber=revision
        )

    @commonerrorhandler
    def get_config_revision_history(self):
        '''
        Obtain a revision history for a given device
        '''
        pass

    @commonerrorhandler
    def get_devices(self, serial_numbers=None, device_ids=None):
        '''
        Get informations about specific managed devices
        '''
        return self.client.service.getDevices(
            servicePass=self.credentials,
            serialNumbers=serial_numbers,
            devIds=device_ids
        )

    @commonerrorhandler
    def get_device_license_list(self):
        '''
        Get a list of all device's licenses
        '''
        return self.client.service.getDeviceLicenseList(
            servicePass=self.credentials
        )

    @commonerrorhandler
    def get_device_list(self, adom=None, detail=False):
        '''
        Get informations about specific managed devices
        '''
        return self.client.service.getDeviceList(
            servicePass=self.credentials,
            adom=adom,
            detail=detail
        )

    @commonerrorhandler
    def get_device_vdom_list(self, device_name=None, device_id=None):
        '''
        Get a list of VDOMs for a device
        '''
        return self.client.service.getDeviceVdomList(
            servicePass=self.credentials,
            devName=device_name,
            devID=device_id
        )

    @commonerrorhandler
    def get_group_list(self, adom=None, detail=False):
        '''
        Get a list of all groups
        adom: list to a specific adom
        detail: Whether to show details
        '''
        return self.client.service.getGroupList(
            self.credentials, adom=adom, detail=detail
        )

    @commonerrorhandler
    def get_groups(self, adom=None, names=None, grpIds=None):
        '''
        Get a list of groups
        adom: If not set it default to root
        '''
        return self.client.service.getGroups(
            servicePass=self.credentials,
            adom=adom,
            names=names,
            grpIds=grpIds
        )

    @commonerrorhandler
    def get_install_log(self, device_id=None, serial=None, task_id=None):
        '''
        Retrieve the installation log
        '''
        return self.client.service.getInstlog(
            servicePass=self.credentials,
            devId=device_id,
            serialNumber=serial,
            taskId=task_id
        )

    @commonerrorhandler
    def get_policy_packages(self, adom=None):
        '''
        Get a list of policy packages
        '''
        return self.client.service.getPackageList(
            servicePass=self.credentials,
            adom=adom
        )

    @commonerrorhandler
    def get_system_status(self, adom=None):
        '''
        Retrieve status infos
        '''
        return self.client.service.getSystemStatus(
            servicePass=self.credentials,
            adom=adom
        )

    @commonerrorhandler
    def get_task_list(self, task_id, adom=None):
        '''
        Get a list of tasks set to run
        Requires to be run as a superuser
        '''
        return self.client.service.getTaskList(
            servicePass=self.credentials,
            adom=adom,
            taskId=task_id
        )

    @commonerrorhandler
    def retrieve_config(self, device_id=None, serial=None,
                        revision_name=None):
        '''
        Create (!) a new revision and return the latest running config
        Requires to be run as a superuser
        '''
        return self.client.service.retrieveConfig(
            servicePass=self.credentials,
            devId=device_id,
            serialNumber=serial,
            newRevName=revision_name
        )

    @commonerrorhandler
    def revert_config(self, revision_id, device_id=None, serial=None):
        '''
        Revert to the previous configuruation
        Requires to be run as a superuser
        revision_id: The ID of the revision to revert to (?)
        '''
        return self.client.service.revertConfig(
            servicePass=self.credentials,
            devId=device_id,
            serialNumber=serial,
            revId=revision_id
        )

    # FortiAnalyzer methods
    @commonerrorhandler
    def get_faz_config(self):
        '''
        Retrieve the FortiAnalyzer config
        '''
        return self.client.service.getFazConfig(
            servicePass=self.credentials
        )

    @commonerrorhandler
    def set_faz_config(self, adom=None, config=None):
        '''
        Alter the FortiAnalyzer config
        '''
        return self.client.service.setFazConfig(
            servicePass=self.credentials,
            adom=adom,
            config=config
        )

    @commonerrorhandler
    def run_faz_report(self, adom=None, report_name=None):
        '''
        Launch a report about web services
        To retrieve the report use get_faz_generated_reports()
        '''
        return self.client.service.runFazReport(
            servicePass=self.credentials,
            adom=adom,
            reportSchedName=report_name
        )

    @commonerrorhandler
    def get_faz_generated_reports(self, adom=None, report_date=None,
                                  report_name=None, compression=None):
        '''
        Obtain a full report
        report_date: Report generation date (will be formatted to YYYY_MM_DD)
        compression: tar or gzip
        Returns a base64 encoded report
        '''
        if report_date is not None:
            report_date = report_date.strftime('%Y_%m_%d')
        return self.client.service.getFazGeneratedReports(
            servicePass=self.credentials,
            adom=adom,
            reportDate=report_date,
            reportName=report_name,
            compression=compression
        )

    @commonerrorhandler
    def __get_archive_type_value(self, archive_type):
        '''
        Get the real value of the desired archive type
        '''
        return getattr(
            self.client.factory.create('archiveTypes'),
            archive_type
        )

    @commonerrorhandler
    def search_faz_log(self, adom=None, log_content=None, log_format=None,
                       log_type=None, search_criteria=None, max_matches=None,
                       start_index=None, check_archive=False):
        '''
        Search FAZ logs
        '''
        pass

    @commonerrorhandler
    def get_faz_archive(self, adom=None, device_id=None, archive_type=None,
                        filename=None, zip_password=None, files=None):
        '''
        Get a FAZ archive
        zip_password: Optional archive password
        '''
        if archive_type is not None:
            archive_type = self.__get_archive_type_value(archive_type)
        return self.client.service.getFazArchive(
            servicePass=self.credentials,
            adom=adom,
            devId=device_id,
            type=archive_type,
            zipPassword=zip_password,
            fileName=filename,
            filelist=files
        )

    @commonerrorhandler
    def list_faz_generated_reports(self, adom=None, start_date=None,
                                   end_date=None):
        '''
        List all previously genereated reports
        '''
        return self.client.service.listFazGeneratedReports(
            servicePass=self.credentials,
            adom=adom,
            startDate=start_date,
            endDate=end_date
        )

    @commonerrorhandler
    def install_config(self, origin=None, destination=None, adom=None,
                       package_oid=None, device_id=None, serial=None,
                       revision_name=None):
        '''
        Install previously requested changes on devices
        '''
        return self.client.service.installConfig(
            servicePass=self.credentials,
            # FIXME 'from' is a reserved keyword in python!
            # from=origin,
            to=destination,
            adom=adom,
            pkgoid=package_oid,
            devId=device_id,
            serialNumber=serial,
            newRevName=revision_name
        )

    @commonerrorhandler
    def remove_faz_archive(self, adom=None, device_id=None, archive_type=None,
                           filename=None, checksum=None):
        '''
        Remove a FAZ archive
        archive_type: Web(0), Email(1), FTP(2), IM(3), MMS(4), Quarantaine(5),
                      IPS(6)
        checksum: only when Quarantaine is used (filename is not ignored in
                  this case)
        '''
        if archive_type is not None:
            archive_type = self.__get_archive_type_value(archive_type)
        return self.client.service.removeFazArchive(
            servicePass=self.credentials,
            adom=adom,
            devId=device_id,
            type=archive_type,
            fileName=filename,  # yes it's fileName
            checksum=checksum
        )

    # Script functions

    @commonerrorhandler
    def create_script(self, adom=None, script_name=None, script_type=None,
                      description=None, script_content=None, overwrite=False):
        '''
        Upload a script to the FortiManager
        Return codes: 0 by success, 1 by failure
        '''
        return self.client.service.createScript(
            servicePass=self.credentials,
            adom=adom,
            name=script_name,
            type=script_type,
            description=description,
            content=script_content,
            overwrite=overwrite
        )

    @commonerrorhandler
    def delete_script(self, script_name=None, script_type=None):
        '''
        Delete a script
        script_type: Type of script (CLI, TCL, CLIGROUP)
        '''
        return self.client.service.deleteScript(
            servicePass=self.credentials,
            name=script_name,
            type=script_type
        )

    @commonerrorhandler
    def get_script(self, script_name=None, script_type=None):
        '''
        Retrieve a script
        '''
        return self.client.service.getScript(
            servicePass=self.credentials,
            name=script_name,
            type=script_type
        )

    @commonerrorhandler
    def get_script_log(self, script_name=None, device_id=None, serial=None,
                       log_id=None):
        '''
        Get a script's log
        '''
        return self.client.service.getScriptLog(
            servicePass=self.credentials,
            scriptname=script_name,
            devId=device_id,
            serialNumber=serial,
            logId=log_id
        )

    @commonerrorhandler
    def get_script_log_summary(self, device_id=None, serial=None,
                               max_logs=None):
        '''
        Retrieve the summary of a script's log
        max_logs: The maximum amount of logs to include in the summary (???)
        '''
        return self.client.service.getScriptLogSummary(
            servicePass=self.credentials,
            devId=device_id,
            serialNumber=serial,
            maxLogs=max_logs
        )

    @commonerrorhandler
    def run_script(self, script_name=None, script_type=None, device_id=None,
                   serial=None, run_on_database=None, package_oid=None):
        '''
        Run a script
        device_id: ID of the device to run the script on (set to -1 to run
                   globally)
        script_type: Type of script (CLI, TCL, CLIGROUP)
        run_on_database: Run on global or device DB, depending on device ID (1)
                         Run on the device. Required either device_id or serial
                         to be set (0)
        '''
        return self.client.service.runScript(
            servicePass=self.credentials,
            name=script_name,
            type=script_type,
            devId=device_id,
            serialNumber=serial,
            runOnDB=run_on_database,
            pkgoid=package_oid
        )


if __name__ == '__main__':
    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    fm = FortiManager(
        host=host,
        username=username,
        password=password
    )
    # logging.basicConfig(level=logging.DEBUG)
    # logging.getLogger('suds.client').setLevel(logging.DEBUG)
    # logging.getLogger('suds.transport').setLevel(logging.DEBUG)

    # print(fm.add_adom('AADELETEME', firmware_version=500,
    #                   firmware_major_release=0))
    # print(fm.add_device(name='DELETEME_DEVICE', ip='10.0.255.3',
    #                     device_type='FortiGate', admin_user='admin'))
    # print(fm.get_group_list())
    # print(fm.get_devices())
    # print(fm.get_device_license_list())
    # print(fm.get_device_list())
    # print(fm.get_device_list('Cust_alphatax', True))
    # print(fm.get_adoms())
    # print(fm.get_adom_list())  # .adomInfo))
    # print(fm.get_devices(adom='Cust_eurofoil'))
    # print(fm.get_adoms(names=['Cust_brgaming', 'Cust_vincotte']))
    # print(fm.get_config(device_id=255))
    # print(fm.get_device_vdom_list(device_id=255))
    # print(fm.get_groups(adom='Cust_brgaming'))
    # print(fm.get_install_log(device_id=255))
    # print(fm.get_package_list())
    # print(fm.get_system_status())
    # print(fm.get_task_list(201))
    # print(fm.get_faz_generated_reports(report_name='test',
    #                                    compression='tar'))
    # print(fm.list_faz_generated_reports(end_date=datetime.datetime.now()))
    # print(fm.get_script_log_summary(device_id=255))
    # print(fm.retrieve_config(device_id=255,
    #                          revision_name='DELETEME_python_test'))
    # JSON functions
    print(fm.login())
    # print(fm.add_policy_package(adom='root', data=None))
    # print(fm.get_policy(adom='root', policy_id='1'))
    # print(json.dumps(fm.get_policy(adom='Cust_alzheimer', policy_package='alzheimer_policy'), indent=2))
    # print(json.dumps(fm.get_policy(adom='root', policy_package='default'), indent=2))
    # print(fm.json_get_package_list('Int_preprod'))
    # print(json.dumps(fm.get_adom_vdom_list(verbose=True, skip=True)['result'], indent=2))
    # for res in fm.get_adom_vdom_list(verbose=True, skip=True)['result']:
    #     for adom in res['data']:
    #         print(adom['name'])
    data = {
            "dstintf": "any",
            "nat": "enable",
            # "logtraffic": "enable",
            "service": [
                "HTTP",
                "HTTPS"
            ],
            "schedule": "always",
            "srcaddr": "all",
            "dstaddr": "all",
            "indentity-based": "disable",
            "action": "accept",
            "srcintf": "any"
        }
    pprint(fm.add_policy(
        adom='root',
        data=data
        # data=json.dumps(
        #     {
        #         "srcaddr": "all",
        #         "nat": "disable",
        #         "service": ["ALL"],
        #         "dstintf": "any",
        #         "srcintf": "any",
        #         "schedule": "always",
        #         "action": "deny",
        #         "dstaddr": "all"
        #     }
        # )
    ))
