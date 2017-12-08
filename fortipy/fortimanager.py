'''
FortiManager
Author: Philipp Schmitt <philipp.schmitt@post.lu>
URLs: https://fndn.fortinet.net/index.php?/topic/52-an-incomplete-list-of-url-parameters-for-use-with-the-json-api/
'''

from __future__ import absolute_import
from __future__ import print_function
from .forti import (login_required, Forti)
import json
import logging
import sys


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# Custom exceptions
class LockException(Exception):
    pass


class CommitException(Exception):
    pass


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
        logger.debug(lock)
        if lock['result'][0]['status']['code'] != 0:
            raise LockException('Unable to lock ADOM')
        res = f(self, *args, **kwargs)
        commit = self.commit(adom=adom)
        logger.debug(commit)
        if commit['result'][0]['status']['code'] != 0:
            raise CommitException('Unable to commit changes')
        unlock = self.unlock_adom(adom=adom)
        logger.debug(unlock)
        return res
    return _wrapper


class FortiManager(Forti):
    '''
    FortiManager class (SOAP/XML API)
    '''

    @login_required
    def get_system_status(self):
        # TODO This method may be common to FortiManager and Analyzer
        return self._get('sys/status')

    @login_required
    def get_serial_number(self):
        return self.get_system_status().get('Serial Number', None)

    @login_required
    def get_version(self):
        return self.get_system_status().get('Version', None)

    @login_required
    def get_hostname(self):
        return self.get_system_status().get('Hostname', None)

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
        return self._request(data)

    @login_required
    def get_adoms(self):
        request_id = 42
        url = 'dvmdb/adom'
        option = 'object member'
        return self._get(url=url, request_id=request_id, option=option)

    @login_required
    def get_load_balancers(self, adom):
        request_id = 545634
        url = 'pm/config/adom/{}/obj/firewall/ldb-monitor'.format(adom)
        return self._get(url=url, request_id=request_id)

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
        return self._request(data)

    @login_required
    def get_policies(self, adom, policy_id=None, policy_package='default'):
        '''
        Read a policy
        If policy_id is supplied retrieve only the corresponding policy
        Otherwise get all policies in package
        '''
        request_id = 13789
        url = 'pm/config/adom/{}/pkg/{}/firewall/policy/{}'.format(
            adom,
            policy_package,
            policy_id if policy_id else ''
        )
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_policy(self, adom, policy_id, policy_package='default'):
        return self.get_policies(
            adom, policy_package=policy_package, policy_id=policy_id
        )

    @login_required
    def get_all_policies(self, adom):
        policies = []
        policy_packages = self.get_policy_package_names(adom)
        if not policy_packages:
            return
        for polpkg in policy_packages:
            pols = self.get_policies(adom=adom, policy_package=polpkg)
            if pols:
                policies += pols
        return policies

    @login_required
    def get_policy_packages(self, adom):
        request_id = 900001
        url = 'pm/pkg/adom/{}/'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_policy_package_names(self, adom):
        policy_packages = self.get_policy_packages(adom)
        if not policy_packages:
            return
        package_names = []
        for pol_pkg in policy_packages:
            children = pol_pkg.get('subobj')
            if children:
                # FIXME This only works with a depth of one!
                for child in children:
                    package_names.append(
                        '{}/{}'.format(pol_pkg.get('name'), child.get('name')))
            else:
                package_names.append(pol_pkg.get('name'))
        return package_names



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
        return self._request(data)

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
        return self._request(data)

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
        return self._request(data)

    @login_required
    @toggle_lock
    def add_policy(self, adom='root', policy_pkg='default',
                   data=None):
        return self.add(
            url='pm/config/adom/{}/pkg/{}/firewall/policy'.format(
                adom, policy_pkg
            ),
            data=data,
            request_id=666
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
            request_id=667
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
        return self._request(data)

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
        Get security profiles
        '''
        request_id = 5723
        url = 'pm/config/adom/{}/obj/firewall'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_firewall_addresses(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        request_id = 5623
        url = 'pm/config/adom/{}/obj/firewall/address'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_firewall_addresses6(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        request_id = 562
        url = 'pm/config/adom/{}/obj/firewall/address6'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_firewall_address6_groups(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        request_id = 5622,
        url = 'pm/config/adom/{}/obj/firewall/addrgrp6'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_firewall_address_groups(self, adom):
        '''
        Get all firewall adress groups defined for an ADOM
        '''
        request_id = 56227
        url = 'pm/config/adom/{}/obj/firewall/addrgrp'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_interfaces(self, adom):
        '''
        Get all interfaces defined for an ADOM
        '''
        request_id = 5682
        url = 'pm/config/adom/{}/obj/dynamic/interface'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_services(self, adom):
        '''
        Get all (firewall) services defined for an ADOM
        '''
        request_id = 5617
        url = 'pm/config/adom/{}/obj/firewall/service/custom'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_firewall_service_groups(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        request_id = 5616
        url = 'pm/config/adom/{}/obj/firewall/service/group'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_schedules(self, adom):
        '''
        Get all scheduless defined for an ADOM
        '''
        request_id = 5620
        url = 'pm/config/adom/{}/obj/firewall/schedule/recurring'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_firewall_schedule_groups(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        request_id = 56201
        url = 'pm/config/adom/{}/obj/firewall/schedule/group'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_firewall_vips(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        request_id = 5632
        url = 'pm/config/adom/{}/obj/firewall/vip'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_firewall_vip_groups(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        request_id = 5633
        url = 'pm/config/adom/{}/obj/firewall/vipgrp'.format(adom)
        return self._get(url=url, request_id=request_id)

    @login_required
    def get_devices(self, adom=None):
        '''
        Get all devices defined for an ADOM
        If adom is undefined return all devices
        '''
        url = 'dvmdb/adom/{}/device'.format(adom) if adom else 'dvmdb'
        return self._get(
            url=url,
            request_id=7465
        )

    @login_required
    def get_traffic_shapers(self, adom):
        '''
        Get all traffic shapers for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/shaper/traffic-shaper'.format(adom),
            request_id=5037
        )

    # Profiles

    @login_required
    def get_antivirus_profiles(self, adom):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/root/obj/antivirus/profile'.format(adom),
            request_id=8175
        )

    def get_webfilters(self, adom):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/webfilter/profile'.format(adom),
            request_id=8177
        )

    @login_required
    def get_ips_sensors(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/ips/sensor'.format(adom),
            request_id=9846
        )

    @login_required
    def get_application_sensors(self, adom):
        '''
        Get a list of all applications defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/application/list'.format(adom),
            request_id=7850
        )

    @login_required
    def get_users(self, adom):
        '''
        Get a list of all local users defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/user/local'.format(adom),
            request_id=9123
        )

    @login_required
    def json_get_groups(self, adom):
        '''
        Get a list of all user groups defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/user/group'.format(adom),
            request_id=9124
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
        return self._request(data)

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
        return self._request(data)

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
        return self._request(data)



if __name__ == '__main__':
    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    fm = FortiManager(
        host=host,
        username=username,
        password=password
    )
    print(fm.login())
