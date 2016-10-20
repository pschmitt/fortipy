'''
FortiManager
Author: Philipp Schmitt <philipp.schmitt@post.lu>
URLs: https://fndn.fortinet.net/index.php?/topic/52-an-incomplete-list-of-url-parameters-for-use-with-the-json-api/
'''

from __future__ import print_function
from collections import namedtuple
import atexit
import datetime
import json
import logging
import requests
import sys


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


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
        # except suds.WebFault as e:
        #     if e.fault.faultstring == "Invalid admin user name '(null)'":
        #         print('Invalid credentials!', file=sys.stderr)
        except Exception as e:
            logger.error('Caught exception: {}'.format(e))
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
            logger.info('Token timeout has been reached. Let\'s login again')
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


class FortiManager(object):
    '''
    FortiManager class (SOAP/XML API)
    '''

    def __init__(self, host, username=None, password=None, verify=True):
        self.json_url = 'https://{}/jsonrpc'.format(host)
        self.token = None
        credentials = namedtuple('Credentials', 'userID password')
        self.credentials = credentials(username, password)
        self.verify = verify
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
        logger.debug('POST DATA: {}'.format(data))
        try:
            # Set verify to True to verify SSL certificates
            r = requests.post(self.json_url, data, verify=self.verify)
            return r.json()
        except requests.exceptions.SSLError as e:
            logger.error(
                'SSL Handshake failed: {}\n'
                'You may want to disable SSL cert verification '
                '[!!!INSECURE!!!]'.format(e)
            )
            raise e
        except Exception as e:
            logger.error('Caught Exception: {}'.format(type(e)))

    @login_required
    def syntax(self, url, rq_id=1):
        logger.debug('GET SYNTAX {}'.format(url))
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": url,
                        "option": "syntax"
                    }
                ],
                "id": rq_id,
                "session": self.token
            }
        )
        return self.__request(data)

    @login_required
    def __get(self, url, rq_id=11, option=None, verbose=False, skip=False):
        '''
        Generic "get" function
        '''
        logger.debug('GET {}'.format(url))
        data = {
            'method': 'get',
            'params': [{'url': url}],
            'id': rq_id,
            'session': self.token,
            'verbose': verbose,
            'skip': skip
        }
        if option:
            data['params'].append({'option': option})
        jdata = json.dumps(data)
        res = self.__request(jdata)
        assert res['id'] == rq_id, 'Request ID changed.'
        assert len(res['result']) == 1, 'More than one result has been returned'
        logger.debug(res)
        if 'data' in res['result'][0] and res['result'][0]['data']:
            return [x for x in res['result'][0]['data']]

    @login_required
    def __add(self, url, data, rq_id=12):
        '''
        Generic "add" function
        '''
        logger.debug('ADD {} - Data: {}'.format(url, data))
        data = json.dumps(
            {
                "method": "add",
                "params": [
                    {
                        "url": url,
                        "data": data
                    }
                ],
                "id": rq_id,
                "session": self.token
            }
        )
        return self.__request(data)


    @login_required
    def set(self, url, data, rq_id=14):
        '''
        Generic "set" method
        '''
        logger.debug('ADD {} - Data: {}'.format(url, data))
        data = json.dumps(
            {
                "method": "set",
                "params": [
                    {
                        "url": url,
                        "data": data
                    }
                ],
                "id": rq_id,
                "session": self.token
            }
        )
        return self.__request(data)


    @login_required
    def delete(self, url, data, rq_id=13):
        '''
        Generic "delete" function
        '''
        logger.debug('ADD {} - Data: {}'.format(url, data))
        data = json.dumps(
            {
                "method": "delete",
                "params": [
                    {
                        "url": url,
                        "data": data
                    }
                ],
                "id": rq_id,
                "session": self.token
            }
        )
        return self.__request(data)

    def __exec(self, url, data, rq_id=11, verbose=False, skip=False):
        '''
        Generic "exec" function
        '''
        logger.debug('EXEC {} - Data: {}'.format(url, data))
        token = self.token if self.token else 1
        data = json.dumps(
            {
                "method": "exec",
                "params": [
                    {
                        "url": url,
                        "data": data
                    }
                ],
                "id": rq_id,
                "session": token
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
        url = 'sys/login/user'
        data = {'passwd': password, 'user': username}
        res = self.__exec(url, data)
        assert res, 'No data received'
        self.token = res['session']
        # Automatically log out at program exit
        atexit.register(self.logout)
        self._token_age = datetime.datetime.now()
        return self.token

    @login_required
    def logout(self):
        '''
        Log out, invalidate the session token
        '''
        logger.debug('LOGOUT REQUEST')
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
    def get_adoms(self):
        rq_id = 42
        url = 'dvmdb/adom'
        option = 'object member'
        return self.__get(url=url, rq_id=rq_id, option=option)

    @login_required
    def get_load_balancers(self, adom):
        rq_id = 545634
        url = 'pm/config/adom/{}/obj/firewall/ldb-monitor'.format(adom)
        return self.__get(url=url, rq_id=rq_id)

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
    def get_policies(self, adom, policy_id=None, policy_package='default'):
        '''
        Read a policy
        If policy_id is supplied retrieve only the corresponding policy
        Otherwise get all policies in package
        '''
        rq_id = 13789
        url = 'pm/config/adom/{}/pkg/{}/firewall/policy/{}'.format(
            adom,
            policy_package,
            policy_id if policy_id else ''
        )
        return self.__get(url=url, rq_id=rq_id)

    @login_required
    def get_policy(self, adom, policy_id, policy_package='default'):
        return self.get_policies(
            adom, policy_package=policy_package, policy_id=policy_id
        )

    @login_required
    def get_all_policies(self, adom):
        policies = []
        policy_packages = self.get_policy_packages(adom)
        if policy_packages:
            for polpkg in [x['name'] for x in policy_packages]:
                pols = self.get_policies(adom=adom, policy_package=polpkg)
                if pols:
                    policies += pols
        return policies

    @login_required
    def get_policy_packages(self, adom):
        rq_id = 900001
        url = 'pm/pkg/adom/{}/'.format(adom)
        return self.__get(url=url, rq_id=rq_id)

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
            rq_id=666
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
            rq_id=667
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
        return self.__get(
            url='pm/config/adom/{}/obj/firewall/shaper/traffic-shaper'.format(adom),
            rq_id=5037
        )

    # Profiles

    @login_required
    def get_antivirus_profiles(self, adom):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self.__get(
            url='pm/config/adom/root/obj/antivirus/profile'.format(adom),
            rq_id=8175
        )

    def get_webfilters(self, adom):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self.__get(
            url='pm/config/adom/{}/obj/webfilter/profile'.format(adom),
            rq_id=8177
        )

    @login_required
    def get_ips_sensors(self, adom):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self.__get(
            url='pm/config/adom/{}/obj/ips/sensor'.format(adom),
            rq_id=9846
        )

    @login_required
    def get_application_sensors(self, adom):
        '''
        Get a list of all applications defined for an ADOM
        '''
        return self.__get(
            url='pm/config/adom/{}/obj/application/list'.format(adom),
            rq_id=7850
        )

    @login_required
    def get_users(self, adom):
        '''
        Get a list of all local users defined for an ADOM
        '''
        return self.__get(
            url='pm/config/adom/{}/obj/user/local'.format(adom),
            rq_id=9123
        )

    @login_required
    def json_get_groups(self, adom):
        '''
        Get a list of all user groups defined for an ADOM
        '''
        return self.__get(
            url='pm/config/adom/{}/obj/user/group'.format(adom),
            rq_id=9124
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
