from __future__ import print_function
from django.conf import settings
from fortimanager import FortiManager
from pprint import pprint
from tempfile import NamedTemporaryFile
from utils import sanitize
from xlwt import Workbook
import core.models as models
import core.tasks
import fortimanager
import functools
import keyring


__fm = None


def __forti():
    '''
    Return an instance of a FortiManager object
    '''
    global __fm
    if __fm is not None:
        return __fm
    # If the password was not defined in the settings file try to
    # retrieve it from the keyring
    password = settings.FORTIMANAGER_PASS
    if password is None or len(password) < 1:
        password = keyring.get_password(
            settings.FORTIMANAGER_HOST, settings.FORTIMANAGER_USER
        )
    else:
        password = settings.FORTIMANAGER_PASS
    __fm = FortiManager(
        host=settings.FORTIMANAGER_HOST,
        username=settings.FORTIMANAGER_USER,
        password=password
    )
    return __fm


def __get_data(response):
    '''
    Extract data from JSON reponse and sanitize keys
    '''
    data = []
    for res in response['result']:
        if 'data' in res:
            for i in res['data']:
                i = sanitize(i)
                data.append(i)
    return data


def __forti_invasive_function(func):
    '''
    Common error handling
    To be called by all functions requiring a lock/commit
    Return a boolean and the actual response
    The boolean is set to True if no error was caught
    '''
    try:
        adom = func.keywords['adom']
        response = func()
        success = True
    except fortimanager.LockException:
        response = {
            'result': [{
                'status': {
                    'code': -11,
                    'message': 'Unable to lock ADOM {}'.format(adom)
                }
            }]
        }
        success = False
    except fortimanager.CommitException:
        response = {
            'result': [{
                'status': {
                    'code': -12,
                    'message': 'Unable to commit changes'
                }
            }]
        }
        success = False
    return success, response


def get_adoms():
    '''
    Get a list of all adoms
    '''
    fm = __forti()
    response = fm.get_adom_vdom_list(verbose=True, skip=True)
    adoms = __get_data(response)
    # Sort alphabetically
    adoms = sorted(adoms, key=lambda s: s['name'].lower())
    return adoms


def get_devices(adom, verbose=False):
    '''
    Get a list of all devices belonging to a given ADOM
    '''
    fm = __forti()
    response = fm.json_get_devices(adom=adom)
    devices = __get_data(response)
    return devices


def get_policy_pkgs(adom=None, verbose=False):
    '''
    Get a list of all policy packages
    '''
    fm = __forti()
    response = fm.json_get_policy_packages(adom=adom)
    pkgs = []
    for res in response['result']:
        if 'data' in res:
            for pkg in res['data']:
                pkgs.append(pkg['name'])
    return pkgs


def get_policy(adom, policy_id, verbose=False):
    '''
    Get a policy by its ID
    '''
    fm = __forti()
    response = fm.get_policy(adom=adom, policy_id=policy_id)
    policy = None
    try:
        policy = sanitize(response['result'][0]['data'])
    except:
        pass
    if verbose:
        print('Get single policy')
        print('Policy ID:', policy_id)
        print('Policy:')
        pprint(policy)
    return policy


def get_policies(adom=None, verbose=False):
    '''
    Get a list of all policies
    adom: Restrict to a specific adom
    '''
    fm = __forti()
    pkgs = get_policy_pkgs(adom, verbose)
    policies = {}
    for pkg in pkgs:
        response = fm.get_policy(adom=adom, policy_package=pkg)
        for res in response['result']:
            if 'data' in res:
                policies[pkg] = []
                for policy in res['data']:
                    # Replace whitespace in keys
                    policy = sanitize(policy)
                    policies[pkg].append(policy)
    if verbose:
        print('Get policies')
        print('Packages:')
        pprint(pkgs)
        print('Policies:')
        pprint(policies)
    return policies


def backup_adom(adom, name, created_by=None, description=None, locked=False):
    '''
    Backup an ADOM Create a new revision
    '''
    fm = __forti()
    response = fm.create_revision(
        adom=adom,
        name=name,
        created_by=created_by,
        description=description,
        locked=locked
    )
    return response


def get_adom_backups(adom, skip=False, verbose=False):
    '''
    Get a list of backups (revisions) for a given ADOM
    '''
    fm = __forti()
    response = fm.get_adom_revision_list(
        adom=adom,
        verbose=verbose,
        skip=skip
    )
    return response


def restore_adom(adom, revision_id, revision_name=None, verbose=False):
    '''
    Restore an ADOM to a previous state (revert to revision)
    '''
    fm = __forti()
    response = fm.revert_revision(
        adom=adom,
        # name=revision_name,
        revision_id=revision_id
    )
    return response


def delete_revision(adom, revision_id, verbose=False):
    '''
    Delete an ADOM revision
    '''
    fm = __forti()
    response = fm.delete_adom_revision(
        adom=adom,
        revision_id=revision_id
    )
    return response


def delete_policy(adom, policy_pkg, policy_id, verbose=False):
    '''
    Delete a policy
    '''
    if verbose:
        print('Delete policy')
        print('Parameters:', adom, policy_pkg, policy_id)
    fm = __forti()
    try:
        response = fm.delete_policy(
            adom=adom,
            policy_pkg=policy_pkg,
            policy_id=policy_id
        )
        if response['result'][0]['status']['code'] == 0:
            adom_model = models.Adom.objects.get(name=adom)
            p = models.Policy.objects.get(
                adom=adom_model,
                policyid=policy_id
            )
            p.delete()
            response = {
                'result': [{
                    'status': {
                        'code': 0,
                        'message': 'Successfully removed policy ' + policy_id
                    }
                }]
            }
    except fortimanager.LockException:
        response = {
            'result': [{
                'status': {
                    'code': -11,
                    'message': 'Unable to lock ADOM ' + adom
                }
            }]
        }
    except fortimanager.CommitException:
        response = {
            'result': [{
                'status': {
                    'code': -12,
                    'message': 'Unable to commit changes'
                }
            }]
        }
    return response


def delete_object(adom, object_type, obj, verbose=False):
    '''
    Delete a policy
    '''
    if verbose:
        print('Delete object')
        print('Parameters:', adom, object_type, obj)
    fm = __forti()

    if object_type == 'interface':
        func = fm.delete_interface
    # TODO Support more object types!
    # elif object_type == 'address':
    #     func = fm.delete_address
    partial_func = functools.partial(
        func,
        obj,
        adom=adom
    )
    success, response = __forti_invasive_function(partial_func)
    if not success:
        return response
    if response['result'][0]['status']['code'] == 0:
        adom_model = models.Adom.objects.get(name=adom)
        if object_type == 'interface':
            p = models.Interface.objects.get(
                adom=adom_model,
                name=obj
            )
        elif object_type == 'address':
            p = models.Address.objects.get(
                adom=adom_model,
                name=obj
            )
        # TODO Support more object types
        # TODO Error handling!
        if p is not None:
            p.delete()
        response = {
            'result': [{
                'status': {
                    'code': 0,
                    'message': 'Successfully removed object ' + obj
                }
            }]
        }
    return response


def get_addresses(adom, verbose=False):
    '''
    Get a list of all addresses and address groups for a given ADOM
    '''
    fm = __forti()
    addresses = {}
    addresses['ipv4'] = fm.get_firewall_addresses(adom=adom)
    addresses['ipv6'] = fm.get_firewall_addresses6(adom=adom)
    addresses['group_ipv4'] = fm.get_firewall_address_groups(adom=adom)
    addresses['group_ipv6'] = fm.get_firewall_address6_groups(adom=adom)
    for key in addresses:
        for res in addresses[key]['result']:
            addresses[key] = []
            if 'data' in res:
                for addr in res['data']:
                    addr = sanitize(addr)
                    addresses[key].append(addr)
    if verbose:
        print('addresses:')
        pprint(addresses)
    return addresses


def get_ips_sensors(adom, verbose=False):
    '''
    Get a list of all IPS sensors for a given ADOM
    '''
    fm = __forti()
    response = sanitize(fm.get_ips_sensors(adom=adom))
    ips_sensors = __get_data(response)
    return ips_sensors


def get_app_sensors(adom, verbose=False):
    '''
    Get a list of all IPS sensors for a given ADOM
    '''
    fm = __forti()
    response = sanitize(fm.get_application_sensors(adom=adom))
    app_sensors = __get_data(response)
    return app_sensors


def get_interfaces(adom, verbose=False):
    '''
    Get a list of all interfaces for a given ADOM
    '''
    fm = __forti()
    response = fm.get_interfaces(adom=adom)
    interfaces = __get_data(response)
    return interfaces


def get_services(adom, verbose=False):
    '''
    Get a list of all services for a given ADOM
    '''
    fm = __forti()
    response = fm.get_services(adom=adom)
    services = __get_data(response)
    return services


def get_schedules(adom, verbose=False):
    '''
    Get a list of all schedules for a given ADOM
    '''
    fm = __forti()
    response = fm.get_schedules(adom=adom)
    schedules = __get_data(response)
    return schedules


def get_vips(adom, verbose=False):
    '''
    Get a list of all virtual IPs defined for a given ADOM
    '''
    if verbose:
        print('Export policies')
        print('Parameters:', adom)

    fm = __forti()
    response = fm.get_firewall_vips(adom=adom)
    vips = __get_data(response)
    return vips


def get_traffic_shapers(adom, verbose=False):
    '''
    Get a list of all traffic shapers defined for a given ADOM
    '''
    if verbose:
        print('Get traffic shapers')
        print('Parameters:', adom)
    fm = __forti()
    response = fm.get_traffic_shapers(adom=adom)
    traffic_shapers = __get_data(response)
    return traffic_shapers


def get_antivirus_profiles(adom, verbose=False):
    '''
    Get a list of all antivirus profiles defined for a given ADOM
    '''
    if verbose:
        print('Get antivirus profiles')
        print('Parameters:', adom)
    fm = __forti()
    response = fm.get_antivirus_profiles(adom=adom)
    antivirus_profiles = __get_data(response)
    return antivirus_profiles


def get_webfilters(adom, verbose=False):
    '''
    Get a list of all web filters defined for a given ADOM
    '''
    if verbose:
        print('Get web filters')
        print('Parameters:', adom)
    fm = __forti()
    response = fm.get_webfilters(adom=adom)
    webfilters = __get_data(response)
    return webfilters


def get_users(adom, verbose=False):
    '''
    Get a list of all antivirus profiles defined for a given ADOM
    '''
    if verbose:
        print('Get users')
        print('Parameters:', adom)
    fm = __forti()
    response = fm.get_users(adom=adom)
    users = __get_data(response)
    return users


def get_groups(adom, verbose=False):
    '''
    Get a list of all antivirus profiles defined for a given ADOM
    '''
    if verbose:
        print('Get user groups')
        print('Parameters:', adom)
    fm = __forti()
    response = fm.json_get_groups(adom=adom)
    groups = __get_data(response)
    return groups


def get_adom_revisions(adom, verbose=False):
    '''
    Get a list of all revisions for a given ADOM
    '''
    if verbose:
        print('Get ADOM revisions')
        print('Parameters:', adom)
    fm = __forti()
    response = fm.get_adom_revision_list(adom=adom)
    revisions = __get_data(response)
    return revisions

def add_policy(adom, policy_type, parameters, verbose=False):
    '''
    Add a new policy
    '''
    if verbose:
        print('Add policy')
        print('Parameters: ', adom, policy_type, parameters)
    fm = __forti()
    new_policy = None
    response = None

    src_intf = parameters.get('incoming_interface', None)
    dst_intf = parameters.get('outgoing_interface', None)
    src_addr = parameters.getlist('source_address')
    dst_addr = parameters.getlist('destination_address')
    service = parameters.getlist('service')
    nat = parameters.get('nat', None)
    logging = parameters.get('logging_options', None)
    log_on_start = parameters.get('log_start_session', None)
    schedule = parameters.get('schedule', None)
    action = parameters.get('action', None)
    tags = parameters.get('tags', None)
    comments = parameters.get('comments', None)

    if src_intf is not None:
        src_intf = models.Interface.objects.get(id=src_intf).name
    if dst_intf is not None:
        dst_intf = models.Interface.objects.get(id=dst_intf).name
    if src_addr is not None:
        # src_addr = models.Address.objects.get(id=src_addr).name
        src_addr_models = models.Address.objects.filter(id__in=src_addr)
        src_addr = [x.name for x in src_addr_models]
    if dst_addr is not None:
        # dst_addr = models.Address.objects.get(id=dst_addr).name
        dst_addr_models = models.Address.objects.filter(id__in=dst_addr)
        dst_addr = [x.name for x in dst_addr_models]
    if service is not None:
        service_models = models.Service.objects.filter(id__in=service)
        service = [x.name for x in service_models]
    if schedule is not None:
        schedule = models.Schedule.objects.get(id=schedule).name
    if action is not None:
        action = 'accept' if action == 'allow' else 'deny'
    if logging is not None:
        if logging == 'none':
            logging = 'disable'
        elif logging == 'all':
            logging = 'all'
        elif logging == 'security':
            logging = 'utm'
    if log_on_start is not None:
        log_on_start = 'enable' if log_on_start == 'on' else 'enable'
    nat = 'enable' if nat is True else 'disable'

    if policy_type == 'address':
        data = [
            {
                "srcintf": src_intf,
                "dstintf": dst_intf,
                "srcaddr": src_addr,
                "dstaddr": dst_addr,
                "service": service,
                "action": action,
                "schedule": schedule,
                "logtraffic": logging,
                "logtraffic-start": log_on_start,
                "nat": nat,
                "tags": tags,
                "comments": comments
                # "identity-based": "enable"
                # "identity-from": "auth"
                # "identity-based-policy": []
            }
        ]
    elif policy_type == 'user':
        pass
    elif policy_type == 'device':
        pass
    elif policy_type == 'ipsec':
        pass
    elif policy_type == 'sslvpn':
        pass
    pol_pkgs = get_policy_pkgs(adom=adom)
    # NOTE: You should consider creating a special policy package that
    # would hold all policies defined using fortictl
    policy_pkg = 'default'
    if pol_pkgs is not None and len(pol_pkgs) > 0:
        policy_pkg = pol_pkgs[0]
    try:
        response = fm.add_policy(
            data=data,
            adom=adom,
            policy_pkg=policy_pkg
        )
        if verbose:
            pprint(response)
        new_policy_id = response['result'][0]['data']['policyid']
        if new_policy_id is not None:
            new_policy = core.tasks.save_policy(
                adom=adom,
                new_policy_id=new_policy_id
            )
            if new_policy is not None:
                code = 0
                message = 'Successfully created policy #{}'.format(new_policy_id)
                if verbose:
                    pprint(data)
                    pprint(response)
                    print('NEW POLICY ID:', new_policy_id)
            else:
                code = -23
                message = 'Failed to retrieve created policy #{}'.format(new_policy_id)
        else:
            code = -13
            message = 'Failed to obtain the new policy id from response {}'.format(response)
    except fortimanager.LockException:
        code = -11
        message = 'Unable to lock ADOM {}'.format(adom)
    except fortimanager.CommitException:
        code = -12
        message = 'Unable to commit changes'
    except:
        code = response['result'][0]['status']['code']
        message = response['result'][0]['status']['message']
    return {
        'result': [{
            'status': {
                'code': code,
                'message': message
            },
            'data': {
                'new_policy': new_policy,
                'response': response
            }
        }]
    }


def add_interface(adom, parameters, verbose=False):
    '''
    Add an interface
    '''
    return add_object(adom, 'interface', parameters, verbose)


def add_object(adom, object_type, parameters, verbose=False):
    '''
    Add an object
    '''
    if verbose:
        print('Add object')
        print('Parameters: ', adom, object_type, parameters)
    fm = __forti()
    new_object = None
    response = None
    if object_type == 'interface':
        name = parameters.get('interface_name', None)
        description = parameters.get('description', None)
        enable_zone = parameters.get('enable_zone', None)
        # dynamic_mapping = parameters.get('dynamic_mapping', None)
        mapped_device = parameters.get('mapped_device', None)
        mapped_interface = parameters.get('mapped_interface', None)
        intrazone_deny = parameters.get('intrazone_deny', None)

        # Get objet names by ID
        if mapped_device is not None:
            mapped_device = models.Device.objects.get(id=mapped_device)
        if mapped_interface is not None:
            mapped_interface = models.Interface.objects.get(id=mapped_interface)
        # Get VDOM name
        # TODO: Exception handling
        vdom_info = eval(mapped_device.vdom)
        vdom = vdom_info[0]['name']
        # Convert true -> 1
        enable_zone = enable_zone == 'true'

        forti_func = fm.add_interface

        data = [{
            'name': name,
            'description': description,
            'single-intf': enable_zone,
            'local-intf': mapped_interface.name,
            'intrazone-deny': intrazone_deny,
            'dynamic_mapping': [
                {
                    'scope': [
                        {
                            'name': mapped_device.name,
                            'vdom': vdom
                        }
                    ]
                }
            ]
        }]
    # Actual API function call
    try:
        response = forti_func(
            data=data,
            adom=adom
        )
        if verbose:
            pprint(response)
        code = response['result'][0]['status']['code']
        message = response['result'][0]['status']['message']
    except fortimanager.LockException:
        code = -11
        message = 'Unable to lock ADOM {}'.format(adom)
    except fortimanager.CommitException:
        code = -12
        message = 'Unable to commit changes'
    except:
        code = response['result'][0]['status']['code']
        message = response['result'][0]['status']['message']
    return {
        'result': [{
            'status': {
                'code': code,
                'message': message
            },
            'data': {
                'new_object': new_object,
                'response': response
            }
        }]
    }


def export_policies(adom, verbose=False):
    adom = models.Adom.objects.get(name=adom)
    book = Workbook()

    # Write policies
    policies = models.Policy.objects.filter(adom=adom)
    sheet = book.add_sheet('{} Policies'.format(adom.name))
    sheet.write(0, 0, '#')
    sheet.write(0, 1, 'Source Interface')
    sheet.write(0, 2, 'Destination Interface')
    sheet.write(0, 3, 'Source')
    sheet.write(0, 4, 'Destination')
    sheet.write(0, 5, 'Schedule')
    sheet.write(0, 6, 'Service')
    sheet.write(0, 7, 'Action')
    sheet.write(0, 8, 'Log')
    sheet.write(0, 9, 'NAT')
    if adom.utm_plus:
        sheet.write(0, 10, 'Profile')
    # sheet.write(0, 12, 'Comments')

    for index, p in enumerate(policies):
        sheet.write(index + 1, 0, p.obj_seq)
        sheet.write(index + 1, 1, p.srcintf.name if p.srcintf else 'None')
        sheet.write(index + 1, 2, p.dstintf.name if p.dstintf else 'None')
        sheet.write(
            index + 1,
            3,
            ','.join([x.name for x in p.srcaddr.all()]) if p.srcaddr else 'None'
        )
        sheet.write(
            index + 1,
            4,
            ','.join([x.name for x in p.dstaddr.all()]) if p.dstaddr else 'None'
        )
        sheet.write(index + 1, 5, p.schedule.name if p.schedule else 'None')
        sheet.write(
            index + 1,
            6,
            ','.join([x.name for x in p.service.all()]) if p.service else 'None'
        )
        if p.action == '0':
            action = 'Deny'
        elif p.action == '1':
            action = 'Allow'
        elif p.action == '2':
            action = 'IPsec'
        elif p.action == '3':
            action = 'SSL VPN'
        else:
            action = p.action
        sheet.write(index + 1, 7, action)
        if p.logtraffic == '3':
            log = 'Security related events only'
        elif p.logtraffic == '2':
            log = 'Log all'
        elif p.logtraffic == '0':
            log = 'Logging disabled'
        else:
            log = p.logtraffic
        sheet.write(index + 1, 8, log)
        if p.nat == '1':
            nat = 'true'
        elif p.nat == '0':
            nat = 'false'
        else:
            nat = p.nat
        sheet.write(index + 1, 9, nat)
        if adom.utm_plus:
            profile = ''
            if p.ips_sensor is not None and p.ips_sensor != '':
                profile += 'IPS: {}'.format(p.ips_sensor)
            if (p.deep_inspection_options is not None and
                    p.deep_inspection_options != ''):
                profile += 'Deep Inspection: {}'.format(p.deep_inspection_options)
            if (p.profile_protocol_options is not None and
                    p.profile_protocol_options != ''):
                profile += 'Profile Protocol Options: {}'.format(
                    p.profile_protocol_options)
            sheet.write(index + 1, 10, profile)
        # sheet.write(index + 1, 11, p.comments)

    # Write objects
    # Write addresses
    sheet = book.add_sheet('Addresses'.format(adom.name))
    addresses = models.Address.objects.filter(adom=adom)
    sheet.write(0, 0, 'Name')
    sheet.write(0, 1, 'Type')
    sheet.write(0, 2, 'Associated Interface')
    sheet.write(0, 3, 'FQDN')
    sheet.write(0, 4, 'Subnet')
    sheet.write(0, 5, 'Member')
    sheet.write(0, 6, 'Comment')

    for index, a in enumerate(addresses):
        sheet.write(index + 1, 0, a.name)
        sheet.write(index + 1, 1, a.type)
        sheet.write(index + 1, 2, a.associated_interface)
        sheet.write(index + 1, 3, a.fqdn)
        sheet.write(index + 1, 4, a.subnet)
        sheet.write(index + 1, 5, a.member)
        sheet.write(index + 1, 6, a.comment)

    # Write interfaces
    sheet = book.add_sheet('Interfaces'.format(adom.name))
    interfaces = models.Interface.objects.filter(adom=adom)
    sheet.write(0, 0, 'Name')
    sheet.write(0, 1, 'Description')
    sheet.write(0, 2, 'Device')
    sheet.write(0, 3, 'VDOM')
    sheet.write(0, 4, 'Local Interface')
    sheet.write(0, 5, 'Deny Intrazone traffic')
    sheet.write(0, 6, 'Single Interface')

    for index, i in enumerate(interfaces):
        sheet.write(index + 1, 0, i.name)
        sheet.write(index + 1, 1, i.description)
        if i.dynamic_mapping is not None and i.dynamic_mapping != '':
            try:
                from pprint import pprint
                pprint(i.dynamic_mapping)
                print('DM')
                dm = eval(i.dynamic_mapping)[0]
                pprint(dm)
                sheet.write(index + 1, 2, dm['scope'][0]['name'])
                sheet.write(index + 1, 3, dm['scope'][0]['vdom'])
                sheet.write(index + 1, 4, dm['local_intf'])
                sheet.write(index + 1, 5, 'true' if dm['intrazone_deny'] == 1 else 'false')
            except Exception as e:
                print(e)
        sheet.write(index + 1, 6, 'true' if i.single_intf == '1' else 'false')

    # Schedules
    sheet = book.add_sheet('Schedules'.format(adom.name))
    schedules = models.Schedule.objects.filter(adom=adom)
    sheet.write(0, 0, 'Name')
    sheet.write(0, 1, 'Day')
    sheet.write(0, 2, 'Start')
    sheet.write(0, 3, 'End')

    for index, s in enumerate(schedules):
        sheet.write(index + 1, 0, s.name)
        sheet.write(index + 1, 1, s.day)
        sheet.write(index + 1, 2, s.start)
        sheet.write(index + 1, 3, s.end)

    # Services
    sheet = book.add_sheet('Services'.format(adom.name))
    services = models.Service.objects.filter(adom=adom)
    sheet.write(0, 0, 'Name')
    sheet.write(0, 1, 'Category')
    sheet.write(0, 2, 'FQDN')
    sheet.write(0, 3, 'IP range')
    sheet.write(0, 4, 'Protocol')
    sheet.write(0, 5, 'TCP Portrange')
    sheet.write(0, 6, 'UDP Portrange')

    for index, s in enumerate(services):
        sheet.write(index + 1, 0, s.name)
        sheet.write(index + 1, 1, s.category)
        sheet.write(index + 1, 2, s.fqdn)
        sheet.write(index + 1, 3, s.iprange)
        if s.protocol == '2':
            protocol = 'IP'
        elif s.protocol == '5':
            protocol = 'TCP/UDP/SCTP'
        else:
            protocol = s.protocol
        sheet.write(index + 1, 4, protocol)
        sheet.write(index + 1, 5, s.tcp_portrange)
        sheet.write(index + 1, 6, s.udp_portrange)

    tmpfile = NamedTemporaryFile()
    book.save(tmpfile.name)
    return tmpfile
