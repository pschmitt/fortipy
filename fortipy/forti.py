'''
Forti
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


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# How long a token should be considered valid (in minutes)
TOKEN_TIMEOUT = 2


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
        if self._token_age:
            timediff = self._token_age - datetime.datetime.now()
            if timediff.total_seconds() / 60 > TOKEN_TIMEOUT:
                logger.info('Token timeout has been reached. Let\'s login again')
                self.logout()  # Log out to invalidate previous token
                self.login()  # Request new token
        else:
            self.login()
        return f(self, *args, **kwargs)
    return _wrapper


class Forti(object):
    '''
    Forti class (JSON API)
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

    def _request(self, method, url, option=None, data=None, request_id=1,
                 verbose=False):
        '''
        Perform a JSON request
        :param method: Method to use (get/set/delete etc.)
        :param url: Internal URL
        :param data: Data of the request
        '''
        try:
            post_data = json.dumps({
                'method': method,
                'params': [{'url': url, 'data': data, 'option': option}],
                'id': request_id,
                'session': self.token,
                'verbose': verbose,
                'jsonrpc': '2.0',
                'session': self.token if self.token else 1
                # 'skip': skip
            })
            logger.debug('POST DATA: {}'.format(post_data))
            # Set verify to True to verify SSL certificates
            r = requests.post(self.json_url, post_data, verify=self.verify)
            if not r.ok:
                logger.error('Erroneous response')
                r.raise_for_status()
            logger.debug(r.text)
            res =  r.json()
            assert res['id'] == request_id, 'Request ID changed.'
            return res
        except requests.exceptions.SSLError as e:
            logger.error(
                'SSL Handshake failed: {}\n'
                'You may want to disable SSL cert verification '
                '[!!!INSECURE!!!]'.format(e)
            )
            raise e

    @login_required
    def _syntax(self, url, request_id=1):
        return self._request(
            method='get',
            option='syntax',
            url=url,
            request_id=request_id
        )

    @login_required
    def _get(self, url, request_id=11, option=None, data=None, verbose=False, skip=False):
        '''
        Generic "get" function
        '''
        res = self._request(
            method='get',
            url=url,
            data=data,
            option=option,
            request_id=request_id,
            verbose=verbose
        )
        logger.debug(res)
        # assert len(res['result']) == 1, 'More than one result has been returned'
        if len(res['result']) > 1:
            logger.warning('More than one result has been returned')
        if 'data' in res['result']:
            if len(res['result']['data']) > 0 and type(res['result']['data']) is list:
                if res['result'][0]['data']:
                    return [x for x in res['result'][0]['data']]
        return res['result']['data']

    @login_required
    def _add(self, url, data, request_id=12, verbose=False):
        '''
        Generic "add" function
        '''
        return self._request(
            method='add',
            url=url,
            request_id=request_id,
            data=data,
            verbose=verbose
        )

    @login_required
    def _set(self, url, data, request_id=14, verbose=False):
        '''
        Generic "set" method
        '''
        return self._request(
            method='set',
            url=url,
            request_id=request_id,
            data=data,
            verbose=verbose
        )

    @login_required
    def _delete(self, url, data, request_id=13, verbose=False):
        '''
        Generic "delete" function
        '''
        return self._request(
            method='delete',
            url=url,
            request_id=request_id,
            data=data,
            verbose=verbose
        )

    def _exec(self, url, data=None, request_id=11, verbose=False, skip=False):
        '''
        Generic "exec" function
        '''
        return self._request(
            method='exec',
            url=url,
            request_id=request_id,
            data=data,
            verbose=verbose
        )

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
        res = self._exec(url, data)
        assert res, 'No data received'
        if 'session' in res:
            self.token = res['session']
            # Automatically log out at program exit
            atexit.register(self.logout)
            self._token_age = datetime.datetime.now()
            return self.token
        else:
            logger.error('Login failed: {}'.format(res))

    @login_required
    def logout(self):
        '''
        Log out, invalidate the session token
        '''
        logger.debug('LOGOUT REQUEST')
        self.token = None
        return self._exec(url='sys/logout', request_id=3)

