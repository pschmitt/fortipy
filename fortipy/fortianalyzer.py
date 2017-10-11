'''
FortiAnalyzer
Author: Philipp Schmitt <philipp.schmitt@post.lu>
URLs: https://fndn.fortinet.net/index.php?/topic/52-an-incomplete-list-of-url-parameters-for-use-with-the-json-api/
'''

from __future__ import absolute_import
from __future__ import print_function
from .forti import Forti
import ssl
from suds.client import Client


# Disable SSL verification for suds
ssl._create_default_https_context = ssl._create_unverified_context


class FortiAnalyzer(Forti):
    def _run(self, url, data, request_id):
        return self._request(
            method='run',
            data=data,
            url=url,
            request_id=request_id
        )

    def _fetch(self, url, data, request_id):
        return self._request(
            method='fetch',
            data=data,
            url=url,
            request_id=request_id
        )

    def _cancel(self, url, data, request_id):
        return self._request(
            method='cancel',
            data=data,
            url=url,
            request_id=request_id
        )

    def fetch_result(self, adom, count, period=None, filters=None,
                     filter_logic='all', devices=None, interim_result=False,
                     logtype='content', compact_result=False, sort=None):
        data = {
            'adom': adom,
            'count': count
        }
        return self._fetch(
            data=data,
            url='faz/fortiview',
            request_id=3321
        )

    def import_report_config(self):
        return self._add(
            url='/faz/report/report_config'
        )

    def xml_fetch_report():
        client = Client('https://192.168.10.130:8080/')
