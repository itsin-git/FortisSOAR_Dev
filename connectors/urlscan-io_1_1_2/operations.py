""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import validators, requests, json
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('urlscan.io')

error_msgs = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Invalid credentials',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error',
    503: 'Service Unavailable'
}
MACRO_LIST = ["URL_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "urlscan-io"


class URLScan:
    def __init__(self, config):
        self.base_url = config.get('server').strip()
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://' + self.base_url
        self.api_key = config['api_key']
        self.verify_ssl = config['verify_ssl']
        self.headers = {'API-Key': self.api_key}

    def make_rest_call(self, endpoint, headers=None, params=None, data=None, method='GET'):
        headers = headers if headers else self.headers
        url = '{0}{1}'.format(self.base_url, endpoint)
        logger.info('Request URL {0}'.format(url))
        try:
            response = requests.request(method, url, json=data, headers=headers, verify=self.verify_ssl, params=params)
            if response.ok:
                return json.loads(response.content.decode('utf-8'))
            else:
                json_data = response.json()
                if json_data:
                    error_msg = response.json().get('message')
                    logger.error('{0}'.format(error_msg))
                    raise ConnectorError('{0}'.format(error_msg))
                elif error_msgs.get(response.status_code):
                    raise ConnectorError('{0}:'.format(error_msgs.get(response.status_code)))
                else:
                    raise ConnectorError('{0}:'.format(response.text))
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))


def _check_health(config):
    url_scan = URLScan(config)
    try:
        response = url_scan.make_rest_call('/user/quotas/', headers=url_scan.headers, method='GET')
        if response:
            logger.info('connector available')
            return True
    except Exception as e:
        raise ConnectorError('{0}'.format(e))


def get_report(config, param):
    url_scan = URLScan(config)
    return url_scan.make_rest_call('/api/v1/result/' + param['scan_id'])


def search_domain(config, params):
    url_scan = URLScan(config)
    domain = params.get('domain')
    size = params.get('size')
    params = {'q': 'domain:{}'.format(domain)}
    if size:
        params.update({'size': size})
    if validators.domain(domain):
        return url_scan.make_rest_call('/api/v1/search/', params=params)
    else:
        raise ConnectorError('Invalid domain {0}'.format(domain))


def search_ip(config, params):
    url_scan = URLScan(config)
    ip = params.get('ip')
    size = params.get('size')
    params = {'q': 'ip:{}'.format(ip)}
    if size:
        params.update({'size': size})
    if validators.ipv4(ip):
        return url_scan.make_rest_call('/api/v1/search/', params=params)
    else:
        raise ConnectorError('Invalid IP {0}'.format(ip))


def submit_url(config, param):
    url_to_scan = param['url']
    url_scan = URLScan(config)
    private = param.get('private', True)
    url_scan.headers['Content-Type'] = 'application/json'
    data = {'url': url_to_scan, 'public': 'off' if private else 'on'}
    if validators.url(url_to_scan):
        return url_scan.make_rest_call('/api/v1/scan/', headers=url_scan.headers, data=data, method='POST')
    else:
        raise ConnectorError('Invalid URL {0}'.format(url_to_scan))


def search_hash(config, params):
    url_scan = URLScan(config)
    hash_val = params.get('hash')
    size = params.get('size')
    params = {'q': 'hash:{}'.format(hash_val)}
    if size:
        params.update({'size': size})
    return url_scan.make_rest_call('/api/v1/search/', params=params)


def custom_search(config, params):
    query = params.get('query')
    size = params.get('size')
    url_scan = URLScan(config)
    params = {'q': query}
    if size:
        params.update({'size': size})
    return url_scan.make_rest_call('/api/v1/search/', params=params)


operations = {
    'get_report': get_report,
    'search_domain': search_domain,
    'search_ip': search_ip,
    'search_hash': search_hash,
    'custom_search': custom_search,
    'submit_url': submit_url
}
