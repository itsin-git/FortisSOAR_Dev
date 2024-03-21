""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
  
import json
import requests
from connectors.core.connector import get_logger, ConnectorError
MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs", "Domain_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "ipstack"
logger = get_logger('ipstack')


class IPStack:
    def __init__(self, config):
        self.base_url = config.get('server_url').strip('/')
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')
        if not any([self.base_url.startswith('https://'), self.base_url.startswith('http://')]):
            self.base_url = '{protocol}://{base_url}'.format(protocol=config.get('protocol').lower(),
                                                             base_url=self.base_url)
        self.error_msg = {
            404: 'The requested resource does not exist',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'
        }

    def make_rest_call(self, endpoint, params={}):
        try:
            request_url = '{0}/{1}'.format(self.base_url, endpoint)
            params['access_key'] = self.api_key
            response = requests.get(request_url, params=params, verify=self.verify_ssl)
            if response.ok:
                return json.loads(response.content.decode('utf-8'))
            if self.error_msg[response.status_code]:
                raise ConnectorError(self.error_msg[response.status_code])
            response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
            raise ConnectorError(self.error_msg['time_out'])
        except Exception as e:
            raise ConnectorError(e)


def _output(response):
    if response.get('success', '') is not '':
        raise ConnectorError(response['error']['info'])
    return response if isinstance(response, list) else [response]


def _request_params(params):
    request_params = {}
    endpoint = ','.join(params['query']) if isinstance(params['query'], list) else params['query']
    request_params['fields'] = ','.join(params['fields']) if isinstance(params['fields'], list) else params['fields']
    if params['enable_hostname']:
        request_params['hostname'] = 1
    if params['enable_security']:
        request_params['security'] = 1
    return endpoint, request_params


def ip_locate(config, params):
    geo_loc = IPStack(config)
    endpoint, request_params = _request_params(params)
    try:
        json_resp = geo_loc.make_rest_call(endpoint, params=request_params)
        return _output(json_resp)
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)


def _check_health(config):
    geo_loc = IPStack(config)
    endpoint = '/check'
    try:
        json_resp = geo_loc.make_rest_call(endpoint)
        if json_resp.get('success', '') is not '':
            raise ConnectorError(json_resp['error']['info'])
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)

functions = {
    'domain_locate': ip_locate,
    'ip_locate': ip_locate
}
