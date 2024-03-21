""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import validators, requests, json
import base64
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('censys')


class Censys(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_id = config.get('api_id')
        self.api_secret = config.get('api_secret')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, endpoint=None, method='GET', data=None, params=None):
        try:
            url = self.server_url + endpoint
            b64_credential = base64.b64encode((self.api_id + ":" + self.api_secret).encode('utf-8')).decode()
            headers = {'Authorization': "Basic " + b64_credential, 'Accept': 'application/json'}
            response = requests.request(method, url, params=params, data=data, headers=headers, verify=self.verify_ssl)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_params(params):
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def get_host_details(config, params):
    try:
        csys = Censys(config)
        if params.get('at_time'):
            params['at_time'] = params.get('at_time').replace('T', ' ')
        params = get_params(params)
        return csys.make_api_call(endpoint='api/v2/hosts/{0}'.format(params.get('ip')), params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def search_hosts(config, params):
    try:
        csys = Censys(config)
        params = get_params(params)
        return csys.make_api_call(endpoint='api/v2/hosts/search', params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def lookup_certificate(config, params):
    try:
        csys = Censys(config)
        return csys.make_api_call(endpoint='api/v2/certificates/{0}'.format(params.get('fingerprint')),
                                  params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def _check_health(config):
    try:
        return get_host_details(config, params={'ip': '8.8.8.8'})
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_host_details': get_host_details,
    'search_hosts': search_hosts,
    'lookup_certificate': lookup_certificate
}
