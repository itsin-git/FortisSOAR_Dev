""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import validators, requests, json
import base64
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('whois-freaks')


class whoisFreaks(object):
    def __init__(self, config, *args, **kwargs):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('api_key')
        self.sslVerify = config.get('verify')

    def make_api_call(self, endpoint=None, method='GET', data=None, params=None):
        try:
            endpoint = self.server_url + endpoint
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json',
                       "Authorization": "Token {}".format(self.api_key)}
            response = requests.request(method, endpoint, params=params, headers=headers,
                                        verify=self.sslVerify, data=json.dumps(data))
            if response.ok:
                logger.info('Successfully got response for url {}'.format(endpoint))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            elif response.status_code == 404:
                return response.text
            else:
                logger.error(response.content)
                raise ConnectorError(
                    {'status_code': response.status_code, 'message': response.content})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def get_params(params):
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def whois_lookup(config, params):
    try:
        wf = whoisFreaks(config)
        params['whois'] = params.get('whois', '').lower()
        if params.get('whois') == 'reverse':
            if params.get('mode'):
                params['mode'] = params.get('mode', '').lower()
            if params.get('keyword') is None and params.get('email') is None and params.get(
                    'owner') is None and params.get(
                    'company') is None:
                raise Exception("At least one parameter is required from \"Keyword\", \"Email Address\", \"Owner\" or "
                                "\"Company\"")
        params.update({'apiKey': config.get('api_key'), 'format': 'JSON'})
        params = get_params(params)
        return wf.make_api_call(endpoint='v1.0/whois', params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def dns_lookup(config, params):
    try:
        wf = whoisFreaks(config)
        lookup = ''.join(params.get('type')).replace("[", "").replace("]", "").replace("'", "").replace(" ", "")
        endpoint = 'v1.0/dns/live?apiKey={}&domainName={}&format=JSON&type={}'.format(config.get('api_key'),
                                                                                      params.get('domainName'), lookup)
        return wf.make_api_call(endpoint)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def ssl_certificates(config, params):
    try:
        wf = whoisFreaks(config)
        params.update({'apiKey': config.get('api_key'), 'format': 'JSON'})
        params = get_params(params)
        return wf.make_api_call(endpoint='v1.0/ssl/live', params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def _check_health(config):
    try:
        return whois_lookup(config=config,
                            params={'domainName': 'google.com', 'whois': 'live', 'keyword': 'google.com'})
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    'whois_lookup': whois_lookup,
    'ssl_certificates': ssl_certificates,
    'dns_lookup': dns_lookup
}
