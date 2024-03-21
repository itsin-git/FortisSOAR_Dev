"""
Copyright start
Copyright (C) 2008 - 2022 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import requests
from urllib.parse import quote, urlencode
from connectors.core.connector import get_logger, ConnectorError

MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs", "URL_Enrichment_Playbooks_IRIs", "Email_Enrichment_Playbooks_IRIs"]
logger = get_logger('ip-quality-score')
CONNECTOR_NAME = "ip-quality-score"


class IPQualityScore(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint=None, method='GET', data=None, params=None, files=None):
        try:
            url = self.server_url + endpoint
            headers = {'Content-Type': 'application/json'}
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
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


def get_ip_reputation(config, params):
    ip_qs = IPQualityScore(config)
    query_params = {k: v for k, v in params.items() if v is not None and v != ''}
    del query_params['ip_address']
    endpoint = 'api/json/ip/{0}/{1}'.format(config.get('password'), params.get('ip_address'))
    return ip_qs.make_request(endpoint=endpoint, params=query_params)


def get_email_reputation(config, params):
    ip_qs = IPQualityScore(config)
    query_params = {k: v for k, v in params.items() if v is not None and v != ''}
    endpoint = 'api/json/email/{0}/{1}'.format(config.get('password'), params.get('email_address'))
    del query_params['email_address']
    return ip_qs.make_request(endpoint=endpoint, params=query_params)


def get_url_reputation(config, params):
    ip_qs = IPQualityScore(config)
    query_params = {k: v for k, v in params.items() if v is not None and v != ''}
    endpoint = 'api/json/url/{0}/{1}'.format(config.get('password'), quote(params.get('url'), safe=''))
    del query_params['url']
    return ip_qs.make_request(endpoint=endpoint, params=query_params)


def _check_health(config):
    try:
        params = {'ip_address': '8.8.8.8'}
        res = get_ip_reputation(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_ip_reputation': get_ip_reputation,
    'get_email_reputation': get_email_reputation,
    'get_url_reputation': get_url_reputation
}
