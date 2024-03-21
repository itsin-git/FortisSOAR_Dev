"""
Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import requests
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('nist-nvd')


class NistNvd(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, endpoint=None, method='GET', data=None, params=None):
        try:
            url = self.server_url + endpoint
            headers = {'apiKey': self.api_key}
            response = requests.request(method, url, params=params, data=data, headers=headers, verify=self.verify_ssl)

            if response.status_code == 200:
                return response
            else:
                logger.error(response.text)
                error_msg = response.headers.get('message', response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': error_msg})
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


def build_query_params(params):
    payload = {'resultsPerPage': 10}

    for key in params.keys():
        if key in SEARCH_FLAG_LIST:
            if params.get(key):
                payload[key] = ''
        elif key in EXCLUDE_LIST or len(str(params.get(key))) == 0:
            if key == 'useSearchFlags' and len(params.get(key)) > 0:
                for item in params.get(key):
                    payload[SEARCH_FLAG_DICT.get(item)] = ''
            else:
                pass
        elif key == 'keywordSearch':
            keywords = params.get(key)
            if isinstance(keywords, list):
                payload[key] = ' '.join([x.strip() for x in keywords])
            elif isinstance(keywords, str):
                payload[key] = ' '.join([x.strip() for x in keywords.split(",")])
        else:
            payload[key] = params.get(key)
    return payload
