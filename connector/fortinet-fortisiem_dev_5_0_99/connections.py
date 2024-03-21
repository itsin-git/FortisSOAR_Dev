""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, base64
from .utils import *
from requests_toolbelt.utils import dump


class FortiSIEM:
    def __init__(self, config):
        self.base_url = config.get('server').strip('/') + '/phoenix'
        if not self.base_url.startswith('https://') and not self.base_url.startswith('http://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.organization = config['organization']
        self.user = config['username']
        self.username = self.organization + '/' + self.user
        self.password = config['password']
        self.verify_ssl = config['verify_ssl']
        self.cookies_dict = {}

        self.error_msg = {
            400: 'The parameters are invalid.',
            401: 'Invalid credentials were provided Or Request Not authorized',
            403: 'Access Denied',
            404: 'The requested resource was not found',
            422: 'Parameters are missing in query/request body.',
            423: 'The parameters are invalid in path/query/request body.',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'}

    def make_rest_call(self, endpoint, params=None, headers=None, json_data=None, data=None, cookies=None,
                       method='GET', files=None, login_flag=False, resource_flag=False):

        url = '{0}{1}'.format(self.base_url, endpoint)
        logger.info('Requesting URL {0}'.format(url))
        logger.debug('params ={}'.format(data))
        try:
            if headers is None and resource_flag:
                headers = {
                    'Accept': 'application/json, text/plain, */*',
                    'Content-Type': 'application/json;charset=UTF-8'
                }
                headers.update({"Cookie": "JSESSIONID={}; s={}".format(self.cookies_dict.get('JSESSIONID'),
                                                                       self.cookies_dict.get('s'))})
            if headers is None:
                headers = self.generate_headers()

            response = requests.request(method,
                                        url,
                                        data=data,
                                        headers=headers,
                                        verify=self.verify_ssl,
                                        params=params,
                                        files=files
                                        )
            logger.debug('\n{}\n'.format(dump.dump_all(response).decode('utf-8')))

            if 'error code="255"' in response.content.decode('utf-8'):
                # if invalid input: response comes out to be 200, with error code 255
                json_resp = xmltodict.parse(response.content.decode('utf-8'))
                # error_msg can come at any of the 2 locations, so checking here with or condition
                error_msg = json_resp.get("response", {}).get("error", {}).get("description") or \
                            json_resp.get("response", {}).get("result", {}).get("error", {}).get("description")
                logger.error(error_msg)
                raise ConnectorError('Error : {0}'.format(error_msg))
            if response.ok:
                if response.text == "":
                    return response
                if login_flag:
                    self.cookies_dict = response.cookies.get_dict()
                    return response.content.decode('utf-8'), response.cookies
                if 'json' in response.headers.get('Content-Type'):
                    return response.json()
                return response.content.decode('utf-8')
            if response.status_code == 500:
                logger.error('{0}'.format(response.content))
                raise ConnectorError('{0}'.format(self.error_msg[response.status_code]))
            if self.error_msg.get(response.status_code, None):
                logger.error('{0}'.format(response.content))
                raise ConnectorError(
                    'status code: {0}, error: {1}'.format(response.status_code, self.error_msg[response.status_code]))
            raise ConnectorError('status code: {0}, error: {1}'.format(response.status_code, response.content))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['time_out']))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))

    def generate_headers(self):
        try:
            auth = base64.b64encode((self.username + ":" + self.password).encode())
            return {'Authorization': 'Basic {0}'.format(auth.decode())}
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
