"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import requests, base64, json
from .utils import *
from requests_toolbelt.utils import dump


class FortiSIEM:
    def __init__(self, config):
        self.base_url = config.get('server').strip('/') + '/phoenix'
        if not self.base_url.startswith('https://') and not self.base_url.startswith('http://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.organization = str(config['organization'])
        self.user = str(config['username'])
        self.username = self.organization + '/' + self.user
        self.password = str(config['password'])
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

    def get_headers(self, headers, resource_flag):
        if headers is None:
            if resource_flag:
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Cookie": f"JSESSIONID={self.cookies_dict.get('JSESSIONID')}; s={self.cookies_dict.get('s')}"
                }
            else:
                headers = self.generate_headers()
        return headers

    def make_json_rest_call(self, endpoint, params=None, headers=None, json_data=None, data=None, cookies=None,
                       method='GET', files=None, login_flag=False, resource_flag=False):
        #Instead of having a rest call with mixed data types (xml vs json, use this one for all json apis
        url = '{0}{1}'.format(self.base_url, endpoint)
        try:
            headers = self.get_headers(headers, resource_flag)
            logger.debug(f"\n----------------req start----------------\n{method} {url} \nparams: {params} \ndata: {data} \nheaders: {headers}\n")
            response = requests.request(method,
                                        url,
                                        data=data,
                                        headers=headers,
                                        verify=self.verify_ssl,
                                        params=params,
                                        files=files
                                        )

            logger.debug(f"\nres_status:{response.status_code} response: {response.json()} \n----------------req end----------------\n")

            if response.ok:
                logger.info('FortiSIEM successfully retrieved page: {0}'.format(response.url))
                return response.status_code, response.json()
            elif response.status_code in [400, 404, 429, 503]:
                #404 may mean FSM has not populated paginated cache yet
                #503 means server is not ready for next page
                #Both indicate we should wait for some time before trying next page
                logger.error('Status Code: {0}, Query URL: {1} Response Data: {2}'.format(response.status_code, response.url, response.json()))
                logger.error('FortiSIEM may sometimes return a 404 in older versions, in place of a 429 or 503, indicating that more time is needed for the server to be ready to serve more pages. Connector will retry the page after a short wait')
                return response.status_code, response.json()
            else:
                logger.error('{0}'.format(response.content))
                raise ConnectorError('status code: {0}, error: {1}'.format(response.status_code, response.json()))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


    def make_rest_call(self, endpoint, params=None, headers=None, json_data=None, data=None, cookies=None,
                       method='GET', files=None, login_flag=False, resource_flag=False):

        url = '{0}{1}'.format(self.base_url, endpoint)
        try:
            headers = self.get_headers(headers, resource_flag)
            logger.debug(f"\n----------------req start----------------\n{method} {url} \nparams: {params} \ndata: {data} \nheaders: {headers}\n")
            response = requests.request(method,
                                        url,
                                        data=data,
                                        headers=headers,
                                        verify=self.verify_ssl,
                                        params=params,
                                        files=files
                                        )

            response_content = response.content.decode('utf-8')
            logger.debug(f"\nres_status:{response.status_code} response: {response_content} \n----------------req end----------------\n")
            if 'error code="255"' in response_content:
                # if invalid input: response comes out to be 200, with error code 255
                json_resp = xmltodict.parse(response_content)
                # error_msg can come at any of the 2 locations, so checking here with or condition
                error_msg = json_resp.get("response", {}).get("error", {}).get("description") or \
                            json_resp.get("response", {}).get("result", {}).get("error", {}).get("description")
                logger.error(error_msg)
                raise ConnectorError('Error : {0}'.format(error_msg))
            elif response.ok:
                if login_flag:
                    self.cookies_dict = response.cookies.get_dict()
                    return response_content, response.cookies
                elif 'json' in response.headers.get('Content-Type'):
                    try:
                        resp = response.json()
                    except Exception:
                        resp = response_content
                    return resp
                elif response.text == "":
                    return response
                return response_content
            elif response.status_code == 400 and 'json' in response.headers.get('Content-Type'):
                logger.error('{0}'.format(response.json()))
                raise ConnectorError(response.json())
            elif response.status_code in [404, 503]:
                #404 may mean FSM has not populated paginated cache yet
                #503 means server is not ready for next page
                #Both indicate we should wait for some time before trying next page
                logger.error('{0}'.format(response.json()))
                return response.json()
            elif response.status_code == 500:
                logger.error('{0}'.format(response.content))
                raise ConnectorError('{0}'.format(self.error_msg[response.status_code]))
            elif self.error_msg.get(response.status_code, None):
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
