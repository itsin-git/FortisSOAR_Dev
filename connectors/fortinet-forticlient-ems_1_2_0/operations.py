"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

import requests
import json
from connectors.core.connector import ConnectorError, get_logger
from .constant import *

logger = get_logger('fortinet-forticlient-ems')


class FortiClientEMS:
    def __init__(self, config):
        self.base_url = config.get('server').strip('/') + '/api/v1'
        if not self.base_url.startswith('https://') and not self.base_url.startswith('http://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.domain = config.get('domain')
        self.username = config['username']
        self.password = config['password']
        self.verify_ssl = config['verify_ssl']
        self.cookie_str = ''
        self.CSRFToken = ''

        self.error_msg = {
            400: 'The parameters are invalid.',
            401: 'Invalid Credentials',
            403: 'Access Denied',
            404: 'The requested resource was not found',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'}

    def make_rest_call(self, endpoint, params=None, headers={}, data=None, method='GET', login_flag=False,
                       logout_flag=False, json=None):
        """
        :param str endpoint:
        :param dict params: Query parameters for provided endpoint
        :param dict headers: Authenticate to FortiSIEM server
        :param dict json_data: Request payload send to FortiSIEM server
        :param str data:
        :param str method: HTTP method
        :return: tuple i.e: return two objects (actual response and the cookie)
        """

        url = '{0}{1}'.format(self.base_url, endpoint)
        logger.info('Requesting URL {0}'.format(url))
        try:
            if not login_flag:
                headers.update({
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'referer': self.base_url.replace('api/v1', ''),
                    'cookie': self.cookie_str,
                    "X-CSRFToken": self.CSRFToken,
                })
            else:
                headers = {'Content-Type': 'application/json',
                           'Accept': 'application/json'}
            logger.debug(f"\n---------req-----------\n{method} {url}\ndata - {data}\njson - {json}\nparams - {params}")
            try:
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, url, headers=headers, params=params, data=data, verify_ssl=self.verify_ssl)
            except Exception:
                pass

            response = requests.request(method,
                                        url,
                                        data=data,
                                        headers=headers,
                                        verify=self.verify_ssl,
                                        params=params,
                                        json=json)
            if response.ok:
                if login_flag:
                    return response
                if logout_flag:
                    return response
                if 'json' in response.headers.get('Content-Type'):
                    return response.json()
                else:
                    return json.loads(response.content.decode('utf-8'))
            else:
                if 'text/html' in response.headers.get('Content-Type'):
                    raise ConnectorError(response.content.decode('utf-8'))
                raise ConnectorError(response.content.decode('utf-8'))
        except requests.exceptions.SSLError as e:
            raise ConnectorError('{0}'.format(self.error_msg['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['time_out']))
        except Exception as e:
            raise ConnectorError('{0}'.format(e))

    def logout(self):
        try:
            res = self.make_rest_call('/auth/signout', logout_flag=True)
            logger.info('successfully logout session res is {}'.format(res))
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def login(self):
        try:
            body = {
                "name": self.username,
                "password": self.password
            }
            response = self.make_rest_call('/auth/signin', method='POST', data=json.dumps(body), login_flag=True)
            cookies = response.cookies.items()
            if len(cookies) == 2:
                self.cookie_str = '{}={};{}={}'.format(cookies[0][0], cookies[0][1], cookies[1][0], cookies[1][1])
                if str(cookies[0][0]) == 'csrftoken':
                    self.CSRFToken = cookies[0][1]
                elif str(cookies[1][0]) == 'csrftoken':
                    self.CSRFToken = cookies[1][1]
            else:
                raise ConnectionError('Login failed, Invalid username or password given')
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)


def str_to_list(input_str):
    if isinstance(input_str, str) and len(input_str) > 0:
        return [(x.strip()) for x in input_str.split(',')]
    elif isinstance(input_str, list):
        return input_str
    elif isinstance(input_str, int):
        return [(input_str)]
    else:
        return []


def check_payload(payload):
    if not payload:
        return {}
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value == 0 or value is False or value:
            updated_payload[key] = value
    return updated_payload


def quarantine_endpoints(config, params):
    try:
        ems_obj = FortiClientEMS(config)
        ems_obj.login()
        body = {
            'ids': str_to_list(params.get('ids')),
        }
        res = ems_obj.make_rest_call('/clients/quarantine', data=json.dumps(body), method='POST')
        ems_obj.logout()
        return res
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def unquarantine_endpoints(config, params):
    try:
        ems_obj = FortiClientEMS(config)
        ems_obj.login()
        body = {
            "ids": str_to_list(params.get('ids')),
        }
        res = ems_obj.make_rest_call('/clients/unquarantine', data=json.dumps(body), method='POST')
        ems_obj.logout()
        return res
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_endpoints(config, params):
    try:
        ems_obj = FortiClientEMS(config)
        ems_obj.login()
        if params.get('activity'):
            params.update({'activity': ACTIVITY.get(params.get('activity'))})
        if params.get('connection'):
            params.update({'connection': CONNECTION.get(params.get('connection'))})
        if params.get('event_type'):
            params.update({'event_type': EVENT_TYPE.get(params.get('event_type'))})
        if params.get('management'):
            params.update({'management': MANAGEMENT.get(params.get('management'))})
        if params.get('status'):
            params.update({'status': STATUS.get(params.get('status'))})
        if params.get('view_type'):
            params.update({'view_type': VIEW_TYPE.get(params.get('view_type'))})
        filters = check_payload(params.get('filters'))
        if filters:
            params.update({'filters': json.dumps(filters)})
        verification = check_payload(params.get('verification'))
        if verification:
            params.update({'verification': json.dumps(verification)})
        if params.get('custom_attributes'):
            params.update(params.pop('custom_attributes'))
        data = check_payload(params)
        res = ems_obj.make_rest_call('/endpoints/index', params=data)
        ems_obj.logout()
        return res
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_endpoint_details(config, params):
    try:
        ems_obj = FortiClientEMS(config)
        ems_obj.login()
        resp = ems_obj.make_rest_call('/endpoints/index?device_id={0}'.format(params.get('device_id')))
        ems_obj.logout()
        return resp
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_zero_trust_rule_sets(config, params):
    try:
        ems_obj = FortiClientEMS(config)
        ems_obj.login()
        filters = check_payload(params.get('filters'))
        if filters:
            params.update({'filters': json.dumps(filters)})
        if params.get('sort_col'):
            params.update({'sort_col': params.get('sort_col').lower()})
        if params.get('sort_ord'):
            params.update({'sort_ord': SORT.get(params.get('sort_ord'))})
        if params.get('custom_attributes'):
            params.update(params.pop('custom_attributes'))
        data = check_payload(params)
        res = ems_obj.make_rest_call('/tag_rules/zero_trust/index', params=data)
        ems_obj.logout()
        return res
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_zero_trust_rule_tags(config, params):
    try:
        ems_obj = FortiClientEMS(config)
        ems_obj.login()
        res = ems_obj.make_rest_call('/tags/zero_trust/index')
        ems_obj.logout()
        return res
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def create_custom_tag(config, params):
    ems_obj = FortiClientEMS(config)
    ems_obj.login()
    data = check_payload(params)
    headers = {"Ems-Call-Type": "2"}
    res = ems_obj.make_rest_call("/tags/custom/create", method="POST", headers=headers, data=json.dumps(data))
    ems_obj.logout()
    return res


def delete_custom_tag(config, params):
    ems_obj = FortiClientEMS(config)
    ems_obj.login()
    params.update({"ids": str_to_list(params["ids"])})
    headers = {"Ems-Call-Type": "2"}
    res = ems_obj.make_rest_call("/tags/custom/delete", method="POST", headers=headers, data=json.dumps(params))
    ems_obj.logout()
    return res


def add_custom_tag(config, params):
    ems_obj = FortiClientEMS(config)
    ems_obj.login()
    params.update({"ids": str_to_list(params["ids"])})
    headers = {"Ems-Call-Type": "2"}
    res = ems_obj.make_rest_call("/clients/tags/custom/add", method="POST", headers=headers, data=json.dumps(params))
    ems_obj.logout()
    return res


def remove_custom_tag(config, params):
    ems_obj = FortiClientEMS(config)
    ems_obj.login()
    params.update({"ids": str_to_list(params["ids"])})
    headers = {"Ems-Call-Type": "2"}
    res = ems_obj.make_rest_call("/clients/tags/custom/remove", method="POST", headers=headers, data=json.dumps(params))
    ems_obj.logout()
    return res


def get_zero_trust_tag_by_id(config, params):
    ems_obj = FortiClientEMS(config)
    ems_obj.login()
    headers = {"Ems-Call-Type": "2"}
    res = ems_obj.make_rest_call(f"/tags/zero_trust/{params['id']}/get", method="GET", headers=headers)
    ems_obj.logout()
    return res


def create_zero_trust_tag(config, params):
    ems_obj = FortiClientEMS(config)
    ems_obj.login()
    headers = {"Ems-Call-Type": "2"}
    res = ems_obj.make_rest_call("/tags/zero_trust/create", method="POST", headers=headers, data=json.dumps(params))
    ems_obj.logout()
    return res


def delete_zero_trust_tag(config, params):
    ems_obj = FortiClientEMS(config)
    ems_obj.login()
    headers = {"Ems-Call-Type": "2"}
    res = ems_obj.make_rest_call(f"/tags/zero_trust/{params['id']}/delete", method="DELETE", headers=headers)
    ems_obj.logout()
    return res


def _check_health(config):
    try:
        ems_obj = FortiClientEMS(config)
        res = ems_obj.login()
        if res:
            return True
    except Exception as err:
        raise ConnectorError('Invalid Credentials')


operations = {
    'quarantine_endpoints': quarantine_endpoints,
    'unquarantine_endpoints': unquarantine_endpoints,
    'get_endpoints': get_endpoints,
    'get_endpoint_details': get_endpoint_details,
    'get_zero_trust_rule_sets': get_zero_trust_rule_sets,
    'get_zero_trust_rule_tags': get_zero_trust_rule_tags,
    "create_custom_tag": create_custom_tag,
    'delete_custom_tag': delete_custom_tag,
    'add_custom_tag': add_custom_tag,
    'remove_custom_tag': remove_custom_tag,
    'get_zero_trust_tag_by_id': get_zero_trust_tag_by_id,
    'create_zero_trust_tag': create_zero_trust_tag,
    'delete_zero_trust_tag': delete_zero_trust_tag
}
