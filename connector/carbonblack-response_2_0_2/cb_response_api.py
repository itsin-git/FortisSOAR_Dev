""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import inspect, json
from requests import request
import requests.exceptions
import requests.packages.urllib3
from parse import parse
import re
import socket
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('cb-response')


def isValidHash(_len, file_hash):
    if _len in [32, 40, 64]:  # md5/sha1/sha256
        pattern = re.compile(r'[0-9a-fA-F]{%s}' % _len)
        match = re.match(pattern, file_hash)
        if match is not None:
            return True
    return False


def validate_input_params(param):
    hostname = host_ip = sensor_id = None
    if param:
        input_type = param.get('input_type')
        value = param.get('value')
        if value and input_type == 'IP Address':
            try:
                socket.inet_aton(value)
                host_ip = value
            except socket.error:
                raise ConnectorError("Provided IP Address is invalid")

        elif value and input_type == 'Hostname':
            hostname = value

        elif value and input_type == 'Sensor ID':
            sensor_id = value

        if not (host_ip or hostname or sensor_id):
            raise ConnectorError("Host ip, Hostname, Sensor is not specified."
                                 "Please specify at-least one of them")
        else:
            return hostname, host_ip, sensor_id


class CbResponseAPI(object):
    """An API wrapper to facilitate interactions to and from CarbonBlack Defence."""

    def __init__(self, host, api_key, verify_ssl=True, timeout=30):
        """
        Initialize a CarbonBlack Defence API instance.
        :param host: The URL for the CarbonBlack Defence server.
        :param api_key: The API key generated on the CarbonBlack Defence API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 25.
        """
        self.host = host
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()  # Disabling SSL warning messages if verification is disabled.

    def api_info(self):
        return self._request('GET', '/api/info')


    # Device

    def get_system_info(self, query_params):
        """Get information about an endpoint."""
        param = dict()
        hostname, host_ip, sensor_id = validate_input_params(query_params)
        if host_ip:
            param['ip'] = host_ip
        if hostname:
            param['hostname'] = hostname

        return self._request('GET', '/api/v1/sensor', param)

    def get_sensor_by_id(self, sensor_id):

        return self._request('GET', '/api/v1/sensor/{0}'.format(sensor_id))

    def list_sensors(self):

        return self._request('GET', '/api/v1/sensor')

    def get_blacklisted_hash(self):

        return self._request('GET', '/api/v1/banning/blacklist')

    def get_file_info(self, param):
        """
        Get info about a file from Carbon Black Response.
        :param param: md5 hash
        :return:binary object
        """
        process_md5 = param.get('md5')

        result = isValidHash(process_md5.__len__(), process_md5)

        if not result:
            logger.error('Failed not a valid MD5')

        return self._request('GET', '/api/v1/binary/{0}/summary'.format(process_md5))

    def ban_hash(self, param):
        md5 = param.get('md5')

        result = isValidHash(md5.__len__(), md5)

        if not result:
            logger.error('Failed not a valid MD5')
            raise ConnectorError(
                'CarbonBlack.ban_hash: Failed not a valid MD5')
        data = {
            "md5hash": md5,
            "text": "Ban from CyOps",
            "last_ban_time": "0",
            "ban_count": "0",
            "last_ban_host": "0",
            "enabled": "True"
        }
        return self._request('POST', '/api/v1/banning/blacklist', data=data)

    def unblock_hash(self, param):
        md5_hash = param.get('md5')

        result = isValidHash(md5_hash.__len__(), md5_hash)

        if not result:
            logger.error('Failed not a valid MD5')
            raise ConnectorError('CarbonBlack.unblock_hash: Failed not a valid MD5')

        return self._request('DELETE', '/api/v1/banning/blacklist/{}'.format(md5_hash))

    def run_query(self, param):
        """
        :param    query_type:(binary or process)
                  query: e.g: "process_name:win *.exe"
        :return: json object
        """

        # query_type can be either binary or process
        query_type_dict = {'Process': 'process',
                           'Binary': 'binary'}

        query_type = query_type_dict.get(param.get('query_type'))
        query = param.get('query')
        start = param.get('start')
        rows = param.get('rows')

        data = {'params': 'server_added_timestamp desc',
                'start': start,
                'rows': rows,
                'facet': 'false',
                'cb.urlver': '1',
                'q': query
                }
        endpoint = '/api/v1/{0}'.format(query_type.lower())
        return self._request('GET', endpoint, data)

    def hunt_file(self, param):
        query_type_dict = {'Process': 'process',
                           'Binary': 'binary'}

        query_type = query_type_dict.get( param.get('query_type'))
        md5 = param.get('md5')
        start = param.get('start')
        rows = param.get('rows')


        if query_type not in ['binary', 'process']:
            logger.error('Unsupported or wrong query type: {0}'.format(query_type))
            return None

        result = isValidHash(md5.__len__(), md5)

        if not result:
            logger.error('Failed not a valid MD5')
            raise ConnectorError('CarbonBlack.hunt_file: Failed not a valid MD5')

        query = md5

        data = {'params': 'server_added_timestamp desc',
                'start': start,
                'rows': rows,
                'facet': 'false',
                'cb.urlver': '1',
                'q': query
                }

        endpoint = '/api/v1/{0}'.format(query_type)
        return self._request('GET', endpoint, data)

    def search_alert(self, params):

        query = params.get('query')
        start = params.get('start')
        rows = params.get('rows')
        status = params.get('status')

        if not status and not query:
            logger.info("Either CB query or status parameter is required.")
            raise ConnectorError("Either CB query or status parameter is required.")
        if status is 'All':
            status = []

        sort_dict = {'Severity': 'alert_severity',
                     'Most Recent': 'created_time desc',
                     'Least Recent': 'created_time asc',
                     'Alert Name Ascending': 'process_name asc',
                     'Alert Name Descending': 'process_name desc'}
        sort_by = sort_dict.get(params.get('sort_by'),'alert_severity')

        data = {'sort': sort_by,
                'start': start,
                'rows': rows,
                'facet': 'false',
                'cb.urlver': '1',
                'cb.fq.status': status,
                'q': query
                }

        return self._request('GET', '/api/v2/alert', params=data)

    def update_alert(self, params):
            alert_id = params.get('unique_id')
            status = params.get('status')

            endpoint = '/api/v1/alert/{0}'.format(alert_id)
            data = {
                'unique_id': alert_id,
                'status': status
            }
            return self._request("POST", endpoint, data=data)

    def bulk_update_alert(self, params):
        result = []
        alert_ids = params.get('alert_id')
        itype = type(alert_ids)
        if itype is str:
            result = alert_ids.split(',')

        status = params.get('status')

        data = {"alert_ids": result,
                "requested_status": status,
                "set_ignored": 'true'
                }

        return self._request("POST", '/api/v1/alerts', data=data)

    def get_watchlist(self, params):
        watchlist_id = params.get('watchlist_id')

        if not watchlist_id:
            return self._request('GET', '/api/v1/watchlist')
        else:
            response_list = []
            result = self._request('GET','/api/v1/watchlist/{0}'.format(watchlist_id))
            if isinstance(result, dict):
                response_list.append(result)
                return response_list

    # Utility
    def _parse_range(self, page_range):
        p = parse('{start}:{end}', page_range)
        if p is None:
            return None, None
        else:
            start = int(p['start'])
            end = int(p['end'])
            if end < start:
                return None, None
            rows = end - start
            if rows == 0:
                rows = 1
            return start, rows

    def _error_message_log(self, message):
        func_name = inspect.stack()[1][3]
        err_msg = func_name + ": " + message
        logger.error(err_msg)
        raise ConnectorError(message)

    def _request(self, method, url, params=None, data=None ,files=None):
        """Common handler for all HTTP requests."""

        headers = {
            'X-Auth-Token': self.api_key,
            'Accept': 'application/json',
            'Content-type': 'application/json'
        }

        try:
            q_url = '{0}{1}'.format(self.host, url)
            logger.info('Making API call with url {}'.format(q_url))
            if method is "DELETE":
                response = request(method="DELETE", url=q_url, headers=headers, verify=self.verify_ssl)
            else:
                response = request(method=method, url=q_url, params=params, data=json.dumps(data), files=files,
                                   headers=headers, timeout=self.timeout, verify=self.verify_ssl)
            if response.status_code == 200:
                try:
                    json_response = response.json()
                    if json_response:
                        return json_response
                    else:
                        self._error_message_log(message='The request is successfully executed but no data found')
                except Exception as err:
                    return self._error_message_log(message=str(err))

            elif response.status_code == 409:
                resp = dict()
                logger.error("Failure with status[{0}]:[{1}]".format(str(response.status_code), response.content))
                resp['result'] = '{0}'.format(response.content)
                return resp
            else:
                msg = "Status Code {0}:{1}".format(str(response.status_code), str(response.text))

                raise ConnectorError(msg)
        except requests.exceptions.SSLError:
            return self._error_message_log(message='SSL certificate validation failed')
        except requests.exceptions.ConnectionError:
            return self._error_message_log(message='Invalid endpoint')
        except requests.exceptions.Timeout:
            return self._error_message_log(message='The request timed out while trying to connect to the remote server')
        except requests.exceptions.RequestException:
            return self._error_message_log(message='There was an error while handling the request.')
        except Exception as err:
            return self._error_message_log(message=format(str(err)))
