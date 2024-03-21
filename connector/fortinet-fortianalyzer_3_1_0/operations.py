""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import arrow
import base64
import os
import json
from datetime import datetime
from connectors.core.connector import get_logger, ConnectorError
from integrations.crudhub import make_request, make_file_upload_request
from django.conf import settings
from connectors.cyops_utilities.builtins import upload_file_to_cyops
from .constants import *

logger = get_logger('fortinet-fortianalyzer')


class FortiAnalyzer():
    def __init__(self, config):
        self.server_url = config.get('server_url')
        self.port = config.get('port')
        if self.server_url.startswith('https://') or self.server_url.startswith('http://'):
            if self.port:
                self.server_url = self.server_url.strip('/') + ':{port}'.format(port=self.port) + '/jsonrpc'
            else:
                self.server_url = self.server_url.strip('/') + '/jsonrpc'
        else:
            if self.port:
                self.server_url = 'https://{0}:{1}'.format(self.server_url.strip('/'), self.port) + '/jsonrpc'
            else:
                self.server_url = 'https://{0}'.format(self.server_url.strip('/')) + '/jsonrpc'
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl')
        self.session = None

    def make_api_call(self, method='GET', endpoint=None, params=None, data=None,
                      json=None, flag=False):
        url = '{0}'.format(self.server_url)
        logger.info('Request URL {0}'.format(url))
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        try:
            response = requests.request(method=method, url=url, params=params, data=data, json=json,
                                        headers=headers,
                                        verify=self.verify_ssl)
            if response.ok:
                result = response.json()
                if isinstance(result.get('result'), list):
                    if result.get('result')[0].get('status').get('code') == -11:
                        raise ConnectorError("No permission for the resource")
                if result.get('error'):
                    if "Invalid params" in result.get('error').get('message'):
                        raise ConnectorError("Invalid ADOM name provided")
                    else:
                        raise ConnectorError('{}'.format(result.get('error').get('message')))
                if response.status_code == 204:
                    return {"Status": "Success", "Message": "Executed successfully"}
                return result
            elif messages_codes[response.status_code]:
                logger.error('{0}'.format(messages_codes[response.status_code]))
                raise ConnectorError('{0}'.format(messages_codes[response.status_code]))
            else:
                logger.error(
                    'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url),
                                                                                        str(response.content),
                                                                                        str(response.reason)))
                raise ConnectorError(
                    'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url),
                                                                                       str(response.content),

                                                                                       str(response.reason)))

        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes['timeout_error']))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))

    def login(self):
        data = {
            "method": "exec",
            "params": [
                {
                    "url": "/sys/login/user",
                    "data": {
                        "user": self.username,
                        "passwd": self.password
                    }
                }
            ],
            "id": CONST_ID
        }
        try:
            json_resp = self.make_api_call(method='POST', json=data)
            self.session = json_resp.get('session')
        except Exception as err:
            logger.exception('{0}'.format(err))
            raise ConnectorError('{0}'.format(err))

    def logout(self):
        data = {
            "method": "exec",
            "params": [
                {
                    "url": "/sys/logout"
                }
            ],
            "session": self.session
        }
        try:
            json_resp = self.make_api_call(method='POST', json=data)
        except Exception as err:
            logger.exception('{0}'.format(err))
            raise ConnectorError('{0}'.format(err))


def build_payload(params, input_params_list):
    result = {k: v for k, v in params.items() if v is not None and v != '' and k in input_params_list}
    return result



def handle_datetime(date_ts):   
    try:    
        conv_date_time = datetime.strptime(date_ts, '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%Y-%m-%dT%H:%M:%SZ")  
    except: 
        import sys  
        ver = sys.version_info  
        if ver.major == 3 and ver.minor == 6:   
            date_ts = date_ts[0:-3] + date_ts[-2:]  
        conv_date_time = datetime.strptime(date_ts, '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%Y-%m-%dT%H:%M:%SZ") 
    return conv_date_time


def check_health(config):
    try:
        logger.info("Invoking check_health")
        fortianalyzer = FortiAnalyzer(config)
        fortianalyzer.login()
        if fortianalyzer.session:
            payload = {
                "method": "get",
                "params": [
                    {
                        "url": "/sys/status",
                        "apiver": APIVER
                    }
                ],
                "jsonrpc": JSONRPC,
                "session": fortianalyzer.session,
                "id": CONST_ID
            }
            response = fortianalyzer.make_api_call(method='POST', json=payload)
            fortianalyzer.logout()
            return True
    except Exception as err:
        logger.exception('{0}'.format(err))
        fortianalyzer.logout()
        raise ConnectorError('{0}'.format(err))


def create_incident(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('create_incident'))
        other_fields = params.get('other_fields', '')
        payload = {
            "method": "add",
            "params": [
                {
                    "url": "/incidentmgmt/adom/{adom_name}/incident".format(adom_name=adom_name),
                    "apiver": APIVER,
                    "reporter": params.get('reporter'),
                    "endpoint": params.get('endpoint')
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('status'):
                result['status'] = status_mapping.get(result.get('status'))
            if result.get('severity'):
                result['severity'] = severity_mapping.get(result.get('severity'))
            result.pop('reporter')
            result.pop('endpoint')
            payload.get('params')[0].update(result)
        if other_fields:
            payload.get('params')[0].update(other_fields)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def list_incidents(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('list_incidents'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/incidentmgmt/adom/{adom_name}/incidents".format(adom_name=adom_name),
                    "filter": "",
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('incids'):
                if not isinstance(result.get('incids'), list):
                    incids = [x.strip() for x in result.get('incids').split(',')]
                    result['incids'] = incids
            if result.get('sort-by'):
                sortby = [{
                    "field": result.get('field'),
                    "order": result.get('order')
                }]
                result['sort-by'] = sortby
                result.pop('field')
                result.pop('order')
            if result.get('detail-level'):
                result['detail-level'] = detail_level_mapping.get(result.get('detail-level'))
            if result.get('status'):
                result['status'] = status_mapping.get(result.get('status'))
            if result.get('filter'):
                filter_str = result.get('filter') + ' and '
            else:
                filter_str = ''
            payload.get('params')[0].update(result)
            if payload.get('params')[0].get('status'):
                filter = 'status={} and '.format(payload.get('params')[0].get('status'))
                filter_str += filter
                payload.get('params')[0].pop('status')
            payload.get('params')[0]['filter'] = filter_str[:-5]
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def update_incident_details(config, params):
    try:
        adom_name = params.get('adom_name')
        incid = params.get('incid')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('update_incident_details'))
        other_fields = params.get('other_fields', '')
        payload = {
            "method": "update",
            "params": [
                {
                    "url": "/incidentmgmt/adom/{adom_name}/incident/{incid}".format(adom_name=adom_name, incid=incid),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('category'):
                result['category'] = category_mapping.get(result.get('category'))
            if result.get('status'):
                result['status'] = status_mapping.get(result.get('status'))
            if result.get('severity'):
                result['severity'] = severity_mapping.get(result.get('severity'))
            result.pop('incid')
            payload.get('params')[0].update(result)
        if other_fields:
            payload.get('params')[0].update(other_fields)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_events_for_incident(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_events_for_incident'))
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/incidentmgmt/adom/{adom_name}/attachments".format(adom_name=adom_name),
                    "incid": params.get('incid'),
                    "attachtype": "alertevent",
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            result.pop('incid')
            payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_incident_assets(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_events_for_incident'))
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/incidentmgmt/adom/{adom_name}/epeu-history".format(adom_name=adom_name),
                    "incid": params.get('incid'),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            result.pop('incid')
            payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_reports(config, params):
    try:
        adom_name = params.get('adom_name')
        start = params.get('start')
        end = params.get('end')
        obj = FortiAnalyzer(config)
        obj.login()
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/report/adom/{adom_name}/reports/state".format(adom_name=adom_name),
                    "state": params.get('state'),
                    "apiver": APIVER,
                    "time-range": {"start": handle_datetime(start),
                                   "end": handle_datetime(end)}
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_schedules(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "report/adom/{adom_name}/config/schedule".format(adom_name=adom_name),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def run_report(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        payload = {
            "method": "add",
            "params": [
                {
                    "url": "/report/adom/{adom_name}/run".format(adom_name=adom_name),
                    "apiver": APIVER,
                    "schedule": params.get('schedule')
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": params.get("id")
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_generated_report(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/report/adom/{adom_name}/reports/data/{tid}".format(adom_name=adom_name,
                                                                                tid=params.get('tid')),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        data = base64.b64decode(response.get('result').get('data'))
        time = arrow.utcnow()
        file_name = 'FortiAnalyzerPDF_{}.zip'.format(time)
        try:
            path = os.path.join(settings.TMP_FILE_ROOT, file_name)
            logger.error("Path: {0}".format(path))
            with open(path, 'wb') as fp:
                fp.write(data)
            attach_response = upload_file_to_cyops(file_path=file_name, filename=file_name,
                                                   name=file_name, create_attachment=True)
            obj.logout()
            return attach_response
        except Exception as e:
            logger.exception(e)
            raise ConnectorError(str(e))
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_users(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_users'))
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/ueba/adom/{adom_name}/endusers".format(adom_name=adom_name),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('euids'):
                euids = result.get('euids')
                if isinstance(euids, list):
                    result['euids'] = euids
                else:
                    result['euids'] = [euids]
            if result.get('sort-by'):
                sortby = [{
                    "field": result.get('field'),
                    "order": result.get('order')
                }]
                result['sort-by'] = sortby
                result.pop('field')
                result.pop('order')
            if result.get('detail-level'):
                result['detail-level'] = detail_level_mapping.get(result.get('detail-level'))
            if result.get('filter'):
                filter_str = result.get('filter') + ' and '
            else:
                filter_str = ''
            payload.get('params')[0].update(result)
            payload.get('params')[0]['filter'] = filter_str[:-5]
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        obj.logout()
        raise ConnectorError(Err)


def get_endpoints(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_endpoints'))
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/ueba/adom/{adom_name}/endpoints".format(adom_name=adom_name),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('epids'):
                epids = result.get('epids')
                if isinstance(epids, list):
                    result['epids'] = epids
                else:
                    result['epids'] = [epids]
            if result.get('sort-by'):
                sortby = [{
                    "field": result.get('field'),
                    "order": result.get('order')
                }]
                result['sort-by'] = sortby
                result.pop('field')
                result.pop('order')
            if result.get('filter'):
                filter_str = result.get('filter') + ' and '
            else:
                filter_str = ''
            payload.get('params')[0].update(result)
            payload.get('params')[0]['filter'] = filter_str[:-5]
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        obj.logout()
        raise ConnectorError(Err)


def list_log_fields(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('list_log_fields'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/logview/adom/{adom_name}/logfields".format(adom_name=adom_name),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('logtype'):
                result['logtype'] = log_type_mapping.get(result.get('logtype'))

            payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_log_file_content(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_log_file_content'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/logview/adom/{adom_name}/logfiles/data".format(adom_name=adom_name),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        file_data = response.get('result').get('data')
        time = arrow.utcnow()
        file_name = result.get('filename')
        try:
            file = make_file_upload_request(file_name, file_data, 'application/octet-stream')
            file_id = file['@id']
            file_description = 'FortiAnalyzer Attachment File'

            attachment_name = 'FortiAnalyzer Attachment_{}'.format(time)
            res = make_request('/api/3/attachments', 'POST',
                               {'name': attachment_name, 'file': file_id, 'description': file_description})
            obj.logout()
            return res
        except Exception as e:
            logger.exception(e)
            raise ConnectorError(str(e))
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def log_search_over_log_file(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('log_search_over_log_file'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/logview/adom/{adom_name}/logfiles/search".format(adom_name=adom_name),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('logtype'):
                result['logtype'] = log_type_mapping.get(result.get('logtype'))

            payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        if response.get('result').get('data'):
            data_list = response.get('result').get('data')
            for i in data_list:
                if i.get('srcname') and '%20' in i.get('srcname'):
                    i['srcname'] = i['srcname'].replace('%20', ' ')
                if i.get('dstcountry') and '%20' in i.get('dstcountry'):
                    i['dstcountry'] = i['dstcountry'].replace('%20', ' ')
                if i.get('msg') and '%20' in i.get('msg'):
                    i['msg'] = i['msg'].replace('%20', ' ')
                if i.get('msg') and '%3A' in i.get('msg'):
                    i['msg'] = i['msg'].replace('%3A', ':')
                if i.get('msg') and '%2C' in i.get('msg'):
                    i['msg'] = i['msg'].replace('%2C', ',')
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_log_file_state(config, params):
    try:
        adom_name = params.get('adom_name')
        start = params.get('start')
        end = params.get('end')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_log_file_state'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/logview/adom/{adom_name}/logfiles/state".format(adom_name=adom_name),
                    "apiver": APIVER,
                    "time-range": {"start": handle_datetime(start),
                                   "end": handle_datetime(end)}
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def start_log_search_request(config, params):
    try:
        adom_name = params.get('adom_name')
        start = params.get('start')
        end = params.get('end')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('start_log_search_request'))

        payload = {
            "method": "add",
            "params": [
                {
                    "url": "/logview/adom/{adom_name}/logsearch".format(adom_name=adom_name),
                    "filter": "",
                    "apiver": APIVER,
                    "time-range": {"start": handle_datetime(start),
                                   "end": handle_datetime(end)}
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        result.pop('start')
        result.pop('end')
        if result:
            if result.get('logtype'):
                result['logtype'] = log_type_mapping.get(result.get('logtype'))
            if result.get('time-order'):
                result['time-order'] = time_order_mapping.get(result.get('time-order'))
                result.pop('time-order')
            if result.get('devid') and result.get('devname'):
                result['device'] = [{"devid": result.get('devid'), "devname": result.get('devname')}]
                result.pop('devid')
                result.pop('devname')
            if result.get('filter'):
                filter_str = result.get('filter') + ' and '
            else:
                filter_str = ''
            payload.get('params')[0].update(result)
            payload.get('params')[0]['filter'] = filter_str[:-5]
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def fetch_log_search_result_by_task_id(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('fetch_log_search_result_by_task_id'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/logview/adom/{adom_name}/logsearch/{tid}".format(adom_name=adom_name,
                                                                              tid=params.get('tid')),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        result.pop('tid')
        payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_alerts(config, params):
    try:
        adom_name = params.get('adom_name')
        start = params.get('start')
        end = params.get('end')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_alerts'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/eventmgmt/adom/{adom_name}/alerts".format(adom_name=adom_name),
                    "filter": "",
                    "apiver": APIVER,
                    "time-range": {"start": start,
                                   "end": end}
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            filter_str = ''
            if result.get('alertid'):
                if isinstance(result.get('alertid'), list):
                    str_alertid = [str(x) for x in result.get('alertid')]
                    alertid = ','.join(str_alertid)
                    alert_filter = "alertid=" + alertid
                    result.pop('alertid')
                    filter_str += alert_filter
                if isinstance(result.get('alertid'), str) and not isinstance(result.get('alertid'), int):
                    alert_filter = "alertid=" + result.get('alertid')
                    result.pop('alertid')
                    filter_str += alert_filter
            if result.get('severity'):
                result['severity'] = severity_mapping.get(result.get('severity'))
            if result.get('devid') and result.get('devname'):
                result['device'] = [{"devid": result.get('devid'), "devname": result.get('devname')}]
                result.pop('devid')
                result.pop('devname')
            if result.get('filter') and filter_str:
                filter_str = result.get('filter') + ' and ' + filter_str
            elif filter_str:
                filter_str = filter_str
            else:
                filter_str = result.get('filter')
            payload.get('params')[0].update(result)
            payload.get('params')[0]['filter'] = filter_str
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_alert_event_logs(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_alert_event_logs'))
        logger.info("Result: {}".format(result))
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/eventmgmt/adom/{adom_name}/alertlogs".format(adom_name=adom_name),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('alertid'):
                if isinstance(result.get('alertid'), int):
                    result['alertid'] = [str(result.get('alertid'))]
                if not isinstance(result.get('alertid'), list):
                    alertid = [x.strip() for x in result.get('alertid').split(',')]
                    result['alertid'] = alertid
            if result.get('devid') and result.get('devname'):
                result['device'] = {"devid": result.get('devid'), "devname": result.get('devname')}
            if result.get('time-order'):
                result['time-order'] = time_order_mapping.get(result.get('time-order'))
                result.pop('time-order')
            payload.get('params')[0].update(result)
        logger.info("Payload: {}".format(payload))
        response = obj.make_api_call(method='POST', json=payload)
        if response.get('result').get('data'):
            data_list = response.get('result').get('data')
            for i in data_list:
                if i.get('msg') and '%20' in i.get('msg'):
                    i['msg'] = i['msg'].replace('%20', ' ')
                if i.get('to') and '%40' in i.get('to'):
                    i['to'] = i['to'].replace('%40', '@')
                if i.get('from') and '%40' in i.get('from'):
                    i['from'] = i['from'].replace('%40', '@')
                if i.get('srcname') and '%20' in i.get('srcname'):
                    i['srcname'] = i['srcname'].replace('%20', ' ')
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_attachments_for_incident(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_attachments_for_incident'))
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/incidentmgmt/adom/{adom_name}/attachments".format(adom_name=adom_name),
                    "incid": params.get('incid'),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            result.pop('incid')
            payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        data = response.get('result').get('data')
        for i in data:
            i['data'] = json.loads(i.get('data'))
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def update_attachment(config, params):
    try:
        adom_name = params.get('adom_name')
        attachid = params.get('attachid')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('update_attachment'))
        payload = {
            "method": "update",
            "params": [
                {
                    "url": "/incidentmgmt/adom/{adom_name}/attachment/{attachid}".format(adom_name=adom_name,
                                                                                         attachid=attachid),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('category'):
                result['category'] = category_mapping.get(result.get('category'))
            if result.get('status'):
                result['status'] = status_mapping.get(result.get('status'))
            if result.get('severity'):
                result['severity'] = severity_mapping.get(result.get('severity'))
            result.pop('attachid')
            payload.get('params')[0].update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_adoms(config, params):
    try:
        obj = FortiAnalyzer(config)
        obj.login()
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/dvmdb/adom",
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def add_master_device(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('add_master_device'))
        payload = {
            "method": "exec",
            "params": [
                {
                    "url": "/dvm/cmd/add/device",
                    "apiver": APIVER,
                    "data": {
                        "device": {
                            "device_action": "add_model",
                            "version": VERSION,
                            "mr": 0,
                            "mgmt_mode": "faz"
                        },
                        "adom": adom_name
                    }
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            payload.get('params')[0].get('data').get('device').update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def add_slave_device(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('add_slave_device'))
        payload = {
            "method": "exec",
            "params": [
                {
                    "url": "/dvm/cmd/update/ha",
                    "apiver": APIVER,
                    "data": {
                        "name": result.get('master_name'),
                        "adom": adom_name,
                        "ha_mode": "AP",
                        "sn": result.get('master_sn'),
                        "mgmt_mode": "faz",
                        "ha_group_name": result.get('master_sn'),
                        "ha_slave": [{
                            "did": result.get('master_sn'),
                            "role": "slave",
                            "name": result.get('slave_name'),
                            "idx": 1,
                            "sn": result.get('slave_sn')
                        }, {
                            "name": result.get('master_name'),
                            "prio": 0,
                            "did": result.get('master_sn'),
                            "idx": 0,
                            "role": "master",
                            "sn": result.get('master_sn')
                        }]
                    }
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def add_new_device(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('add_new_device'))
        payload = {
            "method": "exec",
            "params": [
                {
                    "url": "/dvm/cmd/add/device",
                    "apiver": APIVER,
                    "data": {
                        "device": {
                            "device_action": "add_model",
                            "version": VERSION,
                            "mr": 0,
                            "mgmt_mode": "faz"
                        },
                        "adom": adom_name
                    }
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            payload.get('params')[0].get('data').get('device').update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_devices(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/dvmdb/adom/{adom_name}/device".format(adom_name=adom_name),
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_log_status(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_log_status'))
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/logview/adom/{adom_name}/logstats".format(adom_name=adom_name),
                    "apiver": APIVER,
                    "device": [
                        {
                            "devid": result.get('devid')
                        }
                    ]
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_device_info(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_device_info'))
        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/dvmdb/adom/{adom_name}/device/{name}".format(adom_name=adom_name,
                                                                          name=result.get('name'))
                }
            ],
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def authorize_device(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('authorize_device'))
        payload = {
            "method": "exec",
            "params": [
                {
                    "url": "/dvm/cmd/add/device",
                    "apiver": APIVER,
                    "data": {
                        "device": {
                            "device_action": "promote_unreg",
                            "version": VERSION,
                            "mr": 0,
                            "mgmt_mode": "faz"
                        },
                        "adom": adom_name
                    }
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            payload.get('params')[0].get('data').get('device').update(result)
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def delete_device(config, params):
    try:
        adom_name = params.get('adom_name')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('delete_device'))
        payload = {
            "method": "exec",
            "params": [
                {
                    "url": "/dvm/cmd/del/device",
                    "apiver": APIVER,
                    "data": {
                        "device": result.get('name'),
                        "adom": adom_name
                    }
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def get_alerts_for_multiple_adoms(config, params):
    try:
        adom_name = [x.strip() for x in config.get('adom_name').split(',')]
        start = params.get('start')
        end = params.get('end')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('get_alerts_for_multiple_adoms'))

        if start and end:
            payload = {
                "method": "get",
                "params": [
                    {
                        "url": "/eventmgmt/alerts",
                        "adoms": adom_name,
                        "filter": "",
                        "apiver": APIVER,
                        "time-range": {"start": handle_datetime(start),
                                       "end": handle_datetime(end)}
                    }
                ],
                "jsonrpc": JSONRPC,
                "session": obj.session,
                "id": CONST_ID
            }
            result.pop('start')
            result.pop('end')
        else:
            payload = {
                "method": "get",
                "params": [
                    {
                        "url": "/eventmgmt/alerts",
                        "adoms": adom_name,
                        "filter": "",
                        "apiver": APIVER
                    }
                ],
                "jsonrpc": JSONRPC,
                "session": obj.session,
                "id": CONST_ID
            }        

        if result:
            filter_str = ''
            if result.get('alertid'):
                if isinstance(result.get('alertid'), list):
                    str_alertid = [str(x) for x in result.get('alertid')]
                    alertid = ','.join(str_alertid)
                    alert_filter = "alertid=" + alertid
                    result.pop('alertid')
                    filter_str += alert_filter
                if isinstance(result.get('alertid'), str) and not isinstance(result.get('alertid'), int):
                    alert_filter = "alertid=" + result.get('alertid')
                    result.pop('alertid')
                    filter_str += alert_filter
            if result.get('severity'):
                result['severity'] = severity_mapping.get(result.get('severity'))
            if result.get('devid') and result.get('devname'):
                result['device'] = [{"devid": result.get('devid'), "devname": result.get('devname')}]
                result.pop('devid')
                result.pop('devname')
            if result.get('filter') and filter_str:
                filter_str = result.get('filter') + ' and ' + filter_str
            elif filter_str:
                filter_str = filter_str
            else:
                filter_str = result.get('filter')
            payload.get('params')[0].update(result)
            payload.get('params')[0]['filter'] = filter_str
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def count_alerts_for_multiple_adoms(config, params):
    try:
        adom_name = [x.strip() for x in config.get('adom_name').split(',')]
        group_by = params.get('group-by')
        start = params.get('start')
        end = params.get('end')
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('count_alerts_for_multiple_adoms'))

        if start and end:
            payload = {
                "method": "get",
                "params": [
                    {
                        "url": "/eventmgmt/alerts/count",
                        "adoms": adom_name,
                        "group-by": group_by,
                        "filter": "",
                        "apiver": APIVER,
                        "time-range": {"start": handle_datetime(start),
                                       "end": handle_datetime(end)}
                    }
                ],
                "jsonrpc": JSONRPC,
                "session": obj.session,
                "id": CONST_ID
            }
            result.pop('start')
            result.pop('end')
        else:
            payload = {
                "method": "get",
                "params": [
                    {
                        "url": "/eventmgmt/alerts/count",
                        "adoms": adom_name,
                        "group-by": group_by,
                        "filter": "",
                        "apiver": APIVER
                    }
                ],
                "jsonrpc": JSONRPC,
                "session": obj.session,
                "id": CONST_ID
            }

        if result:
            filter_str = ''
            if result.get('filter') and filter_str:
                filter_str = result.get('filter') + ' and ' + filter_str
            elif filter_str:
                filter_str = filter_str
            else:
                filter_str = result.get('filter')
            payload.get('params')[0].update(result)
            payload.get('params')[0]['filter'] = filter_str
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def list_incidents_for_multiple_adoms(config, params):
    try:
        adom_name = [x.strip() for x in config.get('adom_name').split(',')]
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('list_incidents_for_multiple_adoms'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/incidentmgmt/incidents",
                    "adoms": adom_name,
                    "filter": "",
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            if result.get('incids'):
                if not isinstance(result.get('incids'), list):
                    incids = [x.strip() for x in result.get('incids').split(',')]
                    result['incids'] = incids
            if result.get('sort-by'):
                sortby = [{
                    "field": result.get('field'),
                    "order": result.get('order')
                }]
                result['sort-by'] = sortby
                result.pop('field')
                result.pop('order')
            if result.get('detail-level'):
                result['detail-level'] = detail_level_mapping.get(result.get('detail-level'))
            if result.get('status'):
                result['status'] = status_mapping.get(result.get('status'))
            if result.get('filter'):
                filter_str = result.get('filter') + ' and '
            else:
                filter_str = ''
            payload.get('params')[0].update(result)
            if payload.get('params')[0].get('status'):
                filter = 'status={} and '.format(payload.get('params')[0].get('status'))
                filter_str += filter
                payload.get('params')[0].pop('status')
            payload.get('params')[0]['filter'] = filter_str[:-5]
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


def count_incidents_for_multiple_adoms(config, params):
    try:
        adom_name = [x.strip() for x in config.get('adom_name').split(',')]
        obj = FortiAnalyzer(config)
        obj.login()
        result = build_payload(params, action_input_parameters.get('count_incidents_for_multiple_adoms'))

        payload = {
            "method": "get",
            "params": [
                {
                    "url": "/incidentmgmt/incidents/count",
                    "adoms": adom_name,
                    "filter": "",
                    "apiver": APIVER
                }
            ],
            "jsonrpc": JSONRPC,
            "session": obj.session,
            "id": CONST_ID
        }
        if result:
            filter_str = ''
            if result.get('incids'):
                if not isinstance(result.get('incids'), list):
                    incids = [x.strip() for x in result.get('incids').split(',')]
                    result['incids'] = incids
            if result.get('filter') and filter_str:
                filter_str = result.get('filter') + ' and ' + filter_str
            elif filter_str:
                filter_str = filter_str
            else:
                filter_str = result.get('filter')
            payload.get('params')[0].update(result)
            payload.get('params')[0]['filter'] = filter_str
        response = obj.make_api_call(method='POST', json=payload)
        obj.logout()
        return response
    except Exception as err:
        logger.exception('{0}'.format(err))
        obj.logout()
        raise ConnectorError('{0}'.format(err))


operations = {
    'create_incident': create_incident,
    'list_incidents': list_incidents,
    'update_incident_details': update_incident_details,
    'get_events_for_incident': get_events_for_incident,
    'get_incident_assets': get_incident_assets,
    'get_reports': get_reports,
    'get_schedules': get_schedules,
    'run_report': run_report,
    'get_generated_report': get_generated_report,
    'get_users': get_users,
    'get_endpoints': get_endpoints,
    'list_log_fields': list_log_fields,
    'get_log_file_content': get_log_file_content,
    'log_search_over_log_file': log_search_over_log_file,
    'get_log_file_state': get_log_file_state,
    'start_log_search_request': start_log_search_request,
    'fetch_log_search_result_by_task_id': fetch_log_search_result_by_task_id,
    'get_alerts': get_alerts,
    'get_alert_event_logs': get_alert_event_logs,
    'get_attachments_for_incident': get_attachments_for_incident,
    'update_attachment': update_attachment,

    'get_adoms': get_adoms,
    'add_master_device': add_master_device,
    'add_slave_device': add_slave_device,
    'add_new_device': add_new_device,
    'get_devices': get_devices,
    'get_log_status': get_log_status,
    'get_device_info': get_device_info,
    'authorize_device': authorize_device,
    'delete_device': delete_device,

    'get_alerts_for_multiple_adoms': get_alerts_for_multiple_adoms,
    'count_alerts_for_multiple_adoms': count_alerts_for_multiple_adoms,
    'list_incidents_for_multiple_adoms': list_incidents_for_multiple_adoms,
    'count_incidents_for_multiple_adoms': count_incidents_for_multiple_adoms

}

