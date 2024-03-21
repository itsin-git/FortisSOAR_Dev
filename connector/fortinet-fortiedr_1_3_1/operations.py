""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import requests
import json
import os
import time
import base64
from datetime import datetime
from requests import exceptions as req_exceptions
from django.conf import settings
from integrations.crudhub import make_request
from connectors.core.connector import get_logger, ConnectorError, api_health_check


logger = get_logger('fortinet-fortiedr')

TMP_LOC = os.path.dirname(os.path.realpath(__file__)) + "/FortiEDR"


class FortiEDRClient:
    API_PREFIX = "/management-rest"
    username = None
    password = None
    token = None
    file_actions = ['get_file', 'get_event_file']
    date_time_param = ["firstSeen", "lastSeen", "firstSeenFrom", "firstSeenTo", "lastSeenFrom", "lastSeenTo",
                       "createdBefore", "createdAfter", "updatedBefore", "updatedAfter"]
    persistence_data_action = {"Delete Key": "DeleteKey",
                               "Delete Value": "DeleteValue",
                               "Update": "Update"}

    def __init__(self, config):
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl')
        self.host = config.get('server_url').strip('/')
        if self.host[:7] == "http://":
            self.host = "https://{0}{1}".format(self.host, self.API_PREFIX)
        elif self.host[:8] == "https://":
            self.host = "{0}{1}".format(self.host, self.API_PREFIX)
        else:
            self.host = "https://{0}{1}".format(self.host, self.API_PREFIX)

    def authenticate(self):
        try:
            endpoint = "/events/list-events"
            request_url = "{0}{1}".format(self.host, endpoint)
            request_headers = {
                "Accept": "application/json",
                "content-type": "application/json; charset=utf-8"
            }

            response = requests.get(request_url,
                                    headers=request_headers,
                                    auth=(self.username, self.password),
                                    verify=self.verify_ssl)

            if response.status_code == 200:
                self.token = response.headers['X-Auth-Token']

                return self.token
            else:
                response.raise_for_status()
        except Exception as e:
            raise e

    def make_rest_api_call(self, action_details, headers, payload=None, stream=False, data=None):
        try:
            response = None
            request_url = "{0}{1}".format(self.host, action_details["endpoint"])

            if action_details["http_method"] == 'GET':
                response = requests.get(request_url,
                                        headers=headers,
                                        params=payload,
                                        stream=stream,
                                        verify=self.verify_ssl)

            elif action_details["http_method"] == 'PUT':
                response = requests.put(request_url,
                                        headers=headers,
                                        params=payload,
                                        data=data,
                                        verify=self.verify_ssl)

            elif action_details["http_method"] == 'POST':
                response = requests.post(request_url,
                                         headers=headers,
                                         params=payload,
                                         data=data,
                                         verify=self.verify_ssl)

            elif action_details["http_method"] == 'DELETE':
                response = requests.delete(request_url,
                                           headers=headers,
                                           params=payload,
                                           data=data,
                                           verify=self.verify_ssl)

            if response.ok:
                return response

            else:
                response_error = None
                try:
                    logger.debug("Requested URL: {0}".format(response.url))
                    err_dict = json.loads(response.text)
                    if 'message' in err_dict:
                        response_error = err_dict['message']
                    elif 'errorMessage' in err_dict:
                        response_error = err_dict['errorMessage']
                    error_msg = '{0} Response [{1}:{2}]'.format(action_details['title'],
                                                                response.status_code, response_error)
                except:
                    if action_details["operation"] in ["get_file", "get_event_file"]:
                        error_msg = "Error:Response Code: {0}:".format(response.status_code)
                    else:
                        error_msg = "Error:Response Code: {0} Response:{1}".format(response.status_code, response.text)

                logger.error(error_msg)
                raise ConnectorError(error_msg)

        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error(str(err))
            raise ConnectorError(str(err))

    def build_headers(self, action):
        stream = False

        encode_creds = "{0}:{1}".format(self.username,self.password).encode("ascii")
        creds = base64.b64encode(encode_creds).decode("ascii")
        headers = {'Authorization': 'Basic {0}'.format(creds)}

        if action == "get_raw_json_event_data":
            return headers, stream

        headers['Content-Type'] = 'application/json; charset=utf-8'
        if action in self.file_actions:
            headers['Accept'] = 'application/octet-stream'
            stream = True
        else:
            headers['Accept'] = 'application/json'

        return headers, stream

    def build_response(self, response, operation, params):
        logger.debug("Requested URL: {0}".format(response.url))
        if operation in self.file_actions:
            if operation == "Get File":
                fpath = params.get("filePaths")
                temp_name = "collector_{0}_file.zip".format(params.get("device"))
                temp_description = "FortiEDR: File {0} has been retrieved from the collector {1}".format(fpath, params.get("device"))
            else:
                temp_name = "memdump_{0}.zip".format(params.get("rawEventId"))
                temp_description = "FortiEDR: Collected memory dump for raw event {0}".format(params.get("rawEventId"))

            file_details = {
                "file_name": "{0}".format(temp_name),
                "file_description": temp_description
            }
            temp_path = _save_file(temp_name, response)
            attachment_resp = handle_upload_file_to_cyops(file_details, temp_path)
            return attachment_resp
        if operation == "count_events":
            response = response.json()
            return {"event_count": response}
        if operation == "search":
            response = response.json()
            hash_list = []
            for key in response:
                resp = {"filehash": key}
                resp.update(response.get(key))
                hash_list.append(resp)
            return hash_list
        else:
            if response.text != "":
                return response.json()
            else:
                return {"result": "Successfully executed {0}".format(operation)}

    def intersection(self, lst1, lst2):
        lst3 = [value for value in lst1 if value in lst2]
        return lst3

    def update_date_time(self, payload, res):
        for item in res:
            date_ts = payload[item]
            try:
                conv_date_time = datetime.strptime(date_ts, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
            except:
                conv_date_time = datetime.strptime(date_ts, '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%Y-%m-%d %H:%M:%S")
            payload[item] = str(conv_date_time)
        return payload

    def build_payload(self, params, operation):
        logger.debug("Input Params: {0}".format(params))
        payload = {k: v for k, v in params.items() if v is not None and v != ''}

        if operation in self.file_actions:
            if "retrieve_from" in payload:
                if payload["retrieve_from"] == "Disk":
                    payload['disk'] = True
                    payload['memory'] = False
                else:
                    payload['disk'] = False
                    payload['memory'] = True
                payload.pop("retrieve_from")
            logger.debug("Query Params: {0}".format(payload))
            return payload

        res = self.intersection(payload.keys(), self.date_time_param)
        if res.__len__() != 0:
            payload = self.update_date_time(payload, res)

        if "type" in payload:
            payload.pop("type")
        if "remediate_action" in payload:
            payload["persistenceDataAction"] = self.persistence_data_action.get(payload.get("persistenceDataAction"))
            payload.pop("remediate_action")
        if "sorting" in payload:
            payload["sorting"] = json.dumps(payload["sorting"])
        if "organization" in payload:
            if payload["organization"] == "Exact Organization Name":
                payload["organization"] = payload.get("org_name")
                payload.pop("org_name")
        logger.debug("Payload: {0}".format(payload))
        return payload

    def convert_str_list(self, param):
        param_list = list(map(lambda x: x.strip(' '), param.split(','))) if isinstance(param, str) else param
        return param_list


def check_health_ex(config):
    try:
        client = FortiEDRClient(config)
        token = client.authenticate()
        return True

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def upload_file_to_cyops(file_name, file_content, file_description):
    try:
        # Conditional import based on the FortiSOAR version.
        try:
            from integrations.crudhub import make_file_upload_request
            response = make_file_upload_request(file_name, file_content, 'application/octet-stream')

        except:
            from cshmac.requests import HmacAuth
            from integrations.crudhub import maybe_json_or_raise
            from requests import post

            url = settings.CRUD_HUB_URL + '/api/3/files'
            auth = HmacAuth(url, 'POST', settings.APPLIANCE_PUBLIC_KEY,
                            settings.APPLIANCE_PRIVATE_KEY,
                            settings.APPLIANCE_PUBLIC_KEY.encode('utf-8'))
            files = {'file': (file_name, file_content, {'Expire': 0})}
            response = post(url, auth=auth, files=files, verify=False)
            response = maybe_json_or_raise(response)

        logger.info('File upload complete {0}'.format(str(response)))
        file_id = response['@id']
        attach_response = make_request('/api/3/attachments', 'POST',
                                       {'name': file_name, 'file': file_id, 'description': file_description })
        logger.info('attach file completed: {0}'.format(attach_response))
        return attach_response
    except Exception as err:
        logger.exception('An exception occurred {0}'.format(str(err)))
        raise ConnectorError('An exception occurred {0}'.format(str(err)))


def handle_upload_file_to_cyops(file_details, file_path):
    try:
        file_name = file_details.get("file_name")
        file_description = file_details.get("file_description")
        file_content = open(file_path, "rb")
        attach_response = upload_file_to_cyops(file_name, file_content, file_description)
        logger.debug('{0}'.format(str(type(attach_response))))
        os.remove(file_path)
        return attach_response
    except Exception as err:
        os.remove(file_path)
        logger.exception('An exception occurred {0}'.format(str(err)))
        raise ConnectorError('An exception occurred {0}'.format(str(err)))


def _save_file(filename, response):
    tmp_path = TMP_LOC
    if not os.path.isdir(tmp_path):
        os.mkdir(tmp_path)
    with open("{0}/{1}".format(tmp_path, filename), "wb") as file_to_write:
        for chunk in response.iter_content(chunk_size=512):
            file_to_write.write(chunk)
        file_to_write.close()
    return "{0}/{1}".format(tmp_path, filename)


def get_current_operation(info_json, action):
    try:
        operation_info = info_json.get('operations')
        exec_action = [action_info for action_info in operation_info if action_info['operation'] == action]
        return exec_action[0]

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def api_request(config, params, action):
    try:
        client = FortiEDRClient(config)
        payload = client.build_payload(params, action["operation"])
        headers, stream = client.build_headers(action["operation"])
        response = client.make_rest_api_call(action, headers, payload, stream)

        return client.build_response(response, action["operation"], params)

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_event(config, params, action):
    try:
        body_param = ['mute', 'handle', 'archive', 'comment', 'classification', 'read', 'muteDuration', 'forceUnmute']
        client = FortiEDRClient(config)
        body_param_dict ={}
        payload = client.build_payload(params, action["operation"])
        for item in body_param:
            if item in payload:
                body_param_dict[item] = payload[item]
                payload.pop(item)

        if payload.get("update_fields"):
            payload.pop("update_fields")

        headers, stream = client.build_headers(action["operation"])
        response = client.make_rest_api_call(action, headers, payload, stream, json.dumps(body_param_dict))
        return client.build_response(response, action["operation"], params)

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_exception(config, params, action):
    try:
        client = FortiEDRClient(config)

        payload = client.build_payload(params, action["operation"])
        exception_json = payload.get("exceptionJson")

        if exception_json == None or exception_json == '':
            msg = "Action {0}: Missing JSON inputs for exception".format(action["operation"])
            logger.error("{0}".format(str(msg)))
            raise ConnectorError("{0}".format(str(msg)))

        payload.pop("exceptionJson")
        headers, stream = client.build_headers(action["operation"])
        response = client.make_rest_api_call(action, headers, payload, stream, json.dumps(exception_json))

        return {"result": response.text}

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_exception(config, params, action):
    try:
        client = FortiEDRClient(config)
        # Fetch the rawItemIds from Event ID provided by user
        temp_params = {
            "eventId": params.get("eventId")
        }
        temp_action = {
            "endpoint": "/events/list-raw-data-items",
            "http_method": "GET",
            "title": "Get Raw Data Items",
            "operation": "get_raw_data_items"
        }

        payload = client.build_payload(temp_params, temp_action["operation"])
        headers, stream = client.build_headers(temp_action["operation"])
        raw_response = client.make_rest_api_call(temp_action, headers, payload, stream)
        raw_response = raw_response.json()

        # Fetch exception details
        temp_params = {
            "organization": params.get("organization"),
            "rawItemIds": raw_response[0].get("rawEventId")
        }

        temp_action = {
            "endpoint": "/events/export-raw-data-items-json",
            "http_method": "GET",
            "title": "Get Raw JSON Event Data",
            "operation": "get_raw_json_event_data"
        }
        payload = client.build_payload(temp_params, temp_action["operation"])
        headers, stream = client.build_headers(temp_action["operation"])
        response = client.make_rest_api_call(temp_action, headers, payload, stream)

        payload = client.build_response(response, temp_action["operation"], temp_params)

        existing_exception = payload.get("Exceptions").copy()
        input_exception_id = params.get("exceptionId")
        destination = params.get("destination")
        all_destination = False
        if destination == "All Destinations":
            all_destination = True

        if(len(existing_exception)):
            curr_time = round(time.time() * 1000)
            for exception in existing_exception:
                exception_id = exception.get("ExceptionId")
                if int(input_exception_id) == int(exception_id):
                    input_ip_sets = client.convert_str_list(params.get("ip_set_name"))
                    if input_ip_sets is None:
                        input_ip_sets = []
                    if all_destination == False and len(input_ip_sets) >= 1 :
                        # Here append the ip_groups to the existing one.
                        ip_group = exception.get("IpGroups")
                        # to overwrite the ip_groups uncomment the below.
                        # ip_group = []
                        for ipset in input_ip_sets:
                            ip_group.append({"Name": ipset, "updateTime": curr_time})
                        exception["IpGroups"] = ip_group
                        exception["AllDestinations"] = False
                    else:
                        exception["AllDestinations"] = all_destination

                    collector_grp = params.get('collector_grp')
                    if collector_grp == "All Groups":
                        exception["AllAgentGroups"] = True
                        exception["AllAccountsAgentGroups"] = False

                    elif collector_grp == "All Organizations":
                        exception["AllAccountsAgentGroups"] = True
                        exception["AllDestinations"] = True
                        exception["AllAgentGroups"] = False

                    elif collector_grp == "Exact Collector Group":
                        collector_groups = client.convert_str_list(params.get('collector_group'))
                        if len(collector_groups) >= 1:
                            # Here append the input_AgentGroups to the existing one.
                            input_agent_groups = exception.get('AgentGroups')
                            # to overwrite the input_AgentGroups uncomment the below.
                            # input_agent_groups = []
                            for CG in collector_groups:
                                input_agent_groups.append({"Name": CG})
                            exception["AgentGroups"] = input_agent_groups
                            exception["AllAgentGroups"] = False
                            exception["AllAccountsAgentGroups"] = False

                    comment = params.get("comment")
                    if comment and len(comment) >= 1:
                        existing_comment = exception.get("Comment")
                        if existing_comment:
                            exception["Comment"] = existing_comment[:1] + comment + existing_comment[1:]
                        else:
                            exception["Comment"] = comment

                    payload = existing_exception[0]

                    data = payload
                    temp_params.pop("rawItemIds")
                    temp_params["confirmEdit"] = True

                    payload_new = client.build_payload(temp_params, action["operation"])
                    headers, stream = client.build_headers(action["operation"])
                    action["endpoint"] = "/exceptions/create-or-edit-exception"
                    resp = client.make_rest_api_call(action, headers, payload_new, stream, json.dumps(data))
                    return resp.json()
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_ipset(config, params, action):
    try:
        client = FortiEDRClient(config)
        include = client.convert_str_list(params.get("include"))
        params["include"] = include
        exclude = client.convert_str_list(params.get("exclude"))
        params["exclude"] = exclude
        org_type = params.get("organization")

        if org_type == "Exact Organization Name":
            params["organization"] = params.get("org_name")
            params.pop("org_name")

        elif org_type == "All Organizations":
            params["organization"] = "All organizations"

        elif org_type == "Each":
            params["organization"] = "each"

        data = client.build_payload(params, action["operation"])
        headers, stream = client.build_headers(action["operation"])
        response = client.make_rest_api_call(action, headers, stream=stream, data=json.dumps(data))

        return {"result": "Successfully created {0} IP set".format(params.get("name"))}

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_list(existing_list: list, input_list: list, add_remove:bool = True ):
    if add_remove:
        res = existing_list + input_list
        res_list = set(res)
        return list(res_list)
    else:
        [existing_list.remove(x) for x in input_list if x in existing_list]
        return existing_list


def update_ipset(config, params, action):
    try:
        client = FortiEDRClient(config)
        include = client.convert_str_list(params.get("include"))
        exclude = client.convert_str_list(params.get("exclude"))
        if len(include) == 0 and len(exclude) == 0:
            msg = "Both the include and exclude inputs are blank".format(params["name"])
            logger.error("{0}".format(str(msg)))
            raise ConnectorError("{0}".format(str(msg)))

        org_type = params.get("organization")
        add_items = params["add_items"]
        found_ipset = False
        temp_params = {}

        if org_type == "Exact Organization Name":
            params["organization"] = params.get("org_name")
            temp_params["organization"] = params.get("org_name")
            params.pop("org_name")

        elif org_type == "All Organizations":
            params["organization"] = "All organizations"
            temp_params["organization"] = "All organizations"

        elif org_type == "Each":
            params["organization"] = "each"
            temp_params["organization"] = "All organizations"

        params.pop("add_items")

        # API overwrites the existing list of include and exclude/include IP's So we will first get the list of the IP set
        # then will append the new IP's
        temp_action = {
            "endpoint": "/ip-sets/list-ip-sets",
            "http_method": "GET",
            "title": "Get Raw JSON Event Data",
            "operation": "get_raw_json_event_data"
        }

        payload = client.build_payload(temp_params, temp_action["operation"])
        headers, stream = client.build_headers(temp_action["operation"])
        response = client.make_rest_api_call(temp_action, headers, payload, stream)
        res = response.json()

        for item in res:
            if item["name"] == params["name"] :
                include_ex = item["include"]
                exclude_ex = item["exclude"]
                if include_ex:
                    params["include"] = update_list(include_ex, include, add_items)
                if exclude_ex:
                    params["exclude"] = update_list(exclude_ex, exclude, add_items)
                found_ipset = True
                break

        if not found_ipset:
            msg = "Failed to locate the provided IP SET. IP Set name [{}] not found".format(params["name"])
            logger.error("{0}".format(str(msg)))
            raise ConnectorError("{0}".format(str(msg)))

        data = client.build_payload(params, action["operation"])
        param = {"organization": data.get("organization")}
        data.pop("organization")
        headers, stream = client.build_headers(action["operation"])
        response = client.make_rest_api_call(action, headers, payload=param,  stream=stream, data=json.dumps(data))
        return {"result": "Successfully Updated {0} IP set".format(params.get("name"))}

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_event_list_extended(config, params, operation_info):
    try:
        # Fetch Archived events.
        params["archived"] = True
        result_archived = api_request(config, params, operation_info)
        # Fetch un-archived events.
        params["archived"] = False
        result_unarchived = api_request(config, params, operation_info)
        # combined the result
        result = result_archived + result_unarchived
        return result
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


fortiedr_ops = {
    'create_exception': create_exception,
    'update_event': update_event,
    'update_exception': update_exception,
    'create_ipset': create_ipset,
    'update_ipset': update_ipset,
    'get_event_list_extended': get_event_list_extended
}
