import json, ast, arrow, io
from requests import request, post ,exceptions as req_exceptions
from xmljson import parker
from xml.etree.ElementTree import fromstring
from datetime import datetime
from collections import defaultdict
from connectors.core.connector import get_logger, ConnectorError
from cshmac.requests import HmacAuth
from django.conf import settings
from integrations.crudhub import maybe_json_or_raise
from .symbol_table import *
from .symtab import param_details_symtab

logger = get_logger('qualys')

tmp_list = ['select', 'multiselect', 'checkbox']
handle_report = ['fetch_report']


def get_config(config):
    if config:
        server_url = config.get('server_url')
        username = config.get('username')
        password = config.get('password')
        verify_ssl = config.get('verify_ssl')

        if not server_url.startswith('https://'):
            server_url = 'https://' + server_url
            return server_url, username, password, verify_ssl
        else:
            return server_url, username, password, verify_ssl


def _make_request(url, method, body=None):
    bodyless_methods = ['head', 'get']
    if method.lower() in bodyless_methods:
        body = None
    if type(body) == str:
        try:
            body = ast.literal_eval(body)
        except Exception:
            pass
    url = settings.CRUD_HUB_URL + url
    logger.info('Starting request: {0} , {1}'.format(method, url))
    auth = HmacAuth(url, method, settings.APPLIANCE_PUBLIC_KEY, settings.APPLIANCE_PRIVATE_KEY, json.dumps(body))
    response = request(method, url, auth=auth, json=body, verify=False)
    return response.content


def handle_upload_file_to_cyops(file_name, file_content, file_type):
    try:
        url = settings.CRUD_HUB_URL + '/api/3/files'
        auth = HmacAuth(url, 'POST', settings.APPLIANCE_PUBLIC_KEY,
                        settings.APPLIANCE_PRIVATE_KEY,
                        settings.APPLIANCE_PUBLIC_KEY.encode('utf-8'))
        files = {'file': (file_name, file_content, file_type, {'Expire': 0})}
        response = post(url, auth=auth, files=files, verify=False)
        response = maybe_json_or_raise(response)
        logger.info('File upload complete {}'.format(str(response)))
        file_id = response['@id']
        file_description = file_name
        attach_response = _make_request('/api/3/attachments', 'POST',
                                        {'name': file_name, 'file': file_id, 'description': file_description})
        logger.info('attach file complete: {}')
        logger.info('{}'.format(str(type(attach_response))))
        return json.loads(attach_response.decode('utf-8'))
    except Exception as err:
        logger.exception('An exception occurred {}'.format(str(err)))
        raise ConnectorError('An exception occurred {}'.format(str(err)))


def handle_password(value, ref):
    return value


def handle_text(value, ref):
    if isinstance(value, list):
        value = ','.join(str(item) for item in value)
    return value


def handle_datetime(value, ref):
    try:
        date = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%dT%H:%M:%SZ')
        return date
    except Exception as err:
        logger.error("handle_datetime: {0}".format(err))
        raise ConnectorError("handle_datetime: {0}".format(err))


def handle_integer(value, ref):
    if isinstance(value, list):
        value = ','.join(str(item) for item in value)
    return value


def handle_select(value, ref):
    try:
        if value != '':
            value_ref = ref.get(value)
            if value_ref == None:
               return str(value_ref)
            return value_ref
        else:
            return value
    except Exception as err:
        logger.error("handle_select: {0}".format(err))
        raise ConnectorError("handle_select: {0}".format(err))


def handle_multiselect(values, ref):
    temp = []
    try:
        if values is None:
            values = ''
            return values
        if type(values) != str:
            for value in values:
                ref_value = ref.get(value)
                temp.append(ref_value)
        else:
            temp.append(ref.get(values))

        value_str = ','.join(temp)
        return value_str
    except Exception as err:
        logger.error("handle_multiselect: {0}".format(err))
        raise ConnectorError("handle_multiselect: {0}".format(err))


def handle_bool(value, ref):
    try:
        if value:
            value_ref = ref.get("true")
        else:
            value_ref = ref.get("false")
        return value_ref
    except Exception as err:
        logger.error("handle_bool: {0}".format(err))
        raise ConnectorError("handle_bool: {0}".format(err))


def handle_onchange(sel_op, param, params):
    q_param = {}
    try:
        ref_param = param.get(sel_op)
        if ref_param:
            for x in ref_param:
                q_param_name = x['name']
                handle_ref = handle_datatype.get(x['type'])
                value = handle_ref(params.get(q_param_name),
                                   x['option'] if x['type'] in tmp_list else handle_ref(params.get(q_param_name), None))
                if value != -9 and value != "":
                    q_param[q_param_name] = value
        return q_param
    except Exception as err:
        logger.error("handle_onchange: {0}".format(err))
        raise ConnectorError("handle_onchange: {0}".format(err))


def handle_ordered_dict(data, *args):
    try:
        if args and data:
            element = args[0]
            if element:
                value = data.get(element)
                return value if len(args) == 1 else handle_ordered_dict(value, *args[1:])
    except Exception as err:
        logger.error("handle_ordered_dict: {0}".format(err))
        raise ConnectorError("handle_ordered_dict: {0}".format(err))


def extract_param_details(action, params):
    try:
        query_params = {}
        req_param_meta = param_details_symtab.get(action)
        for param in req_param_meta:
            if param:
                if 'onchange' in param:
                    re_qparam = optional_param_symtab[action]
                    if param.get('name') in re_qparam:
                        query_params[param.get('name')] = handle_select(params.get(param.get('name'), ''),
                                                                        param.get('option'))
                    else:
                        pass
                    value = params.get(param.get('name'), '')
                    qparams = handle_onchange(value, param['onchange'], params)
                    query_params.update(qparams)
                else:
                    value = params.get(param.get('name'), '')
                    if value != '':
                        handle_ref = handle_datatype.get(param.get('type'))
                        value = handle_ref(value, param.get('option')) if param.get('type') in tmp_list else handle_ref(
                            value, None)
                        if value != -9 and value != "":
                            query_params[param.get('name')] = value
        return query_params
    except Exception as err:
        logger.error("extract_param_details: {0}".format(err))
        raise ConnectorError(err)


def build_query_params(action, params):
    try:
        query_params = extract_param_details(action, params)

        req_params = required_param_symtab.get(action)

        if req_params:
            for item in req_params:
                query_params.setdefault(item[0], item[1])

        return query_params

    except Exception as err:
        logger.error("build_query_params: {0}".format(err))
        raise ConnectorError(err)


def build_response(action, json_response):
    """
    This function is required to handle multi-option/dynamic output schema.
    As of now there no functionality for it.
    :param action: the operation for which the output schema needed
    :param json_response: response of the operation
    :return: the dict of the items by referring to output_symtab
    """
    try:
        logger.info("Building output response")
        keys = output_symtab[action]
        for item in keys:
            if len(item) == 3:
                inter_dict = json_response[item[0]][item[1]][item[2]]
                key_test = item[2]
                if isinstance(inter_dict, dict):
                    resp = defaultdict(list)
                    resp[key_test].append(inter_dict)
                    json_response[item[0]][item[1]] = resp
            else:
                inter_dict = json_response[item[0]][item[1]]
                key_test = item[1]
                if isinstance(inter_dict, dict):
                    resp = defaultdict(list)
                    resp[key_test].append(inter_dict)
                    json_response[item[0]] = resp

        return json_response
    except Exception as err:
        logger.error("build_response: {0}".format(err))
        raise ConnectorError(err)


def upload_report(action, response):
    try:
        filename = None
        content = None
        file_type = None
        try:
            # As of now we will keep this(json_response = response.json())
            # if removed then need to change the rest of the logic.
            # For Fetch VM : As response itself return json data no need to convert it again to json

            json_response = response.json()
            json_response = response.text
            filename = "Qualys Vulnerability Scan Result {}Z.json".format(str(arrow.now().format('YYYY-MM-DDTHH:mm:ss')))
            content = io.StringIO(json_response)
            file_type = "json"
        except:
            try:
                result = dict((key, value) for key, value in response.raw._original_response.headers._headers)
                filename = (result.get('Content-Disposition')).split("filename=",1)[1]
                file_type = result.get('Content-Type')
                content = response.content
            except:
                if str(response.content).startswith("<?xml", 2):
                    raw_data = parker.data(fromstring(response.content))
                    raw_response = raw_data.get('RESPONSE')
                    if raw_response.get('CODE') == 7001:
                        error_string = "Error occured with error code " + str(raw_data['RESPONSE']['CODE']) + ":" + \
                                       raw_data['RESPONSE']['TEXT']
                        logger.error(error_string)
                        raise ConnectorError(error_string)
                    content_arg = content_symtab[action]
                    if content_arg:
                        json_response = handle_ordered_dict(raw_data, *content_arg)
                        if json_response and action != "list_vulnerability":
                            filename = 'Qualys {0} {1}.{2}'.format(json_response['HEADER']['NAME'],
                                                                   json_response['HEADER']['GENERATION_DATETIME'], "json")
                        else:
                            filename = "Qualys Vulnerabilities {}Z.json".format(str(arrow.now().format('YYYY-MM-DDTHH:mm:ss')))
                        content = io.StringIO(json.dumps(json_response))
                    file_type = "json"

        logger.info("creating attachment start")
        upload_response = handle_upload_file_to_cyops(filename, content, file_type)
        return upload_response
    except Exception as err:
        raise ConnectorError(str(err))


def api_request(config, params, action):
    """
    Common handler for all HTTP requests.
    """
    try:
        param_dict = None
        data = None
        server_url, username, password, verify_ssl = get_config(config)

        headers = {'X-Requested-With': 'CyberSponse'}
        query_data = build_query_params(action, params)
        if http_method_symtab.get(action) == 'GET':
            param_dict = query_data
        else:
            data = query_data
        endpoint = server_url + api_symtab[action]
        try:
            response = request(http_method_symtab[action], endpoint, headers=headers, auth=(username, password),
                               params=param_dict, data=data, verify=verify_ssl)

            if response.status_code == 200 or response.status_code == 202:
                if action in handle_report or params.get('add_vuln_as_attachment', False):
                    return upload_report(action, response)
                elif action == "fetch_vm_scan":
                    return {"result": response.json()}
                raw_response = parker.data(fromstring(response.content))
                content_arg = content_symtab[action]
                if content_arg:
                    order_dict_response = handle_ordered_dict(raw_response, *content_arg)
                    json_response = json.loads(json.dumps(order_dict_response))
                    try:
                        return build_response(action, json_response)
                    except Exception as err:
                        return json_response
                return raw_response
            else:
                raw_response = parker.data(fromstring(response.content))['RESPONSE']
                logger.error('{0} Response [{1}:{2}] Error Code: {3} Details: {4}'.format(action, response.status_code,
                                                                                          response.reason,
                                                                                          raw_response.get('CODE'),
                                                                                          raw_response.get('TEXT')))
                raise ConnectorError(
                    '{0} Response [{1}:{2}] Error Code: {3} Details: {4}'.format(action, response.status_code,
                                                                                 response.reason, raw_response.get('CODE'),
                                                                                 raw_response.get('TEXT')))
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

    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def check_health_ex(config):
    try:
        if api_request(config, params={"state": "Finished"}, action='list_report'):
            return True
    except Exception as err:
        raise ConnectorError(str(err))

# Reference to the data type handlers.

handle_datatype = {
    "text": handle_text,
    "datetime": handle_datetime,
    'integer': handle_integer,
    "select": handle_select,
    "multiselect": handle_multiselect,
    "checkbox": handle_bool,
    "onchange": handle_onchange,
    "password": handle_password
}
