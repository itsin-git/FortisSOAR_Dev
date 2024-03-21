""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import ipaddress
import json
from urllib.parse import quote_plus
import requests

from connectors.core.connector import get_logger, ConnectorError

from .constants import *
from .constants import SYSTEM_EVENTS

logger = get_logger('fortigate-firewall')


def generate_dict_from_list(input_val):
    final_lst = []
    if input_val == '' or input_val == []:
        return final_lst
    if isinstance(input_val, str):
        input_val = list(map(lambda x: x.strip(' '), input_val.split(",")))
    if isinstance(input_val, list):
        for name in input_val:
            final_lst.append({'name': name})
    return final_lst


def get_final_lst(params, prev_response, param_name, add_param, remove_param):
    try:
        tmp_lst = []
        member_list = prev_response[0].get(param_name)
        for item in member_list:
            tmp_lst.append(item.get('name'))
        if params.get(add_param):
            add_mem_lst = _get_list_from_str_or_list(params, add_param)
            member_list = tmp_lst + list(set(add_mem_lst) - set(tmp_lst))
        if params.get(remove_param):
            remove_mem_lst = _get_list_from_str_or_list(params, remove_param)
            for mem in remove_mem_lst:
                if mem in tmp_lst:
                    tmp_lst.remove(mem)
            member_list = tmp_lst
        return member_list
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def _get_config(config):
    address = config.get('address', None).strip('/')
    api_key = config.get("api_key")
    port = config.get('port', None)
    verify_ssl = config.get("verify_ssl", None)
    server_url = '{0}:{1}'.format(address, port)
    if server_url[:7] != 'http://' and server_url[:8] != 'https://':
        server_url = 'https://{}'.format(str(server_url))
    return server_url, api_key, verify_ssl


def _api_request(config, url, header=None, body=None, parameters={}, method='get'):
    try:
        server_url, api_key, verify_ssl = _get_config(config)
        parameters.update({'access_token': api_key})
        logger.debug('body = {}'.format(body))
        url = server_url + url
        logger.debug('{} url: {}'.format(method, url))
        api_response = requests.request(method, url=url, data=json.dumps(body), headers=header, params=parameters,
                                        verify=verify_ssl)
        logger.debug('api_response: {}'.format(api_response.status_code))
        if api_response.ok:
            return api_response.json()
        elif api_response.status_code == 403:
            api_response = api_response.json()
            vdom_not_exist = list(filter(lambda x: x.get('status') == 'error',
                                         api_response if isinstance(api_response, list) else [api_response]))
            result = list(filter(lambda x: x.get('status') == 'success',
                                 api_response if isinstance(api_response, list) else [api_response]))
            return {'vdom_not_exist': vdom_not_exist, 'result': result}
        elif api_response.status_code == 404:
            logger.error('{0}. Response is : {1}'.format(RESOURCE_NOT_FOUND, str(api_response.text)))
            raise ConnectorError('{0}. Response is : {1}'.format(RESOURCE_NOT_FOUND, str(api_response.text)))
        elif api_response.status_code == 500:
            tmpf = api_response.json()
            if str(api_response.json().get('http_status')) == '500' and str(api_response.json().get('error')) == '-5':
                logger.error(
                    'Fail to request API {0}, Possibly because of input resource name already exists. Response is {1}'
                    .format(str(url), api_response.text))
                raise ConnectorError(
                    'Fail to request API {0}, Possibly because of input resource name already exists. Response is {1}'
                    .format(str(url), api_response.text))
            else:
                logger.error('Fail to request API {0} Response is : {1}'.format(str(url), str(api_response.text)))
                raise ConnectorError('Fail to request API {0} Response is : {1}'.format(str(url),
                                                                                        str(api_response.text)))
        else:
            logger.error('Fail to request API {0} Response is : {1}'.format(str(url), str(api_response.text)))
            raise ConnectorError('Fail to request API {0} Response is : {1}'.format(str(url),
                                                                                    str(api_response.text)))
    except requests.exceptions.SSLError:
        raise ConnectorError(SSL_VALIDATION_ERROR)
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError(CONNECTION_TIMEOUT)
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(REQUEST_READ_TIMEOUT)
    except requests.exceptions.ConnectionError:
        raise ConnectorError(INVALID_URL_OR_CREDENTIALS)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _get_vdom(config, params, check_multiple_vdom=False):
    try:
        vdom = []
        try:
            vdom = _get_list_from_str_or_list(params, "vdom")
        except Exception as e:
            logger.debug('vdom not provided as param. Check config vdom.')
        if not vdom:
            try:
                vdom = _get_list_from_str_or_list(config, "vdom")
            except Exception as e:
                logger.debug('VDOM not provided as config.')
        if check_multiple_vdom:
            if len(vdom) > 1:
                logger.error("Action is not supported for multiple vdom.")
                raise ConnectorError("Action is not supported for multiple vdom.")
        return vdom
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)


def _validate_vdom(config, params, check_multiple_vdom=True):
    vdom_list = _get_vdom(config, params, check_multiple_vdom=check_multiple_vdom)
    querystring = {}
    if vdom_list:
        querystring.update({'vdom': ','.join(vdom_list)})
    try:
        response = _api_request(config, LIST_VDOM, parameters=querystring)
        list_vdom = response.get('result') if 'result' in response else response
        list_vdom = [list_vdom] if isinstance(list_vdom, dict) else list_vdom
        vdom_names = [i.get('vdom') for i in list_vdom]
        vdom_not_exists = response.get('vdom_not_exist') if 'vdom_not_exist' in response else []
        if len(vdom_not_exists) != 0 and len(vdom_not_exists) == len(vdom_list):
            logger.exception('Given VDOM {} not exists.'.format(','.join(vdom_list)))
            raise ConnectorError('Given VDOM {} not exists.'.format(','.join(vdom_list)))
        return vdom_names, vdom_not_exists
    except Exception as e:
        logger.error("{}".format(str(e)))
        if '401' in str(e):
            logger.error(UNAUTH_MSG)
            raise ConnectorError(UNAUTH_MSG)
        raise ConnectorError(e)


def _get_list_from_str_or_list(params, parameter, is_ip=False):
    try:
        parameter_list = params.get(parameter)
        if parameter_list:
            if isinstance(parameter_list, str):
                parameter_list = list(map(lambda x: x.strip(' '), parameter_list.split(",")))
            elif isinstance(parameter_list, list):
                parameter_list = parameter_list
            if is_ip:
                for ip in parameter_list:
                    if ' ' in ip:
                        tmp_ip = ip.split(' ')
                        if len(tmp_ip) == 2:
                            try:
                                ipaddress.ip_network(tmp_ip[0], False)
                                ipaddress.ip_network(tmp_ip[1], False)
                            except Exception as Err:
                                logger.error(str(Err))
                                raise ConnectorError(str(Err))
                    else:
                        try:
                            ipaddress.ip_network(ip, False)
                        except Exception as Err:
                            logger.error(str(Err))
                            raise ConnectorError(str(Err))
            return parameter_list
        else:
            return []
    except Exception as Err:
        raise ConnectorError(Err)


def get_address_grp(config, ip_group_name, vdom, Flag=False, type=''):
    querystring = {}
    if vdom:
        querystring.update({'vdom': ','.join(vdom)})
    if 'IPv4' in type:
        url = ADDRESS_GROUP_API
    else:
        url = ADDRESS_GROUP_API_IPv6
    response = _api_request(config, url.format(ip_group_name=ip_group_name.replace('/', '%2f')), parameters=querystring)
    if response.get('results') and 'member' not in response.get('results')[0]:
        logger.error("Check Firewall Address permission to read group member.")
        return True
    if Flag:
        return response
    blocked_ips = response.get('results')[0].get('member', [])
    return list(map(lambda x: x.get('name'), blocked_ips))


def get_address(ip_addr, config, querystring, ip_type='IPv4'):
    try:
        if ip_type == 'IPv4':
            if '/' in ip_addr:
                ip_addr = ip_addr.split('/')[0]
            endpoint = "{0}?datasource=1&with_meta=1&filter=subnet=@{1}".format(ADD_ADDRESS, ip_addr)
            response = _api_request(config, endpoint, parameters=querystring, method='GET')
            result = response["results"]
        else:
            addr = ipaddress.ip_network(ip_addr, False)
            endpoint = "{}?datasource=1&with_meta=1&filter=ip6=@{}"
            resp_input_exploded = _api_request(config, endpoint.format(ADD_ADDRESS_IPv6, addr.exploded),
                                               parameters=querystring)
            resp_input_compressed = _api_request(config, endpoint.format(ADD_ADDRESS_IPv6, addr.compressed),
                                               parameters=querystring)
            resp_input = _api_request(config, endpoint.format(ADD_ADDRESS_IPv6, ip_addr), parameters=querystring)
            if resp_input_exploded.get('results') != []:
                result = resp_input_exploded['results']
            elif resp_input_compressed.get('results') != []:
                result = resp_input_compressed['results']
            else:
                result = resp_input.get('results')
        ip_recs = []
        if len(result):
            for item in result:
                temp = {"name": item.get("name")}
                ip_recs.append(temp)

        return ip_recs if ip_recs.__len__() > 0 else None
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def add_bulk_address(config, vdom, ip_list, type=''):
    try:
        querystring = {}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if vdom:
            querystring.update({'vdom': ','.join(vdom)})
        if 'IPv4' in type:
            endpoint = ADD_ADDRESS
        else:
            endpoint = ADD_ADDRESS_IPv6
        result = []
        for ip_addr in ip_list:
            if 'IPv4' in type:
                payload = {"name": ip_addr, "subnet": ip_addr + '/32'}
            else:
                payload = {"name": ip_addr, "ip6": ip_addr}
            try:
                response = _api_request(config, endpoint, header=headers, parameters=querystring, body=payload,
                                        method='POST')
                if response["http_status"] == 200:
                    pre_addr_obj = [payload]
                result = result + pre_addr_obj
            except Exception as err:
                logger.info('failed to create address object {0}, error is {1}'.format(payload, err))
                pass
        return result
    except Exception as Err:
        logger.error(str(Err))
        if 'Internal Server Error' in str(Err):
            logger.error('Input address already exists or failed to create address with input {} address'.
                         format(type))
            raise ConnectorError('Input address already exists or failed to create address with input {} address'.
                                 format(type))


def add_bulk_urls(config, vdom_list, url_list):
    try:
        querystring ={}
        if vdom_list:
            querystring.update({'vdom': ','.join(vdom_list)})

        for url in url_list:
            data = {"name": url, "type": "fqdn", "fqdn": url}
            try:
                response = _api_request(config, ADD_ADDRESS, parameters=querystring, body=data, method='POST')
                logger.debug('URL {} added successfully'.format(url))
            except Exception as e:
                logger.exception(str(e))
                logger.info("URL {} already exist or not invalid".format(url))
                continue
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def get_country_names(config, params):
    try:
        tmp_country_list = []
        for item in country_list:
            tmp_country_list.append(item.get('name', ''))
        return tmp_country_list
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def get_system_events(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        querystring = {}
        if vdom_list:
            querystring.update({'vdom': ','.join(vdom_list)})
        # user=*"admin", level=*"emergency", _metadata.timestamp<=*"1650965364927"

        filter_list = _get_list_from_str_or_list(params, 'filter', False)
        build_filter_query = ''
        for query_param in filter_list:
            build_filter_query = '{}&filter={}'.format(build_filter_query, quote_plus(query_param, safe='"*'))
        if len(build_filter_query) > 0:
            url = '{}?{}'.format(SYSTEM_EVENTS, build_filter_query)
        else:
            url = SYSTEM_EVENTS

        params.pop('filter', None)
        data = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        querystring.update(data)
        response = _api_request(config, url, parameters=querystring)
        return response
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))
