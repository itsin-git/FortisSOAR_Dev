""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import datetime
import json
from urllib.parse import urlencode

from OTXv2 import OTXv2, IndicatorTypes
from connectors.core.connector import ConnectorError, get_logger
from integrations.crudhub import make_request, make_file_upload_request


logger = get_logger('AlienVaultOtx')
url = ''

type_dict = {
    'IPv4': IndicatorTypes.IPv4,
    'IPv6': IndicatorTypes.IPv6,
    'Domain': IndicatorTypes.DOMAIN,
    'Email': IndicatorTypes.EMAIL,
    'Hostname': IndicatorTypes.HOSTNAME,
    'URL': IndicatorTypes.URL,
    'CVE': IndicatorTypes.CVE,
    'CIDR': IndicatorTypes.CIDR,
    'FileHash-MD5': IndicatorTypes.FILE_HASH_MD5,
    'FileHash-SHA1': IndicatorTypes.FILE_HASH_SHA1,
    'FileHash-SHA256': IndicatorTypes.FILE_HASH_SHA256
}

actions = {
    'Subscribe': 'subscribe',
    'Unsubscribe': 'unsubscribe',
    'Follow': 'follow',
    'Unfollow': 'unfollow'
}

section_dict = {
    'General': 'general',
    'Reputation': 'reputation',
    'Geo': 'geo',
    'Malware': 'malware',
    'URL List': 'url_list',
    'Passive DNS': 'passive_dns',
    'Whois': 'whois'
}

def get_hash_type(hashcode):
    if len(hashcode) == 32:
        return 'FileHash-MD5'
    elif len(hashcode) == 40:
        return 'FileHash-SHA1'
    elif len(hashcode) == 64:
        return 'FileHash-SHA256'      
    else:
        logger.exception('Wrong Hash code: {}'.format(hashcode))
        raise ConnectorError('Wrong Hash code: {}'.format(hashcode))

def create_otx_object(config):
    try:
        global url
        server_url = config.get('url')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = 'https://' + server_url
        url = server_url
        otx = OTXv2(api_key=config.get('api_key'), server=server_url, verify=config.get('verify_ssl'))
        logger.info('otx object created')
        return otx
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_reputation(indicator_obj, indicator_value, config, section='general'):
    try:
        otx = create_otx_object(config)
        return otx.get_indicator_details_by_section(indicator_obj, indicator=indicator_value,
                                                    section=section)
    except Exception as err:
        logger.exception(str(err))
        if 'object has no attribute' in str(err):
            raise ConnectorError('Invalid Input')
        raise ConnectorError(str(err))


def get_ip_reputation(config, params):
    try:
        indicator_obj = type_dict.get(params.get('indicator_type'))
        ip_address = params.get('ip_address')
        return get_reputation(indicator_obj, ip_address, config, 'reputation')
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_domain_reputation(config, params):
    try:
        result = {'general': {}, 'malware': {}, 'geo': {}, 'passive_dns': {}, 'url_list': {},
                  'whois': {}}
        domain = params.get('domain')
        section = section_dict.get(params.get('section'))
        otx_obj = create_otx_object(config)
        headers = {
            'X-OTX-API-KEY': config.get('api_key'),
            'Content-Type': 'application/json'
        }
        if not section:
            section = 'general'
        endpoint = '{0}/api/v1/indicators/domain/{1}/{2}'.format(url, domain, section)
        response = requests.get(endpoint, headers=headers, verify=config.get('verify_ssl'))
        if response.ok:
            result[section] = response.json()
            return result
        else:
            logger.error(str(response.content.decode('utf-8')))
    except Exception as err:
        logger.exception(str(err))
        if 'object has no attribute' in str(err):
            raise ConnectorError('Invalid Input')
        raise ConnectorError(err)
    raise ConnectorError(response.json())


def get_url_reputation(config, params):
    result = {}
    result['url_list'] = get_reputation(IndicatorTypes.URL, params.get('url'), config,
                                        'url_list')
    result['general'] = get_reputation(IndicatorTypes.URL, params.get('url'), config,
                                       'general')
    return result


def get_file_reputation(config, params):
    try:
        file_hash = params.get('file_hash')
        indicator_type = get_hash_type(file_hash)
        indicator_obj = type_dict.get(indicator_type)
        result = {}
        result['general'] = get_reputation(indicator_obj, file_hash, config, 'general')
        result['analysis'] = get_reputation(indicator_obj, file_hash, config, 'analysis')
        return result
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_hostname_reputation(config, params):
    result = {'general': {}, 'malware': {}, 'geo': {}, 'passive_dns': {}, 'url_list': {}}
    section = section_dict.get(params.get('section'))
    if not section:
        section = 'general'
    result[section] = get_reputation(IndicatorTypes.HOSTNAME, params.get('hostname'),
                                     config, section)
    return result


def upload_file_to_cyops(file_name, file_content, file_type=None):
    try:
        response = make_file_upload_request(file_name, file_content, file_type)
        logger.info('File upload complete {0}'.format(str(response)))
        file_id = response['@id']
        file_description = 'Indicators from alienvault-OTX'
        attach_response = make_request('/api/3/attachments', 'POST',
                                       {'name': file_name, 'file': file_id,
                                        'description': file_description})
        logger.info('File attached to FortiSOAR attachments, details are {0}'.format(str(attach_response)))
        return attach_response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))

def get_all_indicators(config, params):
    try:
        export_json = params.get('export_json')
        indicator_type = params.get('indicator_type')
        indicator_type = ','.join(indicator_type)
        param_dict = {
            'modified_since': params.get('from_time'),
            'types': indicator_type,
            'limit': params.get('limit'),
            'page': params.get('page')
        }
        param_dict = {k: v for k,v in param_dict.items() if v is not None and v != '' and v !={} and v !=[]}
        otx = create_otx_object(config)
        endpoint = '{0}/api/v1/indicators/export?{1}'.format(url, urlencode(param_dict))
        result = otx.get(endpoint)
        attachment_name = 'indicators_' + str(datetime.datetime.now()) + '.json'
        if export_json:
            result_set = result['results']
            result_dict = json.dumps(result_set)
            response = upload_file_to_cyops(attachment_name, result_dict.encode(), 'json')
            return response
        return result
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_pulse_details(config, params):
    try:
        otx = create_otx_object(config)
        return otx.get_pulse_details(pulse_id=params.get('pulse_id'))
    except Exception as err:
        logger.exception(str(err))
        if 'object has no attribute' in str(err):
            raise ConnectorError('Entered pulse ID is invalid')
        raise ConnectorError(str(err))


def get_pulse_indicators(config, params):
    try:
        otx = create_otx_object(config)
        endpoint = '{0}/api/v1/pulses/{pulse_id}/indicators?limit={limit}&include_inactive={include_inactive}&page={page}'.\
            format(url, pulse_id=params.get('pulse_id'), include_inactive=1 if params.get('include_inactive') else 0,
                   limit=params.get('limit') if params.get('limit') else 1000,
                   page=params.get('page') if params.get('page') else 1)
        return otx.get(endpoint)
    except Exception as err:
        logger.exception(str(err))
        if 'object has no attribute' in str(err):
            raise ConnectorError('Entered pulse ID is invalid')
        raise ConnectorError(str(err))


def get_shared_indicator_pulses(config, params):
    # get_related_pulses
    try:
        otx = create_otx_object(config)
        endpoint = '{0}/api/v1/pulses/{1}/related?page={2}'.format(url, params.get('pulse_id'),
                                                                   params.get('page_number'))
        return otx.get(endpoint)
    except Exception as err:
        logger.exception(str(err))
        if 'object has no attribute' in str(err):
            raise ConnectorError('Entered pulse ID is invalid')
        raise ConnectorError(str(err))


def get_subscribed_pulses(config, params):
    try:
        otx = create_otx_object(config)
        endpoint = '{0}/api/v1/pulses/subscribed/?modified_since={1}&limit={2}&page={3}'\
            .format(url, params.get('from_time'), params.get('limit'), params.get('page'))

        return otx.get(endpoint)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_pulse(config, params):
    try:
        indicator_list = params.get('indicator_list') if params.get('indicator_list') else []
        tags = params.get('tag') if params.get('tag') else []
        if isinstance(tags, str):
            tags = tags.split(',')
        references = params.get('references') if params.get('references') else []
        if isinstance(references, str):
            references = references.split(',')
        public = params.get('public') if params.get('public') else False
        otx = create_otx_object(config)
        return otx.create_pulse(name=params.get('pulse_name'), public=public, indicators=indicator_list,
                                tags=tags, references=references, description=params.get('pulse_des'))
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def search_pulses(config, params):
    try:
        otx = create_otx_object(config)
        endpoint = '{0}/api/v1/search/pulses?page={1}&limit={2}&q={3}'.format(url, params.get('page'),
                                                                        params.get('limit') if params.get('limit') else 50,
                                                                              params.get('user_text'))
        return otx.get(endpoint)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def user_action(config, params):
    try:
        otx = create_otx_object(config)
        endpoint = '{0}/api/v1/user/{1}/{2}'.format(url, params.get('username'), actions.get(params.get('user_action')))
        return otx.post(endpoint, body={})
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError('Invalid Username')


def subscribe_pulse(config, params):
    try:
        otx = create_otx_object(config)
        endpoint = '{0}/otxapi/pulses/{1}/subscribe/'.format(url, params.get('pulse_id'))
        return otx.get(endpoint)
    except Exception as err:
        logger.exception(str(err))
        if 'object has no attribute' in str(err):
            raise ConnectorError('Entered pulse ID is invalid')
        raise ConnectorError(str(err))


def unsubscribe_pulse(config, params):
    try:
        otx = create_otx_object(config)
        endpoint = '{0}/otxapi/pulses/{1}/unsubscribe/'.format(url, params.get('pulse_id'))
        return otx.get(endpoint)
    except Exception as err:
        logger.exception(str(err))
        if 'object has no attribute' in str(err):
            raise ConnectorError('Entered pulse ID is invalid')
        raise ConnectorError(str(err))


def run_query(config, params):
    try:
        otx = create_otx_object(config)
        return otx.get(params.get('query_url'))
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def test_connection(config):
    try:
        otx = create_otx_object(config)
        otx.get('{0}/api/v1/users/me'.format(url))
        return True
    except Exception as err:
        logger.exception(str(err))
        if 'Name or service not known' in str(err):
            raise ConnectorError('Invalid Endpoint URL')
        raise ConnectorError(str(err))


operations = {
    'get_ip_reputation': get_ip_reputation,
    'get_domain_reputation': get_domain_reputation,
    'get_url_reputation': get_url_reputation,
    'get_file_reputation': get_file_reputation,
    'get_hostname_reputation': get_hostname_reputation,
    'get_all_indicators': get_all_indicators,
    'get_pulse_details': get_pulse_details,
    'get_pulse_indicators': get_pulse_indicators,
    'get_shared_indicator_pulses': get_shared_indicator_pulses,
    'get_subscribed_pulses': get_subscribed_pulses,
    'create_pulse': create_pulse,
    'search_pulses': search_pulses,
    'user_action': user_action,
    'subscribe_pulse': subscribe_pulse,
    'unsubscribe_pulse': unsubscribe_pulse,
    'run_query': run_query
}
