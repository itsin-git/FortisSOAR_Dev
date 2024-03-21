""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json
from .constants import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('whois-xml-api')


class WhoisXMLAPI(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        self.sslVerify = config.get('verify')

    def make_api_call(self, endpoint=None, method='GET', data=None, params=None):
        try:
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json',
                       "Authorization": "Token {}".format(self.api_key)}
            response = requests.request(method, endpoint, params=params, headers=headers,
                                        verify=self.sslVerify, data=json.dumps(data))
            if response.ok:
                logger.info('Successfully got response for url {}'.format(endpoint))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            elif response.status_code == 404:
                return response.text
            else:
                logger.error(response.content)
                raise ConnectorError(
                    {'status_code': response.status_code, 'message': response.content})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def get_params(params):
    for k, v in list(params.items()):
        if v is not None and v != '':
            if k in ['sinceDate', 'createdDateFrom', 'createdDateTo', 'updatedDateFrom', 'updatedDateTo',
                     'expiredDateFrom', 'expiredDateTo']:
                v = v.split('T')[0]
            params.update({k: v})
        else:
            params.pop(k, '')
    return params


def whois_history_search(config, params):
    try:
        wxa = WhoisXMLAPI(config)
        params['mode'] = params.get('mode', '').lower()
        params.update({'apiKey': config.get('api_key')})
        params = get_params(params)
        return wxa.make_api_call(endpoint=WHOISXML_WHOIS_HISTORY_SEARCH_ENDPOINT, params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def whois_search(config, params):
    try:
        wxa = WhoisXMLAPI(config)
        if params.get('other_fields'):
            params.update(params.get('other_fields'))
            del params['other_fields']
        if params.get('preferFresh'):
            params['preferFresh'] = True_False_Map.get(str(params.get('preferFresh')))
        if params.get('ip'):
            params['ip'] = True_False_Map.get(str(params.get('ip')))
        if params.get('checkProxyData'):
            params['checkProxyData'] = True_False_Map.get(str(params.get('checkProxyData')))
        if params.get('ipWhois'):
            params['ipWhois'] = True_False_Map.get(str(params.get('ipWhois')))
        if params.get('da'):
            params['da'] = Domain_Availability_Map.get(params.get('da'))
        params.update({'apiKey': config.get('api_key'), 'outputFormat': 'JSON'})
        params = get_params(params)
        return wxa.make_api_call(endpoint=WHOISXML_WHOIS_SEARCH_ENDPOINT, params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def dns_lookup(config, params):
    try:
        wxa = WhoisXMLAPI(config)
        lookup = ''.join(params.get('type')).replace("[", "").replace("]", "").replace("'", "").replace(" ", "")
        endpoint = WHOISXML_DNS_LOOKUP_ENDPOINT.format(config.get('api_key'), params.get('domainName'), lookup)
        return wxa.make_api_call(endpoint, 'GET')
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def reverse_dns_search(config, params):
    try:
        wxa = WhoisXMLAPI(config)
        params.update({'apiKey': config.get('api_key'), 'outputFormat': 'JSON'})
        params = get_params(params)
        return wxa.make_api_call(endpoint=WHOISXML_REVERSE_DNS_SEARCH_ENDPOINT.get(params.get('reverse_dns_type')),
                                 params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def reverse_whois_search(config, params):
    try:
        wxa = WhoisXMLAPI(config)
        exclude_domain_search_terms = params.get('exclude_domain_search_terms').split(',') if isinstance(
            params.get('exclude_domain_search_terms'),
            str) else params.get('exclude_domain_search_terms')
        include_domain_search_terms = params.get('include_domain_search_terms').split(',') if isinstance(
            params.get('include_domain_search_terms'),
            str) else params.get('include_domain_search_terms')
        payload = {
            "apiKey": config.get('api_key'),
            "searchType": params.get('search_type').lower(),
            "mode": params.get('mode').lower(),
            "punycode": True,
            "searchAfter": params.get('search_after'),
            "responseFormat": "json",
            "includeAuditDates": params.get('include_audit_dates'),
            "createdDateFrom": params.get('createdDateFrom'),
            "createdDateTo": params.get('createdDateTo'),
            "updatedDateFrom": params.get('updatedDateFrom'),
            "updatedDateTo": params.get('updatedDateTo'),
            "expiredDateFrom": params.get('expiredDateFrom'),
            "expiredDateTo": params.get('expiredDateTo'),
            "basicSearchTerms": {
                "include": include_domain_search_terms,
                "exclude": exclude_domain_search_terms
            }
        }
        return wxa.make_api_call(endpoint=WHOISXML_REVERSE_WHOIS_SEARCH_ENDPOINT, method='POST', data=payload)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def domain_subdomain_discovery(config, params):
    try:
        wxa = WhoisXMLAPI(config)
        include_domain = params.get('include_domain').split(',') if isinstance(params.get('include_domain'),
                                                                               str) else params.get('include_domain')
        exclude_domains = params.get('exclude_domains').split(',') if isinstance(params.get('exclude_domains'),
                                                                                 str) else params.get('exclude_domains')
        include_subdomain = params.get('include_subdomain').split(',') if isinstance(params.get('include_subdomain'),
                                                                                     str) else params.get(
            'include_subdomain')
        exclude_subdomains = params.get('exclude_subdomains').split(',') if isinstance(params.get('exclude_subdomains'),
                                                                                       str) else params.get(
            'exclude_subdomains')
        payload = {
            'apiKey': config.get('api_key'),
            'domains': {
                'include': include_domain,
                'exclude': exclude_domains
            },
            'subdomains': {
                'include': include_subdomain,
                'exclude': exclude_subdomains
            },
            'outputFormat': 'JSON',
            'sinceDate': params.get('sinceDate')
        }
        return wxa.make_api_call(endpoint=WHOISXML_DOMAIN_SUBDOMAIN_DISCOVERY_ENDPOINT, method='POST', data=payload)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def brand_monitor(config, params):
    try:
        wxa = WhoisXMLAPI(config)
        exclude_domain_search_terms = params.get('exclude_domain_search_terms').split(',') if isinstance(
            params.get('exclude_domain_search_terms'),
            str) else params.get('exclude_domain_search_terms')
        include_domain_search_terms = params.get('include_domain_search_terms').split(',') if isinstance(
            params.get('include_domain_search_terms'),
            str) else params.get('include_domain_search_terms')
        payload = {
            "apiKey": config.get('api_key'),
            "sinceDate": params.get('sinceDate'),
            "mode": params.get('mode').lower(),
            "withTypos": params.get('withTypos'),
            "responseFormat": "json",
            "punycode": True,
            "includeSearchTerms": include_domain_search_terms,
            "excludeSearchTerms": exclude_domain_search_terms
        }
        return wxa.make_api_call(endpoint=WHOISXML_BRAND_MONITOR_ENDPOINT, method='POST', data=payload)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def ssl_certificates(config, params):
    try:
        wxa = WhoisXMLAPI(config)
        params['withChain'] = True_False_Map.get(str(params.get('withChain')))
        params['hardRefresh'] = True_False_Map.get(str(params.get('hardRefresh')))
        params.update({'apiKey': config.get('api_key'), 'outputFormat': 'JSON'})
        params = get_params(params)
        return wxa.make_api_call(endpoint=WHOISXML_SSL_CERTIFICATES_ENDPOINT, params=params)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def _check_health(config):
    try:
        wxa = WhoisXMLAPI(config)
        endpoint = WHOISXML_API_TOKEN_ENDPOINT.format(config.get('api_key'))
        return wxa.make_api_call(endpoint, 'GET')
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    'whois_history_search': whois_history_search,
    'whois_search': whois_search,
    'reverse_whois_search': reverse_whois_search,
    'reverse_dns_search': reverse_dns_search,
    'domain_subdomain_discovery': domain_subdomain_discovery,
    'brand_monitor': brand_monitor,
    'dns_lookup': dns_lookup,
    'ssl_certificates': ssl_certificates
}
