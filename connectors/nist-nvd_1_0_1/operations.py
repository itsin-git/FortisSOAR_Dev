"""
Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
from .utils import *

logger = get_logger('nist-nvd')


def get_specific_cve_details(config, params):
    nist_nvd = NistNvd(config)
    endpoint = 'rest/json/cves/2.0'
    query_params = build_query_params(params)
    response = nist_nvd.make_api_call(endpoint=endpoint, params=query_params)
    return response.json()


def cve_search(config, params):
    nist_nvd = NistNvd(config)
    endpoint = 'rest/json/cves/2.0'
    query_params = build_query_params(params)
    response = nist_nvd.make_api_call(endpoint=endpoint, params=query_params)
    return response.json()


def cve_search_by_keywords(config, params):
    nist_nvd = NistNvd(config)
    endpoint = 'rest/json/cves/2.0'
    query_params = build_query_params(params)
    response = nist_nvd.make_api_call(endpoint=endpoint, params=query_params)
    return response.json()


def get_cve_change_history(config, params):
    nist_nvd = NistNvd(config)
    endpoint = 'rest/json/cvehistory/2.0'
    query_params = build_query_params(params)
    response = nist_nvd.make_api_call(endpoint=endpoint, params=query_params)
    return response.json()


def cpe_search(config, params):
    nist_nvd = NistNvd(config)
    endpoint = 'rest/json/cpematch/2.0' if params.get('cveId') else 'rest/json/cpes/2.0'
    query_params = build_query_params(params)
    response = nist_nvd.make_api_call(endpoint=endpoint, params=query_params)
    return response.json()


def _check_health(config):
    nist_nvd = NistNvd(config)
    endpoint = 'rest/json/cves/2.0'
    query_params = {'cveId': 'CVE-2019-1010218'}
    response = nist_nvd.make_api_call(endpoint=endpoint, params=query_params)
    if response.status_code == 200:
        logger.info('Connector Available')
        return True
    else:
        logger.info('Connector Not Available')
        return False


operations = {
    'get_specific_cve_details': get_specific_cve_details,
    'cve_search': cve_search,
    'cve_search_by_keywords': cve_search_by_keywords,
    'get_cve_change_history': get_cve_change_history,
    'cpe_search': cpe_search
}
