""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
import urllib.parse as urlp

from connectors.core.connector import get_logger, ConnectorError
from .utils import (
    _check_and_build_vulnerability_params,
    _generate_headers,
    _build_url,
    _get,
    error_handling)

MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs", "FileHash_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "xforce"
logger = get_logger('xforce')


def get_ip_reputation(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='ipr/history', params=params['ip'])
    logger.info("IP reputation url: {url}".format(url=url))
    ip_reputation = _get(url, verify_ssl, headers=headers)
    if ip_reputation.ok:
        return ip_reputation.json()
    elif ip_reputation.status_code == 404:
        return json.dumps({"message": "IP reputation for given IP is not found in XForce Server"})
    error_handling("Failed to receive IP reputation. ", ip_reputation)


def get_ip_report(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='ipr', params=params['ip'])
    logger.info("IP report url: {url}".format(url=url))
    ip_report = _get(url, verify_ssl, headers=headers)
    if ip_report.ok:
        return ip_report.json()
    elif ip_report.status_code == 404:
        return json.dumps({"message": "IP report for given IP is not found in XForce Server"})
    error_handling("Failed to receive IP report. ", ip_report)


def get_ip_behaviour(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='ipr/malware', params=params['ip'])
    logger.info("IP behaviour url: {url}".format(url=url))
    ip_malware = _get(url, verify_ssl, headers=headers)
    if ip_malware.ok:
        return ip_malware.json()
    elif ip_malware.status_code == 404:
        return json.dumps({"message": "IP malware for given IP is not found in XForce Server"})
    error_handling("Failed to receive IP malware content. ", ip_malware)


def get_vulnerability(config, params):
    headers, verify_ssl = _generate_headers(config)
    query_params = _check_and_build_vulnerability_params(params)
    url = _build_url(config, method_name='vulnerabilities/fulltext', query_params=query_params)
    logger.info("search vulnerability url: {url}".format(url=url))
    vulnerability = _get(url, verify_ssl, headers=headers)
    if vulnerability.ok:
        return vulnerability.json()
    elif vulnerability.status_code == 404:
        return json.dumps({"message": "No vulnerability was found for given search term"})
    error_handling("Failed to search vulnerability. ", vulnerability)


def get_vulnerability_from_xfid(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='vulnerabilities', params=params['xfid'])
    logger.info("search vulnerability XFID url: {url}".format(url=url))
    xfid = _get(url, verify_ssl, headers=headers)
    if xfid.ok:
        return xfid.json()
    elif xfid.status_code == 404:
        return json.dumps({"message": "No vulnerability was found for given xfid"})
    error_handling("Failed to search vulnerability by xfid. ", xfid)


def get_vulnerability_from_stdcode(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='vulnerabilities/search', params=params['stdcode'])
    logger.info("search vulnerability STDCODE url: {url}".format(url=url))
    stdcode = _get(url, verify_ssl, headers=headers)
    if stdcode.ok:
        return stdcode.json()
    elif stdcode.status_code == 404:
        return json.dumps({"message": "No vulnerability was found for given stdcode"})
    error_handling("Failed to search vulnerability by stdcode. ", stdcode)


def get_file_reputation_using_filehash(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='malware', params=params['filehash'])
    logger.info("Malware file hash url: {url}".format(url=url))
    file_malware = _get(url, verify_ssl, headers=headers)
    if file_malware.ok:
        return file_malware.json()
    elif file_malware.status_code == 404:
        return json.dumps({"message": "No result found for given file hash"})
    error_handling("Failed to receive malware by file hash. ", file_malware)


def get_relative_malware(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='malware/family', params=params['family'])
    logger.info("Malware relative url: {url}".format(url=url))
    family_malware = _get(url, verify_ssl, headers=headers)
    if family_malware.ok:
        return family_malware.json()
    elif family_malware.status_code == 404:
        return json.dumps({"message": "No result found for given malware family"})
    error_handling("Failed to receive malware by family. ", family_malware)


def get_dns_record(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='resolve', params=params['query'])
    logger.info("DNS record url: {url}".format(url=url))
    host_details = _get(url, verify_ssl, headers=headers)
    if host_details.ok:
        return host_details.json()
    elif host_details.status_code == 404:
        return json.dumps({"message": "No record found for given input"})
    error_handling("Failed to receive dns record. ", host_details)


def get_ip_registrant(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='whois', params=params['host'])
    logger.info("IP registrant url: {url}".format(url=url))
    host_details = _get(url, verify_ssl, headers=headers)
    if host_details.ok:
        return host_details.json()
    elif host_details.status_code == 404:
        return json.dumps({"message": "No record found for given input"})
    error_handling("Failed to receive host owner. ", host_details)


def search_signature(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='signatures/fulltext', query_params="q=" + urlp.quote(params['query_string']))
    logger.info("search signature url: {url}".format(url=url))
    search_signature_response = _get(url, verify_ssl, headers=headers)
    if search_signature_response.ok:
        return search_signature_response.json()
    elif search_signature_response.status_code == 404:
        return json.dumps({"message": "No record found for given input"})
    error_handling("Failed to search signature. ", search_signature_response)


def search_signature_by_pamid(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='signatures', params=params['pamId'])
    logger.info("search signature PAMID url: {url}".format(url=url))
    pamid_search = _get(url, verify_ssl, headers=headers)
    if pamid_search.ok:
        return pamid_search.json()
    elif pamid_search.status_code == 404:
        return json.dumps({"message": "No record found for given input"})
    error_handling("Failed to search signature by pamid. ", pamid_search)


def search_signature_by_xpu(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='signatures/xpu', params=params['xpu'])
    logger.info("search signature XPU url: {url}".format(url=url))
    xpu_search = _get(url, verify_ssl, headers=headers)
    if xpu_search.ok:
        return xpu_search.json()
    elif xpu_search.status_code == 404:
        return json.dumps({"message": "No record found for given input"})
    error_handling("Failed to search signature by XPU. ", xpu_search)


def get_url_report(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='url', params=params['url'])
    logger.info("Get report url: {url}".format(url=url))
    url_report = _get(url, verify_ssl, headers=headers)
    if url_report.ok:
        return url_report.json()
    elif url_report.status_code == 404:
        return json.dumps({"message": "No record found for given input"})
    error_handling("Failed to receive report for url. ", url_report)


def get_url_behaviour(config, params):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='url/malware', params=params['url'])
    logger.info("Get malware behaviour url: {url}".format(url=url))
    url_malware_report = _get(url, verify_ssl, headers=headers)
    if url_malware_report.ok:
        return url_malware_report.json()
    elif url_malware_report.status_code == 404:
        return json.dumps({"message": "No record found for given input"})
    error_handling("Failed to receive malware for url. ", url_malware_report)


operations = {
    'search_signature': search_signature,
    'search_signature_by_xpu': search_signature_by_xpu,
    'search_signature_by_pamid': search_signature_by_pamid,

    'get_vulnerability_from_stdcode': get_vulnerability_from_stdcode,
    'get_vulnerability_from_xfid': get_vulnerability_from_xfid,
    'get_vulnerability': get_vulnerability,

    'get_ip_reputation': get_ip_reputation,
    'get_ip_behaviour': get_ip_behaviour,
    'get_ip_report': get_ip_report,

    'get_url_report': get_url_report,
    'get_url_behaviour': get_url_behaviour,

    'get_relative_malware': get_relative_malware,
    'get_file_reputation_using_filehash': get_file_reputation_using_filehash,
    'get_dns_record': get_dns_record,
    'get_ip_registrant': get_ip_registrant
}
