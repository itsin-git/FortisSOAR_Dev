""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .utils import VirusTotalConnection
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('virustotal')


def get_widget_rendering_url(config, params):
    vt = VirusTotalConnection(config)
    return vt.getWidgetUrl(config, params)


def get_widget_html_content(config, params):
    vt = VirusTotalConnection(config)
    return vt.getWidgetHtmlContent(config, params)


def query_ip(config, params):
    vt = VirusTotalConnection(config)
    ip = params.get('ip')
    relationships = params.get('relationships')
    if isinstance(ip, bytes):
        ip = ip.decode('utf-8')
    return vt.getIpReport(ip, relationships)


def query_domain(config, params):
    vt = VirusTotalConnection(config)
    domain = params.get('domain')
    relationships = params.get('relationships')
    if isinstance(domain, bytes):
        domain = domain.decode('utf-8')
    return vt.getDomainReport(domain, relationships)


def query_url(config, params):
    vt = VirusTotalConnection(config)
    url = params.get('url')
    relationships = params.get('relationships')
    return vt.getUrlReport(url, relationships)


def upload_sample(config, params):
    vt = VirusTotalConnection(config)
    file_iri = vt.handle_params(params)
    return vt.submitFile(file_iri)


def scan_url(config, params):
    vt = VirusTotalConnection(config)
    url = params.get('url')
    return vt.scanUrl(url)


def file_reputation(config, params):
    vt = VirusTotalConnection(config)
    file_hash = params.get('file_hash')
    relationships = params.get('relationships')
    if isinstance(file_hash, bytes):
        file_hash = file_hash.decode('utf-8')
    result = vt.getHashReport(str(file_hash), relationships)
    return result


def analysis_file(config, params):
    vt = VirusTotalConnection(config)
    id = params.get('analysis_id')
    type = params.get('type')
    response = vt.getFileAnalysis(id, type)
    return response


def custom_endpoint(config, params):
    vt = VirusTotalConnection(config)
    url = params.get('endpoint')
    method = params.get('method')
    body = params.get('body')
    response = vt.getUrlEndpoint(url, method, body)
    return response


def get_output_schema_ip(config, params):
    vt = VirusTotalConnection(config)
    return vt.build_output_schema_ip(config, params)


def get_output_schema_domain(config, params):
    vt = VirusTotalConnection(config)
    return vt.build_output_schema_domain(config, params)


def get_output_schema_url(config, params):
    vt = VirusTotalConnection(config)
    return vt.build_output_schema_url(config, params)


def get_output_schema_file(config, params):
    vt = VirusTotalConnection(config)
    return vt.build_output_schema_file(config, params)


def _check_health(config):
    try:
        url = 'https://www.google.com'
        vt = VirusTotalConnection(config)
        res = vt.getUrlReport(url, relationships='')
        if res:
            return True
    except Exception as Err:
        raise ConnectorError('Invalid URL or Credentials')


operations = {
    'get_widget_rendering_url': get_widget_rendering_url,
    'get_widget_html_content': get_widget_html_content,
    'upload_sample': upload_sample,
    'file_reputation': file_reputation,
    'scan_url': scan_url,
    'query_url': query_url,
    'query_ip': query_ip,
    'query_domain': query_domain,
    'analysis_file': analysis_file,
    'custom_endpoint': custom_endpoint,
    'get_output_schema_ip': get_output_schema_ip,
    'get_output_schema_domain': get_output_schema_domain,
    'get_output_schema_url': get_output_schema_url,
    'get_output_schema_file': get_output_schema_file
}
