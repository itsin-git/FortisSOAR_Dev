""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import time

from connectors.core.connector import get_logger, ConnectorError, api_health_check

logger = get_logger('tenable-io')

days_mapping = {'Last 24 Hours': 1, 'Last 3 Days': 3, 'Last 5 Days': 5,
                'Last 7 Days': 7, 'Last 15 Days': 15, 'Last 25 Days': 25, 'Last 30 Days': 30,
                'Last 50 Days': 50, 'Last 60 Days': 60, 'Last 90 Days': 90, 'Last 120 Days': 120, 'Last 180 Days': 180
                }

state_mapping = {
    "Open": "open",
    "Reopened": "reopened",
    "Fixed": "fixed"
}

severity_mapping = {
    "Info": "info",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
    "Critical": "critical"
}


class TenableIO(object):
    def __init__(self, config):
        self.base_url = config.get('server').strip()
        self.verify_ssl = config.get('verify_ssl')
        self.current_time_epoch = int(time.time())
        self.day_seconds = 86400
        self.auth_headers = {
            'X-ApiKeys': 'accessKey={0}; secretKey={1};'.format(config.get('access_key'), config.get('secret_key')),
            'User-Agent': 'Integration/1.0 (Fortinet; FortiSOAR; Build/1.2.0)'
        }
        self.error_msg = {
            400: 'Bad Request or Invalid Request',
            401: 'Invalid login credentials',
            404: 'No resource available for provided id',
            409: 'Provided scan already triggered',
            429: 'Too many requests, Please wait and run the action again.',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'
        }
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://' + self.base_url
        if not self.base_url.endswith('/'):
            self.base_url += '/'

    @staticmethod
    def find_current_history_id(scan_details):
        current_date = 0
        history_id = int()
        for h in scan_details['history']:
            if current_date < h['creation_date']:
                current_date = h['creation_date']
                history_id = h['history_id']
        return history_id

    def get_asset_uuids(self, scan_id, history_id):
        endpoint = "private/scans/{scan_id}/assets/vulnerabilities?history_id={history_id}".format(
            scan_id=scan_id,
            history_id=history_id)

        json_resp = self.make_rest_call(endpoint)
        return [item['uuid'] for item in json_resp.get('assets')]

    def get_asset_details(self, scan_id, uuid, history_id):
        endpoint = "private/scans/{scan_id}/assets/{uuid}/info?history_id={history_id}".format(
            scan_id=scan_id,
            uuid=uuid,
            history_id=history_id)

        json_resp = self.make_rest_call(endpoint)
        json_resp = json_resp.get('info')
        return (dict(
            ip=json_resp.get('ipv4', ""),
            mac=json_resp.get('mac_address', ""),
            os=json_resp.get('operating_system', ""),
            fqdn=json_resp.get('fqdn', ""),
            uuid=uuid,
            time_start=json_resp.get('time_start', ""),
            time_end=json_resp.get('time_end'))
        )

    def make_rest_call(self, endpoint, params=None, data=None, headers={}, method='GET'):
        url = '{0}{1}'.format(self.base_url, endpoint)
        headers.update(self.auth_headers)
        request_headers = headers
        try:
            response = requests.request(method,
                                        url,
                                        json=data,
                                        headers=request_headers,
                                        verify=self.verify_ssl,
                                        params=params)
            if response.ok:
                return response.json() if response.content else ''
            if self.error_msg[response.status_code]:
                raise ConnectorError('{0}'.format(self.error_msg[response.status_code]))
            response.raise_for_status()
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(self.error_msg['time_out']))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def get_epoch(_date):
    pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
    return int(time.mktime(time.strptime(_date, pattern)))


def get_scans(config, params):
    tenable = TenableIO(config)
    days = days_mapping.get(params['days'], 3)
    last_fetched = tenable.current_time_epoch - days * tenable.day_seconds
    endpoint = 'scans?last_modification_date={}'.format(last_fetched)
    json_resp = tenable.make_rest_call(endpoint)
    return json_resp.get('scans')


def get_asset_vulnerabilities(config, params):
    tenable = TenableIO(config)
    endpoint = 'workbenches/assets/{uuid}/vulnerabilities'.format(uuid=params.get('asset_id'))
    return tenable.make_rest_call(endpoint).get('vulnerabilities')


def get_scan_assets(config, params):
    tenable = TenableIO(config)
    scan_id = params.get('scan_id')
    assets = list()
    scan_details_endpoint = 'scans/{scan_id}'.format(scan_id=scan_id)
    details = tenable.make_rest_call(scan_details_endpoint)
    history_id = tenable.find_current_history_id(details)
    uuids = tenable.get_asset_uuids(scan_id, history_id)
    for u in uuids:
        assets.append(tenable.get_asset_details(scan_id, u, history_id))
    return assets


def launch_scan(config, params):
    tenable = TenableIO(config)
    scan_id = params.get('scan_id')
    targets = params.get('alt_targets', None)
    endpoint = 'scans/{scan_id}/launch'.format(scan_id=scan_id)
    if isinstance(targets, str):
        targets = targets.split(",")
    data = {"alt_targets": targets if targets else None}
    json_resp = tenable.make_rest_call(endpoint, data=data, method='POST')
    return json_resp


def get_vulnerabilities_details(config, params):
    tenable = TenableIO(config)
    plugin_id = params.get('plugin_id')
    endpoint = 'workbenches/vulnerabilities/{plugin_id}/info'.format(plugin_id=plugin_id)
    json_resp = tenable.make_rest_call(endpoint)
    json_resp.get('info').get('plugin_details').update({'plugin_id': plugin_id})
    if not json_resp:
        raise ConnectorError('Not Found URL {}{}'.format(tenable.base_url, endpoint))
    return json_resp


def get_plugin_details(config, params):
    tenable = TenableIO(config)
    endpoint = 'plugins/plugin/{plugin_id}'.format(plugin_id=params.get('plugin_id'))
    json_resp = tenable.make_rest_call(endpoint)
    if not json_resp:
        raise ConnectorError('Not Found URL {0}{1}'.format(tenable.base_url, endpoint))
    return json_resp


def _check_health(config):
    tenable = TenableIO(config)
    endpoint = '{base}server/heartbeat'.format(base=tenable.base_url)
    try:
        json_resp = api_health_check(endpoint, headers=tenable.auth_headers, verify=tenable.verify_ssl)
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def make_export_filter_params(params, filter_params, key, map):
    value = params.get(key)
    new_val = []
    if len(value) != 0:
        for item in value:
            new_val.append(map[item])
        filter_params.update({key: new_val})
    return filter_params


def submit_vuln_export_job(config, params):
    tenable = TenableIO(config)
    endpoint = 'vulns/export'
    request_params = {"num_assets": params.get('num_assets')}
    filter_params = {}
    if params.get('cidr_range'):
        filter_params.update({'cidr_range': params.get('cidr_range')})
    if params.get('since'):
        since = params.get('since')
        since = get_epoch(since) if isinstance(since, str) else since
        filter_params.update({'since': since})
    if params.get('state'):
        filter_params = make_export_filter_params(params, filter_params, 'state', state_mapping)
    if params.get('severity'):
        filter_params = make_export_filter_params(params, filter_params, 'severity', severity_mapping)
    if filter_params:
        request_params.update({'filters': filter_params})
    json_resp = tenable.make_rest_call(endpoint=endpoint, data=request_params, method='POST')
    return json_resp


def get_vuln_export_status(config, params):
    tenable = TenableIO(config)
    endpoint = 'vulns/export/{0}/status'.format(params.get('export_uuid'))
    json_resp = tenable.make_rest_call(endpoint=endpoint)
    return json_resp


def download_vuln_export_chunk(config, params):
    tenable = TenableIO(config)
    endpoint = 'vulns/export/{0}/chunks/{1}'.format(params.get('export_uuid'), params.get('chunk_id'))
    json_resp = tenable.make_rest_call(endpoint=endpoint)
    return json_resp


def list_vuln_export_jobs(config):
    tenable = TenableIO(config)
    endpoint = 'vulns/export/status'
    json_resp = tenable.make_rest_call(endpoint=endpoint)
    return json_resp


def cancel_vuln_export_job(config, params):
    tenable = TenableIO(config)
    endpoint = 'vulns/export/{0}/cancel'.format(params.get('export_uuid'))
    json_resp = tenable.make_rest_call(endpoint=endpoint, method='POST')
    return json_resp


def submit_asset_export_job(config, params):
    tenable = TenableIO(config)
    endpoint = 'assets/export'
    request_params = {"chunk_size": params.get('chunk_size')}
    last_assessed = params.get('last_assessed')
    if last_assessed:
        last_assessed = get_epoch(last_assessed) if isinstance(last_assessed, str) else last_assessed
        request_params.update({"filters": {"last_assessed": last_assessed}})
    json_resp = tenable.make_rest_call(endpoint=endpoint, data=request_params, method='POST')
    return json_resp


def get_asset_export_status(config, params):
    tenable = TenableIO(config)
    endpoint = 'assets/export/{0}/status'.format(params.get('export_uuid'))
    json_resp = tenable.make_rest_call(endpoint=endpoint)
    return json_resp


def download_asset_export_chunk(config, params):
    tenable = TenableIO(config)
    endpoint = 'assets/export/{0}/chunks/{1}'.format(params.get('export_uuid'), params.get('chunk_id'))
    json_resp = tenable.make_rest_call(endpoint=endpoint)
    return json_resp


def list_asset_export_jobs(config):
    tenable = TenableIO(config)
    endpoint = 'assets/export/status'
    json_resp = tenable.make_rest_call(endpoint=endpoint)
    return json_resp


def cancel_asset_export_job(config, params):
    tenable = TenableIO(config)
    endpoint = 'assets/export/{0}/cancel'.format(params.get('export_uuid'))
    json_resp = tenable.make_rest_call(endpoint=endpoint, method='POST')
    return json_resp


def get_host_details(config, params):
    tenable = TenableIO(config)
    endpoint = 'scans/{0}/hosts/{1}'.format(params.pop('scan_uuid'), params.pop('host_id'))
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    json_resp = tenable.make_rest_call(endpoint=endpoint, params=params)
    return json_resp


def get_scan_history(config, params):
    tenable = TenableIO(config)
    endpoint = 'scans/{0}/history'.format(params.pop('scan_id'))
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    json_resp = tenable.make_rest_call(endpoint=endpoint, params=params)
    return json_resp


operations = {
    'get_scans': get_scans,
    'trigger_scan': launch_scan,
    'get_scan_assets': get_scan_assets,
    'get_asset_vulnerabilities': get_asset_vulnerabilities,
    'get_vuln_details': get_vulnerabilities_details,
    'get_plugin_details': get_plugin_details,
    'submit_vuln_export_job': submit_vuln_export_job,
    'get_vuln_export_status': get_vuln_export_status,
    'download_vuln_export_chunk': download_vuln_export_chunk,
    'list_vuln_export_jobs': list_vuln_export_jobs,
    'cancel_vuln_export_job': cancel_vuln_export_job,
    'submit_asset_export_job': submit_asset_export_job,
    'get_asset_export_status': get_asset_export_status,
    'download_asset_export_chunk': download_asset_export_chunk,
    'list_asset_export_jobs': list_asset_export_jobs,
    'cancel_asset_export_job': cancel_asset_export_job,
    'get_host_details': get_host_details,
    'get_scan_history': get_scan_history
}
