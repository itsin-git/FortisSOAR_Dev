""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request, exceptions as req_exceptions
from .microsoft_api_auth import *
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config

logger = get_logger('azure-log-analytics')

MANAGE_SERVER_URL = 'https://management.azure.com'
MANAGE_API_VERSION = '2020-08-01'
LOG_SERVER_URL = 'https://api.loganalytics.io'
LOG_API_VERSION = '2022-10-27_Preview'


class AzureLogAnalytics(object):
    def __init__(self, config):
        self.server_url = LOG_SERVER_URL
        self.manage_server_url = MANAGE_SERVER_URL
        self.verify_ssl = config.get('verify_ssl')
        self.ms_auth = MicrosoftAuth(config)
        self.tenant_id = config.get('tenant_id')
        self.connector_info = config.pop('connector_info', '')
        self.manage_token = self.ms_auth.validate_token(config, self.connector_info)
        self.log_token = self.ms_auth.validate_log_token(config, self.connector_info)
        self.api_version = MANAGE_API_VERSION

    def api_request(self, method, endpoint, config, params=None, data=None, headers={},
                    manage_api_endpoint=False):
        try:
            if manage_api_endpoint:
                headers = {
                    'Authorization': self.manage_token,
                    'Content-Type': 'application/json'
                }
                service_url = self.manage_server_url + endpoint
                params['api-version'] = MANAGE_API_VERSION
            else:
                headers = {
                    'Authorization': self.log_token,
                    'Content-Type': 'application/json'
                }
                service_url = self.server_url + endpoint
                params['api-version'] = LOG_API_VERSION
            try:
                response = request(method, service_url, headers=headers, params=params, json=data,
                                   verify=self.verify_ssl)
                logger.debug("Response Status Code: {0}".format(response.status_code))
                logger.debug("Response: {0}".format(response.text))
                logger.debug("API Header: {0}".format(response.headers))
                if response.status_code in [200, 201, 204]:
                    if response.text != "":
                        return response.json()
                    else:
                        return True
                else:
                    if response.text != "":
                        err_resp = response.json()
                        failure_msg = err_resp['error']['message']
                        error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                             failure_msg if failure_msg else '')
                    else:
                        error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
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
                raise ConnectorError(str(err))
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    final_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                final_payload[key] = nested
        elif value is not None and value != '':
            final_payload[key] = value
    return final_payload


def build_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def execute_query(config, params):
    try:
        al = AzureLogAnalytics(config)
        endpoint = '/v1/workspaces/{0}/query'.format(config.get('workspace_id'))
        workspaces = config.get("workspace_name")
        if workspaces:
            workspaces = workspaces.split(",")
        payload = {
            'query': params.get('query'),
            'timespan': params.get('timespan'),
            'workspaces': workspaces
        }
        payload = build_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = al.api_request("POST", endpoint, config=config, data=payload, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def list_saved_searches(config, params):
    try:
        al = AzureLogAnalytics(config)
        endpoint = '/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/savedSearches'.format(
            config.get('subscription_id'), config.get('resource_group_name'), config.get('workspace_name'))
        response = al.api_request("GET", endpoint, config, manage_api_endpoint=True, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_saved_searches(config, params):
    try:
        al = AzureLogAnalytics(config)
        endpoint = '/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/savedSearches/{3}'.format(
            config.get('subscription_id'), config.get('resource_group_name'), config.get('workspace_name'),
            params.get('savedSearchId'))
        response = al.api_request("GET", endpoint, config, manage_api_endpoint=True, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_saved_searches(config, params):
    try:
        al = AzureLogAnalytics(config)
        endpoint = '/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/savedSearches/{3}'.format(
            config.get('subscription_id'), config.get('resource_group_name'), config.get('workspace_name'),
            params.get('savedSearchId'))
        additional_fields = params.get('additional_fields')
        payload = {
            "etag": params.get('etag'),
            "properties": {
                "category": params.get('category'),
                "displayName": params.get('displayName'),
                "query": params.get('query')
            }
        }
        if additional_fields:
            payload['properties'].update(additional_fields)
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = al.api_request("PUT", endpoint, config, data=payload, manage_api_endpoint=True, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_saved_searches(config, params):
    try:
        al = AzureLogAnalytics(config)
        endpoint = '/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/savedSearches/{3}'.format(
            config.get('subscription_id'), config.get('resource_group_name'), config.get('workspace_name'),
            params.get('savedSearchId'))
        additional_fields = params.get('additional_fields')
        payload = {
            "etag": "*",
            "properties": {
                "category": params.get('category'),
                "displayName": params.get('displayName'),
                "query": params.get('query')
            }
        }
        if additional_fields:
            payload['properties'].update(additional_fields)
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = al.api_request("PUT", endpoint, config, data=payload, manage_api_endpoint=True, params={})
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def delete_saved_search(config, params):
    try:
        al = AzureLogAnalytics(config)
        endpoint = '/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/savedSearches/{3}'.format(
            config.get('subscription_id'), config.get('resource_group_name'), config.get('workspace_name'),
            params.get('savedSearchId'))
        response = al.api_request("DELETE", endpoint, config, manage_api_endpoint=True, params={})
        return {'result': 'Deleted Saved Search {0} successfully'.format(params.get('savedSearchId'))}
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def check(config, connector_info):
    try:
        ms = MicrosoftAuth(config)
        config_id = config['config_id']
        if 'accessToken' in config and 'logAccessToken' in config:
            ms.validate_token(config, connector_info) and ms.validate_log_token(config, connector_info)
        elif 'accessToken' not in config and 'logAccessToken' in config:
            token_resp = ms.generate_token()
            config['accessToken'] = token_resp.get('accessToken')
            config['expiresOn'] = token_resp.get('expiresOn')
            config['refresh_token'] = token_resp.get('refresh_token')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id']) and ms.validate_log_token(config, connector_info)
        elif 'accessToken' in config and 'logAccessToken' not in config:
            token_resp = ms.generate_token(LOG_SCOPE)
            config['logAccessToken'] = token_resp['accessToken']
            config['logExpiresOn'] = token_resp['expiresOn']
            config['logRefreshToken'] = token_resp.get('refresh_token')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id']) and ms.validate_log_token(config, connector_info)
        else:
            token_resp = ms.generate_token()
            config['accessToken'] = token_resp.get('accessToken')
            config['expiresOn'] = token_resp.get('expiresOn')
            config['refresh_token'] = token_resp.get('refresh_token')
            token_resp = ms.generate_token(LOG_SCOPE)
            config['logAccessToken'] = token_resp['accessToken']
            config['logExpiresOn'] = token_resp['expiresOn']
            config['logRefreshToken'] = token_resp.get('refresh_token')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id']) and ms.validate_log_token(config, connector_info)
        config['config_id'] = config_id
        return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'execute_query': execute_query,
    'list_saved_searches': list_saved_searches,
    'get_saved_searches': get_saved_searches,
    'create_saved_searches': create_saved_searches,
    'update_saved_searches': update_saved_searches,
    'delete_saved_search': delete_saved_search
}
