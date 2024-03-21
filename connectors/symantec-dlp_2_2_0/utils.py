""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import requests
from sys import _getframe
from connectors.core.connector import get_logger, ConnectorError
from .soap_input import *

logger = get_logger('symantec-dlp')


def check_config_url(config):
    if config.get('server_url').startswith('https://'):
        config['server_url'] = config.get('server_url')[8:]
    elif config.get('server_url').startswith('http://'):
        config['server_url'] = config.get('server_url')[7:]
    return config


def make_api_call(method, url, auth, headers, verify=True, timeout=40, body=None, error_message=None):
    operation_name = str(_getframe(1).f_code.co_name)
    request_func = getattr(requests, method)
    error_log_msg = "Response from Api: Operation Name: {operation_name}. Output: Generic Error occurred for url: [{url}]" \
                    " with error as: {error_text}"
    try:
        res = request_func(url,
                           data=body if body else None,
                           headers=headers,
                           verify=verify,
                           timeout=timeout,
                           auth=auth)
        return res
    except requests.exceptions.SSLError as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))
    except requests.exceptions.ConnectionError as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))
    except requests.exceptions.RequestException as e:
        logger.exception(error_log_msg.format(operation_name=operation_name, url=url, error_text=str(e)))
        if error_message:
            raise ConnectorError(error_message)
        else:
            raise ConnectorError(error_log_msg.format(operation_name=operation_name, url=url, error_text=str(e)))
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def _build_url(config):
    """ Concatenate URLs """
    port = config.get('port') if config.get('port') else 8443
    if port:
        url = '{protocol}://{server_url}:{port}/{method_args}'.format(protocol=config.get('protocol'),
                                                               server_url=config.get('server_url'), port=port,
                                                               method_args='ProtectManager/services/v2011/incidents')
    else:
        url = '{protocol}://{server_url}/{method_args}'.format(protocol=config.get('protocol'),
                                                           server_url=config.get('server_url'),
                                                           method_args='ProtectManager/services/v2011/incidents')
    verify_ssl = config.get('verify_ssl', True)
    auth = (config.get('username'), config.get('password'))
    return url, verify_ssl, auth


def _generate_headers(soapAction):
    return {
        'SOAPAction': soapAction,
        'Content-Type': 'text/xml',
    }



def error_handling(exception_message, status_code, body, params):
    logger.error('body is {body}'.format(body=body))
    logger.error('params are {params}'.format(params=params))
    logger.error("Response from API [{error_message}] message".format(
        error_message=exception_message))
    raise ConnectorError("Response from API: [{error_message}] message with error_code [{error_code}]".format(
        error_message=exception_message, error_code=status_code))


def prepare_incident_details_body(params):
    incident_long_id = params['incident_long_id'] if type(params['incident_long_id']) == list \
        else str(params['incident_long_id']).split(',')
    incident_long_ids = ''
    for ele in incident_long_id:
        incident_long_ids += INCIDENT_LONG_ID.format(ele)
    include_violations = 'true' if params.get('include_violations') else 'false'
    include_history = 'true' if params.get('include_history') else 'false'
    incident_details = INCIDENT_DETAIL.format(include_violations, include_history, incident_long_ids)
    return incident_details


def prepare_incident_violation_body(params):
    include_image_violations = 'true' if params.get('include_image_violations') else 'false'
    incident_long_id = params.get('incident_long_id')
    incident_violations = INCIDENT_VIOLATIONS.format(incident_long_id, include_image_violations)
    return incident_violations


def prepare_update_incident_body(params):
    incident_long_id = params.get('incident_long_id')
    severity = INCIDENT_SEVERITY.format(params.get('severity')) if params.get('severity') else ''
    logger.info(severity)
    status = INCIDENT_STATUS.format(params.get('status')) if params.get('status') else ''
    notes = ''
    if params.get('note')and params.get('note_creation_date'):
        notes = NOTES.format(params.get('note_creation_date'), params.get('note'))
    remediation_status = REMEDIATION_STATUS.format(params.get('remediation_status')) if \
        params.get('remediation_status') else ''
    remediation_location = REMEDIATION_LOCATIONS.format(params.get('remediation_location')) if \
        params.get('remediation_location') else ''
    custom_attrib = ''
    custom_attrib_str = ''
    if len(params.get('custom_attrib_value')) >= 1:
        cust_attr_dict = params.get('custom_attrib_value')
        for key, value in cust_attr_dict.items():
            custom_attrib = CUSTOM_ATTRIB.format(str(key), str(value))
            custom_attrib_str = custom_attrib_str + custom_attrib
    update_incident = UPDATE_INCIDENT.format(severity=severity, status=status, notes=notes,
                                             custom_attrib_str=custom_attrib_str, remediation_status= remediation_status,
                                             remediation_location=remediation_location, incident_long_id=incident_long_id)
    return update_incident


def prepare_list_incident_body(params):
    report_id = params.get('report_id')
    creation_date_greater_then = params.get('creation_date_greater_then')
    list_incident = INCIDENT_LIST.format(report_id, creation_date_greater_then)
    return list_incident
