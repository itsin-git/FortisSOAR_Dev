""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import xmltodict, json, base64
from .utils import (_build_url, _generate_headers,
                    make_api_call, error_handling,
                    prepare_incident_details_body,
                    prepare_incident_violation_body,
                    prepare_update_incident_body,
                    prepare_list_incident_body)
from integrations.crudhub import make_request, make_file_upload_request
from connectors.core.connector import get_logger
from .soap_input import (LIST_INCIDENT_STATUS, LIST_CUSTOM_ATTRIB, INCIDENT_ATTACHMENT)
from .policy_utils import *

logger = get_logger('symantec-dlp')


def _validate_connectivity(config):
    url, verify_ssl, auth = _build_url(config)
    headers = _generate_headers(soapAction='listIncidentStatus')
    body = LIST_INCIDENT_STATUS
    check_health = make_api_call('post', url, auth, body=body,
                                 headers=headers, verify=verify_ssl)
    try:
        output = json.loads(json.dumps(xmltodict.parse(check_health.text)))
        output = output.get('S:Envelope').get('S:Body')
    except Exception as e:
        error_handling(e, check_health.status_code, body, {})
    if check_health.ok:
        logger.info(output)
        faultstring = output.get('S:Fault', {}).get('faultstring', '')
        logger.info(faultstring)
        if faultstring:
            raise ConnectionError(faultstring)
        return output
    error_handling("Failed to Get Incident Status" + str(output.get('S:Fault', {}).get('faultstring')),
                   check_health.status_code, body, {})


def get_incident_status(config, params):
    url, verify_ssl, auth = _build_url(config)
    headers = _generate_headers(soapAction='listIncidentStatus')
    body = LIST_INCIDENT_STATUS
    incident_status = make_api_call('post', url, auth, body=body, headers=headers, verify=verify_ssl)
    try:
        output = json.loads(json.dumps(xmltodict.parse(incident_status.text)))
        output = output.get('S:Envelope').get('S:Body')
    except Exception as e:
        error_handling(e, incident_status.status_code, body, params)
    if incident_status.ok:
        return output
    error_handling("Failed to Get Incident Status" + str(output.get('S:Fault', {}).get('faultstring')),
                   incident_status.status_code, body, params)


def get_incidents_ids(config, params):
    url, verify_ssl, auth = _build_url(config)
    headers = _generate_headers(soapAction='incidentList')
    body = prepare_list_incident_body(params)
    incident_id = make_api_call('post', url, auth, body=body, headers=headers, verify=verify_ssl)
    try:
        output = json.loads(json.dumps(xmltodict.parse(incident_id.text)))
        output = output.get('S:Envelope').get('S:Body')
    except Exception as e:
        error_handling(e, incident_id.status_code, body, params)
    if incident_id.ok:
        return output
    error_handling("Failed to Get Incident IDs" + str(output.get('S:Fault', {}).get('faultstring')),
                   incident_id.status_code, body, params)



def get_incident_details(config, params):
    url, verify_ssl, auth = _build_url(config)
    headers = _generate_headers(soapAction='incidentDetail')
    body = prepare_incident_details_body(params)
    incident_details = make_api_call('post', url, auth, body=body, headers=headers, verify=verify_ssl)
    try:
        output = json.loads(json.dumps(xmltodict.parse(incident_details.text)))
        output = output.get('S:Envelope').get('S:Body')
    except Exception as e:
        error_handling(e, incident_details.status_code, body, params)
    if incident_details.ok:
        return output
    error_handling("Failed to Get Incident Details" + str(output.get('S:Fault', {}).get('faultstring')),
                   incident_details.status_code, body, params)


def get_custom_attributes(config, params):
    url, verify_ssl, auth = _build_url(config)
    headers = _generate_headers(soapAction='listCustomAttributes')
    body = LIST_CUSTOM_ATTRIB
    custom_attrib = make_api_call('post', url, auth, body=body, headers=headers, verify=verify_ssl)
    try:
        output = json.loads(json.dumps(xmltodict.parse(custom_attrib.text)))
        output = output.get('S:Envelope').get('S:Body')
    except Exception as e:
        error_handling(e, custom_attrib.status_code, body, params)
    if custom_attrib.ok:
        return output
    error_handling("Failed to Get Custom Attributes" + str(output.get('S:Fault', {}).get('faultstring')),
                   custom_attrib.status_code, body, params)


def get_incident_violations(config, params):
    url, verify_ssl, auth = _build_url(config)
    headers = _generate_headers(soapAction='incidentViolations')
    body = prepare_incident_violation_body(params)
    incident_violations = make_api_call('post', url, auth, body=body,
                                        headers=headers, verify=verify_ssl)
    try:
        output = json.loads(json.dumps(xmltodict.parse(incident_violations.text)))
        output = output.get('S:Envelope').get('S:Body')
    except Exception as e:
        error_handling(e, incident_violations.status_code, body, params)
    if incident_violations.ok:
        return output
    error_handling("Failed to Get Incident Violation" + str(output.get('S:Fault', {}).get('faultstring')),
                   incident_violations.status_code, body, params)


def update_incident(config, params):
    url, verify_ssl, auth = _build_url(config)
    headers = _generate_headers(soapAction='updateIncidents')
    body = prepare_update_incident_body(params)
    update_incident = make_api_call('post', url, auth, body=body, headers=headers, verify=verify_ssl)
    try:
        output = json.loads(json.dumps(xmltodict.parse(update_incident.text)))
        output = output.get('S:Envelope').get('S:Body')
    except Exception as e:
        error_handling(e, update_incident.status_code, body, params)
    if update_incident.ok and output.get('ns5:incidentUpdateResponse',{}).get('batchResult',{}).get('statusCode') == 'SUCCESS':
            return output
    error_handling("Failed to Update Incident " + str(output.get('ns5:incidentUpdateResponse',{})
                                                     .get('batchResult',{}).get('statusCode')),
                   update_incident.status_code, body, params)


def create_cyops_attachment(content, attachment_name, file_name):
    file_resp = make_file_upload_request(file_name, content, 'application/octet-stream')
    description = 'Symantec DLP: {}'.format(file_name)
    payload = {'name': attachment_name, 'file': file_resp['@id'], 'description': description}
    return make_request('/api/3/attachments', 'POST', payload)


def get_incident_attachment(config, params):
    url, verify_ssl, auth = _build_url(config)
    output = {}
    headers = _generate_headers(soapAction='incidentBinaries')
    body = INCIDENT_ATTACHMENT.format(includeOriginalMessage='true' if params['includeOriginalMessage'] else 'false',
                                      includeAllComponents='true' if params['includeAllComponents'] else 'false',
                                      incident_id=params['incident_long_id']
                                      )
    logger.info('body= {}'.format(body))
    incident_details = make_api_call('post', url, auth, body=body, headers=headers, verify=verify_ssl)
    try:
        output = json.loads(json.dumps(xmltodict.parse(incident_details.text)))
        output = output.get('S:Envelope').get('S:Body')
    except Exception as e:
        error_handling(e, incident_details.status_code, body, params)
    output_lst = []
    if incident_details.ok:
        if output.get('ns5:incidentBinariesResponse').get('ns5:originalMessage'):
            output['ns5:incidentBinariesResponse']['ns5:originalMessage'] = base64.b64decode(output.get('ns5:incidentBinariesResponse').get('ns5:originalMessage').encode('utf-8'))

        incident_bin_comp = output.get('ns5:incidentBinariesResponse').get('ns5:Component')
        if incident_bin_comp:
            if type(incident_bin_comp) is dict:
                incident_bin_comp = [incident_bin_comp]
            if type(incident_bin_comp) is list:
                for item in incident_bin_comp:
                    attachment_content = item.get('ns5:content')
                    file_name = item.get('ns5:name')
                    logger.info('filename = {}'.format(file_name))
                    attachment_name = 'Symantec DLP: Incident ID: {}: Filename: {}'.format(params['incident_long_id'], file_name)
                    res = create_cyops_attachment(base64.b64decode(attachment_content.encode('utf-8')), attachment_name, file_name)
                    output_lst.append(res)
            output['ns5:incidentBinariesResponse']['ns5:Component'] = output_lst
        return output
    error_handling("Failed to Get Incident Attachments" + str(output.get('S:Fault', {}).get('faultstring')),
                   incident_details.status_code, body, params)

def download_eml(config, params):
    params['includeOriginalMessage'] = True
    params['includeAllComponents'] = False
    response = get_incident_attachment(config, params)
    file_name = 'incident_{}.eml'.format(params.get('incident_long_id'))
    file_content = response.get('ns5:incidentBinariesResponse').get('ns5:originalMessage')

    if params.get('save_as_attachment'):
        attachment_name = 'Symantec DLP: Incident ID: {}: Filename: {}'.format(params['incident_long_id'], file_name)
        res = create_cyops_attachment(file_content, attachment_name, file_name)
        return res
    else:
        file_resp = make_file_upload_request(file_name, file_content, 'application/octet-stream')
        return file_resp


def update_sender_recipient_pattern(config, params):
    if params.get("rule_type") == "Sender":
        config["type"] = "Sender Pattern"
    else:
        config["type"] = "Recipient Pattern"

    sym = SymatecDLP_Policy(config)
    sym.get_list(params.get("pattern_name"))
    resp = sym.update_policy(params)
    sym.logoff()
    return resp


def get_sender_recipient_pattern(config, params):
    if params.get("rule_type") == "Sender":
        config["type"] = "Sender Pattern"
    else:
        config["type"] = "Recipient Pattern"

    sym = SymatecDLP_Policy(config)
    sym.get_list(params.get("pattern_name"))
    ip_list, email_id_list, url_domain_list, description = sym.get_policy()
    # The list could be either populated or blank.
    resp = {
        "ips": ip_list ,
        "emails": email_id_list ,
        "urls_domains":url_domain_list
    }
    sym.logoff()
    return resp


operations = {
    'get_incident_status': get_incident_status, #done
    'get_incidents_ids': get_incidents_ids,
    'get_incident_details': get_incident_details, #done
    'get_incident_attachment': get_incident_attachment,
    'get_custom_attributes': get_custom_attributes, #doone
    'get_incident_violations': get_incident_violations,
    'update_incident': update_incident,
    'download_eml': download_eml,
    'update_sender_recipient_pattern': update_sender_recipient_pattern,
    'get_sender_recipient_pattern': get_sender_recipient_pattern
}
