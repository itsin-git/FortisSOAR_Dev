""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json

from .schema import report_schema, schema_by_event_id, search_event_schema
from .attributes_list import *
from .watch_list_actions import *
from .lookup_table_actions import *
from .resource_list_actions import *

requests.packages.urllib3.disable_warnings()


def get_devices_details(config, params):
    fortisiem_obj = FortiSIEM(config)
    params['organization'] = params.get('org', None)
    endpoint = '/rest/cmdbDeviceInfo/devices'
    resp = fortisiem_obj.make_rest_call(endpoint, params=params)
    response = xmltodict.parse(resp)
    if response.get('response'):
        return response['response']['error']['description']
    return response if response.get('devices') else {'devices': {'device': [response['device']]}}


def get_device_info(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        endpoint = '/rest/cmdbDeviceInfo/device'
        params_dict = {
            'organization': params.get('org'),
            'loadDepend': True,
            'ip': params.get('ip')
        }
        resp = fortisiem_obj.make_rest_call(endpoint, params_dict)
        return xmltodict.parse(resp)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_monitored_devices(config, params):
    fortisiem_obj = FortiSIEM(config)
    endpoint = '/rest/deviceInfo/monitoredDevices'
    resp = fortisiem_obj.make_rest_call(endpoint)
    res_json = xmltodict.parse(resp)
    return res_json


def get_monitored_organizations(config, params):
    fortisiem_obj = FortiSIEM(config)
    return monitored_org(fortisiem_obj)


def get_org_name_by_org_id(config, params):
    fortisiem_obj = FortiSIEM(config)
    org_list = monitored_org(fortisiem_obj)
    domain_id = str(params.get('domain_id'))
    for domain in org_list:
        if domain_id == str(domain['domainId']):
            return domain
    return 'Organization not found for provided organization ID {0}'.format(domain_id)


def convert_time_to_miliseconds(input_datetime):
    try:
        if input_datetime:
            return int(time.mktime(time.strptime(input_datetime, '%Y-%m-%dT%H:%M:%S.%fZ'))) * 1000
        else:
            return ''
    except Exception as err:
        raise ConnectorError(err)


def reformat_response(res):
    data = res.get('data', [])
    for item in data:
        if item.get('attackTechnique'):
            try:
                item['attackTechnique'] = json.loads(item.get('attackTechnique'))
            except:
                pass
        if item.get('incidentTarget'):
            tmp_lst = {k.strip(): v.strip() for k, v in (dict(filter(lambda y: len(y) == 2, map(lambda x: x.split(':'),
                                                        str(item.get('incidentTarget').strip()).split(','))))).items()}
            item['incidentTarget'] = tmp_lst
        if item.get('incidentSrc'):
            tmp_lst = {k.strip(): v.strip() for k, v in (dict(filter(lambda y: len(y) == 2, map(lambda x: x.split(':'),
                                                    str(item.get('incidentSrc').strip()).split(','))))).items()}
            item['incidentSrc'] = tmp_lst
    res['data'] = data
    return res


def get_incidents(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        endpoint = '/rest/pub/incident'
        # incidentLastSeen DESC
        orderBy_field = ''
        sort_order = 'incidentLastSeen'
        if params.get('orderBy'):
            orderBy = params.get('orderBy').split(' ')
            if len(orderBy) == 2:
                orderBy_field = orderBy[0]
                sort_order = orderBy[1]
        data = {
            "filters": params.get('search', {}) if len(params.get('search', {})) > 0 else {},
            "start": params.get('start'),
            "size": params.get('size'),
            "timeFrom": convert_time_to_miliseconds(params.get('timeFrom')),
            "timeTo": convert_time_to_miliseconds(params.get('timeTo')),
            "orderBy": orderBy_field,
            "descending": True if sort_order == 'DESC' else False,
            "fields": str_to_list_for_stings(params.get('fields'))
        }
        if params.get('incidentStatus'):
            status_list = []
            for item in params.get('incidentStatus'):
                if PARAMS_MAPPING.get(item):
                    status_list.append(PARAMS_MAPPING.get(item))
            data['filters'].update({'status': status_list})

        if params.get('incidentCategory'):
            data['filters'].update({'phIncidentCategory': str_to_list_for_stings(params.get('incidentCategory'))})

        # this filter is not working
        if params.get('incidentSubCategory'):
            data['filters'].update({'phSubIncidentCategory': str_to_list_for_stings(params.get('incidentSubCategory'))})

        # this filter is not working
        if params.get('severity'):
            data['filters'].update({'eventSeverityCat': params.get('severity')})

        if params.get('eventType'):
            data['filters'].update({'eventType': str_to_list_for_stings(params.get('eventType'))})

        data = {k: v for k, v in data.items() if v is not None and v != '' and v != {} and v != []}
        res = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=json.dumps(data), method='POST')
        return reformat_response(res)
    except Exception as err:
        raise ConnectorError(err)


def get_incident_details(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        endpoint = '/rest/pub/incident'
        if not isinstance(params.get('incidentId'), list):
            params['incidentId'] = [params.get('incidentId')]
        data = {
            "filters": {
                "incidentId": params.get('incidentId')
            },
            "timeFrom": convert_time_to_miliseconds(params.get('timeFrom')),
            "timeTo": convert_time_to_miliseconds(params.get('timeTo'))
        }
        data = {k: v for k, v in data.items() if v is not None and v != '' and v != {} and v != []}
        return fortisiem_obj.make_rest_call(endpoint, headers=headers, data=json.dumps(data), method='POST')
    except Exception as err:
        raise ConnectorError(err)


def update_incident(config, params):
    try:
        params['incidentStatus'] = PARAMS_MAPPING.get(params.get('incidentStatus'))
        params['incidentId'] = str(params.get('incidentId'))
        params["resolution"] = PARAMS_MAPPING.get(params.get('resolution'), '')
        params_list = {k: str(v) for k, v in params.items() if v is not None and v != ''}
        return update_incident_data(config, params, params_list, 'Incident updated')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def incident_comment(config, params):
    try:
        body = {
            "incidentId": str(params.get('id')),
            "comments": params.get('comment_text')
        }
        return update_incident_data(config, params, body, 'Successfully added comment to incident')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def clear_incident(config, params):
    try:
        body = {
            "incidentId": str(params.get('id')),
            "incidentStatus": "2",
            "comments": params.get('comment_text')
        }
        return update_incident_data(config, params, body, 'Successfully cleared specified incident with reason')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def _get_event_details(fortisiem_obj, time_xml, params):
    try:
        build_xml = '(eventId IN ({})  AND  phEventCategory &gt;= 0)'.format(
            params.get('event_id'))
        xml_payload = schema_by_event_id.format(eventId=build_xml, time_duration=time_xml)

        query_id, headers = get_event_query(fortisiem_obj, xml_payload)
        query_status = get_query_progress_status(fortisiem_obj, query_id, headers)
        if query_status:
            incidents_records = get_records(fortisiem_obj, headers, query_id, params.get('start'), params.get('perPage'))
            final_result = make_output(incidents_records, query_id)
            return final_result.get('events')
        else:
            raise ConnectorError('Query progress status is still in progress')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_associated_events(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        headers.update({'Content-Type': 'application/json', 'Accept': 'application/json'})
        endpoint = '/rest/pub/incident/triggeringEvents?incidentId={0}&size={1}'.format(params.get('incident_id'),
                                                                                        params.get('perPage') if params.get('perPage') else 10)
        return fortisiem_obj.make_rest_call(endpoint, headers=headers)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def run_report(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        xml_request_payload = report_schema.format(AttrList=params.get('AttrList') if params.get('AttrList') else '',
                                               orderby=params.get('orderby') if params.get('orderby') else '',
                                               conditions=params.get('cond', ''), groupby=params.get('groupby', ''),
                                               time_duration=handle_time(params)
                                               )
        xml_request_payload = xml_request_payload.replace('None', '')
        query_id, headers = get_event_query(fortisiem_obj, xml_request_payload)
        query_status = get_query_progress_status(fortisiem_obj, query_id, headers)
        if query_status:
            incidents_records = get_records(fortisiem_obj, headers, query_id, params.get('start'), params.get('perPage'))
            return make_output(incidents_records, query_id)
        else:
            raise ConnectorError('Query progress status is still in progress')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_event_details(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        time_xml = calculate_epoc_time(params)
        res = _get_event_details(fortisiem_obj, time_xml, params)
        if res == []:
            return {}
        else:
            return res[0]
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def update_incident_data(config, params, body, msg):
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        if params.get('id'):
            result = {'message': 'Provided incident does not exist', 'incident_id': params.get('id')}
        else:
            result = {'message': 'Provided incident does not exist', 'incident_id': params.get('incidentId')}
        endpoint = '/rest/incident/external?incident='
        res = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=json.dumps(body), method='POST')
        if res == '"OK"':
            result['message'] = msg
        return result
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_incident_attributes(config, params):
    return attribute_list


def search_events(config, params):
    try:
        attribute = params.get('attribute')
        temp_str = ''
        report_name = ''
        fortisiem_obj = FortiSIEM(config)
        if type(attribute) is list:
            for item in attribute:
                report_name = report_name + item
                temp = (item.replace(' ', '_')).lower()
                param_value = temp + "_value"
                if param_value == "event_action_value":
                    op_value = event_mapping.get(params.get(temp + "_value"))
                else:
                    op_value = params.get(temp + "_value")
                temp_str = temp_str + attribute_mapping.get(item).format(op_value) + ' AND '
        temp_str = temp_str[:-5]
        logger.info('Query string is = {}'.format(temp_str))
        xml_request_payload = search_event_schema.format(queryString = temp_str, reportName=report_name,
                                                         time_duration=handle_time(params),
                                                         select_clause=params.get('select_clause'))
        xml_request_payload = xml_request_payload.replace('None', '')
        query_id, headers = get_event_query(fortisiem_obj, xml_request_payload)
        query_status = get_query_progress_status(fortisiem_obj, query_id, headers)
        if query_status:
            incidents_records = get_records(fortisiem_obj, headers, query_id, params.get('start'), params.get('perPage'))
            return make_output(incidents_records, query_id)
        else:
            raise ConnectorError('Query progress status is still in progress')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_events_by_query_id(config, params):
    try:
        fortisiem_obj = FortiSIEM(config)
        headers = fortisiem_obj.generate_headers()
        headers['Content-Type'] = 'text/xml'
        query_id = ','.join(map(str, params.get('query_id'))) if isinstance(params.get('query_id'), list) \
            else params.get('query_id')
        incidents_records = get_records(fortisiem_obj, headers, query_id, params.get('start'), params.get('perPage'))
        return make_output(incidents_records, query_id)
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def _check_health(config):
    try:
        list_data = get_monitored_organizations(config, {})
        if list_data:
            return True
    except Exception as err:
        raise ConnectorError('{0}'.format(err))


operations = {
    'get_incidents': get_incidents,
    'get_incident_details': get_incident_details,
    'update_incident': update_incident,
    'incident_comment': incident_comment,
    'clear_incident': clear_incident,
    'get_associated_events': get_associated_events,
    'get_monitored_devices': get_monitored_devices,
    'get_devices_details': get_devices_details,
    'get_devices_details_in_address': get_devices_details,
    'get_device_info': get_device_info,
    'get_monitored_organizations': get_monitored_organizations,
    'get_org_name_by_org_id': get_org_name_by_org_id,
    'run_report': run_report,
    'get_event_details': get_event_details,
    'search_events': search_events,
    'get_incident_attributes': get_incident_attributes,
    'get_events_by_query_id': get_events_by_query_id,

    'get_watch_lists': get_watch_lists,
    'add_watch_list_entries_to_watch_list_groups': add_watch_list_entries_to_watch_list_groups,
    'create_watchlist_group': create_watchlist_group,
    'update_watch_list_entry': update_watch_list_entry,
    'delete_watch_list_entry': delete_watch_list_entry,
    'delete_watch_list': delete_watch_list,
    'get_watch_list_entry': get_watch_list_entry,
    'get_watch_list_entries_count': get_watch_list_entries_count,

    'get_all_lookup_tables': get_all_lookup_tables,
    'create_lookup_table': create_lookup_table,
    'delete_lookup_table': delete_lookup_table,
    'import_lookup_table_data': import_lookup_table_data,
    'check_import_task_status': check_import_task_status,
    'get_lookup_table_data': get_lookup_table_data,
    'update_lookup_table_data': update_lookup_table_data,
    'delete_lookup_table_data': delete_lookup_table_data,

    'get_all_resource_list': get_all_resource_list,
    'get_resource_list_entries': get_resource_list_entries,
    'add_entries_to_resource_list': add_entries_to_resource_list,
    'remove_entries_from_resource_list': remove_entries_from_resource_list

}
