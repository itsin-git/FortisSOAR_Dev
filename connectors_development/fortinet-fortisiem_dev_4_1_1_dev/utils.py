""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import xmltodict, time
from datetime import datetime, timedelta
from connectors.core.connector import ConnectorError, get_logger
from .schema import incident_schema, discover_device_schema
from .constants import *

logger = get_logger('fortinet-fortisiem')


def str_to_list(input_str):
    if isinstance(input_str, str) and len(input_str) > 0:
        return [int(x.strip()) for x in input_str.split(',')]
    elif isinstance(input_str, list):
        return input_str
    elif isinstance(input_str, int):
        return [int(input_str)]
    else:
        return []


def str_to_list_for_stings(input_str):
    if isinstance(input_str, str) and len(input_str) > 0:
        return [x.strip() for x in input_str.split(',')]
    elif isinstance(input_str, list):
        return input_str
    elif isinstance(input_str, int):
        return [input_str]
    else:
        return []


def get_epoch(_date):
    try:
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        return int(time.mktime(time.strptime(_date, pattern)))
    except Exception as Err:
        logger.error('get_epoch: Exception occurred [{0}]'.format(str(Err)))
        raise ConnectorError('get_epoch: Exception occurred [{0}]'.format(str(Err)))


def calculate_epoc_time(params):
    try:
        start_datetime, end_datetime = params.get('from', ''), params.get('to', '')
        if start_datetime and end_datetime:
            start_time_epoch, end_time_epoch = get_epoch(start_datetime), get_epoch(end_datetime)
            # If provided start datetime is greater than the end datetime then returns 1440 minutes i.e last 24 hours
            minutes = '<Window unit="Minute" val="1440"/>' if start_time_epoch > end_time_epoch else \
                '<Low>{low}</Low><High>{high}</High>'.format(low=start_time_epoch, high=end_time_epoch)
            return minutes
        elif start_datetime:
            start_time_epoch = get_epoch(start_datetime)
            return '<Low>{low}</Low>'.format(low=start_time_epoch)
        elif end_datetime:
            end_time_epoch = get_epoch(end_datetime)
            return '<High>{high}</High>'.format(high=end_time_epoch)
        else:
            #If start and end time not given then by default it will take last 2 weeks
            end_time_epoch = int(datetime.now().strftime('%s'))
            two_weeks_back = datetime.now() - timedelta(days=14)
            start_time_epoch = int(two_weeks_back.strftime('%s'))
        time_xml = """<Low>{0}</Low>
                <High>{1}</High>""".format(start_time_epoch, end_time_epoch)
        return time_xml
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_records(fortisiem_obj, headers, query_id, begin=0, end=1000):
    logger.info('begin = {} and end= {}'.format(begin, end))
    endpoint = '/rest/query/events/{query_id}/{begin}/{end}'.format(query_id=query_id, begin=begin if begin else 0,
                                                                        end=end if end else 50)
    xml_resp = fortisiem_obj.make_rest_call(endpoint, headers=headers)
    p = xml_resp.replace('\\u0000', 'CYOPS_NULL').replace('"', "'").replace('\n', '').replace('\b', '')\
        .replace('\u0000', 'CYOPS_NULL')
    json_resp = xmltodict.parse(p)
    return json_resp


def send_discovery_request(params, headers, fortisiem_obj):
    headers['Content-Type'] = 'text/xml'
    endpoint = '/rest/deviceMon/discover'
    final_schema = discover_device_schema.format(
                                                 disc_type=params['discovery_type'].replace(' ', ''),
                                                 include_ip=params.get('includeIps'),
                                                 exclude_ip=params.get('excludeIps', ''),
                                                 noping='true' if params.get('noping') else 'false',
                                                 onlyping='true' if params.get('onlyping') else 'false'
                                                 )
    response = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=final_schema, method='PUT')
    return response


def get_query_progress_status(fortisiem_obj, query_id, headers):
    try:
        endpoint = '/rest/query/progress/{query_id}'.format(query_id=query_id)
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers)
        iteration = 30  # Used for until progress reaches 100 in 30 seconds
        while response != '100' and iteration:
            response = fortisiem_obj.make_rest_call(endpoint, headers=headers)
            time.sleep(2)
            iteration -= 2
        if iteration == 0 and response != '100':
            return False
        return True
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def get_event_query(fortisiem_obj, xml_request_payload):
    try:
        headers = fortisiem_obj.generate_headers()
        headers['Content-Type'] = 'text/xml'
        endpoint = '/rest/query/eventQuery'
        response = fortisiem_obj.make_rest_call(endpoint, headers=headers, data=xml_request_payload, method='POST')
        return response, headers
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def monitored_org(fortisiem_obj):
    endpoint = '/rest/config/Domain'
    resp = fortisiem_obj.make_rest_call(endpoint)
    resp = xmltodict.parse(resp)
    domains = resp['response']['result']['domains']['domain']
    domains_list = domains if isinstance(domains, list) else [domains]
    return domains_list


def list_to_str(params, key, val):
    try:
        tmp_input_list = params.get(key)
        temp_evt_lst = []
        if type(tmp_input_list) is list:
            for item in tmp_input_list:
                temp_evt_lst.append("{0}".format(item))
        elif type(tmp_input_list) is str:
            temp_lst = tmp_input_list.split(',')
            for item in temp_lst:
                temp_evt_lst.append("{0}".format(item.strip()))
        else:
            temp_evt_lst.append("{0}".format(tmp_input_list))
        if len(temp_evt_lst) == 1:
            event_query = '{0} IN ("{1}") AND '.format(val, temp_evt_lst[0])
        else:
            event_query = '{0} IN {1} AND '.format(val, tuple(temp_evt_lst))
        return event_query
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def build_query_for_org(params, data, fortisiem_obj):
    try:
        org_name_list = params.get('org') if isinstance(params.get('org'), list) else [params.get('org')]
        domains = monitored_org(fortisiem_obj)
        org_ids = []
        for org_name in org_name_list:
            for domain_item in domains:
                if org_name == domain_item['name']:
                    org_ids.append(domain_item['domainId'])

        if len(org_ids) == 1:
            org_query = 'phCustId IN ({0}) AND '.format(org_ids[0])
        elif len(org_ids) == 0:
            raise ConnectorError('Input organization name id not found/invalid')
        else:
            org_query = 'phCustId IN {0} AND '.format(tuple(org_ids))
        data += org_query
        return data
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def make_query_payload(fortisiem_obj, params):
    try:
        if params.get('incidentId'):
            if isinstance(params.get('incidentId'), list):
                incident_id = '({0})'.format(','.join(map(str, params.get('incidentId'))))
            else:
                incident_id = '({0})'.format(params.get('incidentId'))
            filter_params = '<SingleEvtConstr>(incidentId IN {0}) AND (phEventCategory = 1)</SingleEvtConstr>'\
                .format(incident_id)
            final_schema = incident_schema.replace('<SingleEvtConstr>(phEventCategory = 1) AND (phCustId IN (1))'
                                                   '</SingleEvtConstr>', filter_params)
            time_selection = handle_time(params)
            schema = final_schema.format(time_duration=time_selection, select_clause=params.get('select_clause', ''))
            return schema
        time_selection = handle_time(params)
        data = '(phEventCategory=1) AND '
        data = build_query_for_status_sev(params.get('status', []), data)
        data = build_query_for_status_sev(params.get('severity', []), data)

        for key, val in get_incident_param_list.items():
            if params.get(key, ''):
                tmp_qry = list_to_str(params, key, val)
                data += tmp_qry

        if params.get('org'):
            data = build_query_for_org(params, data, fortisiem_obj)

        data = build_query_for_host(params, data, host_ip='hostname')
        data = build_query_for_host(params, data, host_ip='ip')

        filter_params = '<SingleEvtConstr>{filter}</SingleEvtConstr>'.format(filter=data.rstrip(' AND '))
        schema = incident_schema.format(time_duration=time_selection, select_clause=params.get('select_clause', ''))
        final_schema = schema.replace('<SingleEvtConstr>(phEventCategory = 1) AND (phCustId IN (1))</SingleEvtConstr>',
                                      filter_params)
        return final_schema
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def build_query_for_status_sev(status_sev, data):
    try:
        status_sev_query = ''
        for qparam in status_sev:
            status_sev_query += incident_query_map[qparam.lower()]
        if status_sev_query:
            data += '({0})'.format(status_sev_query.rstrip(' OR ')) + ' AND '
        return data
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def build_query_for_host(params, data, host_ip=''):
    try:
        host_query = ''
        if params.get(host_ip):
            host = params[host_ip] if isinstance(params[host_ip], list) else [params[host_ip]]
            for each_host in host:
                host_query += '( incidentSrc CONTAIN "{host}," OR incidentTarget CONTAIN "{host},") OR '.\
                    format(host=each_host)
        if host_query:
            data += '({0})'.format(host_query.rstrip(' OR ')) + ' AND '
        return data
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def handle_time(params):
    selected_time = params.get('rel_time', '')
    start_datetime, end_datetime = params.get('from', ''), params.get('to', '')
    selected_time_value = params.get('value', '')
    if start_datetime and end_datetime:
        start_time_epoch, end_time_epoch = get_epoch(start_datetime), get_epoch(end_datetime)
        # If provided start datetime is greater than the end datetime then return one minute instead of zero.
        minutes = '<Window unit="Minute" val="1"/>' if start_time_epoch > end_time_epoch else \
            '<Low>{low}</Low><High>{high}</High>'.format(low=start_time_epoch, high=end_time_epoch)
        return minutes

    minutes = selected_time_value * time_map[selected_time] if selected_time and selected_time_value > 0 else (2 * 60)  # Default 2 Hours
    return '<Window unit="Minute" val="{minutes}"/>'.format(minutes=minutes)


def make_output(response, query_id=None, eventFlag=False):
    if eventFlag:
        result = {'events': []}
    else:
        result = {'events': [],
              '@totalCount': response['queryResult']['@totalCount'],
              '@start': response['queryResult']['@start'],
              '@queryId': query_id if query_id else response['queryResult']['@queryId'],
              '@errorCode': response['queryResult']['@errorCode']
              }
    if response['queryResult']['@totalCount'] == '0':
        return result
    event_records = response['queryResult']['events']['event']
    events_list = event_records if isinstance(event_records, list) else [event_records]

    for record in events_list:
        attributes = {}
        if not isinstance(record['attributes']['attribute'], list):
            record['attributes']['attribute'] = [record['attributes']['attribute']]
        for item in record['attributes']['attribute']:
            if item['@name'] == 'incidentDetail':
                attributes[item['@name']] = item.get('#text', '').replace("<![CDATA[", "").replace("]]>", "")
            else:
                attributes[item['@name']] = item.get('#text', '')
        record['attributes'] = attributes
        result['events'].append(record)
    return result

