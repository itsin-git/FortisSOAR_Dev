""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json
import cbapi
from requests import request
import cbapi.models
from cbapi.response.models import Sensor, Process
from .cb_response_api import *

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('cb-rsponse')


def isolate_sensor(config, params):
    action = params.get('input_type')
    if action:
        execute = isolate_operations.get(action)
        return execute(config, params)


def unisolate_sensor(config, params):
    action = params.get('input_type')
    if action:
        execute = unisolate_operations.get(action)
        return execute(config, params)


def terminate_process(config, params):
    action = params.get('select_type')
    if action:
        execute = terminate_process_operations.get(action)
        return execute(config, params)


def get_config(config):
    if config:
        server_url = config.get('server_url')
        logger.debug('get_config health check server_url: {0}'.format(str(server_url)))
        api_key = config.get('api_key')
        verify_ssl = config.get('verify_ssl', 'False')
        if all([server_url, api_key]):
            if not server_url.startswith('https://'):
                server_url = 'https://' + server_url
            return server_url, api_key, verify_ssl
        else:
            raise ConnectorError("Server url and api key is required")


def get_hostname_from_sensor_id(config, sensor_id):
    server_url, api_key, verify_ssl = get_config(config)
    try:
        endPointUrl = server_url + "/api/v1/sensor/{}".format(sensor_id)
        headers = {
            'x-auth-token': api_key
        }
        sensor = request("GET", endPointUrl, headers=headers, verify=verify_ssl)

        if sensor.status_code == 200:
            sensor_dict = json.loads(sensor.text)
            hostname = sensor_dict.get('computer_name')
            return hostname
        else:
            logger.error('Failed to get hostname from sensor id: {0}'
                         'Status code: {1}'.format(sensor_id, str(sensor.status_code)))
            return None

    except Exception as err:
        logger.error("Failure {0}".format(str(err)))


def check_health_ex(config):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    response = cb_response.api_info()
    if response:
        return True


def get_host_details(config, param):
    server_url, api_key, verify_ssl = get_config(config)
    filter_opt = param.get('input_type', None)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)

    if filter_opt == 'All':
        return cb_response.list_sensors()
    if filter_opt == 'Hostname':
        return cb_response.get_system_info(param)
    if filter_opt == 'IP Address':
        return cb_response.get_system_info(param)
    if filter_opt == 'Sensor ID':
        response_list = []
        sensor_id = param.get('value', None)
        result = cb_response.get_sensor_by_id(sensor_id)
        if isinstance(result, dict):
            response_list.append(result)
            return response_list


def get_blacklisted_hash(config, param):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.get_blacklisted_hash()


def get_file_info_md5(config, param):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.get_file_info(param)


def block_hash(config, param):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.ban_hash(param)


def unblock_hash(config, param):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.unblock_hash(param)


def run_query(config, param):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.run_query(param)


def hunt_file(config, param):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.hunt_file(param)


def search_alert(config, params):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.search_alert(params)


def update_alert(config, params):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.update_alert(params)


def bulk_update_alert(config, params):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.bulk_update_alert(params)


def get_watchlist(config, params):
    server_url, api_key, verify_ssl = get_config(config)
    cb_response = CbResponseAPI(server_url, api_key, verify_ssl)
    return cb_response.get_watchlist(params)


# Live Response
def get_process_list(config, param):
    """
    List the running processes on a machine.
    :param input:server_url, api_key, verify_ssl
    :param param:host_ip, hostname, sensor_id
    :return: list all running processes on endpoint
    """

    sensor = None
    server_url, api_key, verify_ssl = get_config(config)
    hostname, host_ip, sensor_id = validate_input_params(param)
    cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=verify_ssl)
    if host_ip:
        sensor = cb.select(Sensor).where("ip:{0}".format(str(host_ip))).first()

    elif hostname:
        sensor = cb.select(Sensor).where("hostname:{0}".format(str(hostname))).first()

    elif sensor_id:
        sensor_hostname = get_hostname_from_sensor_id(config, str(sensor_id))
        if sensor_hostname:
            sensor = cb.select(Sensor).where("hostname:{0}".format(sensor_hostname)).first()

    if not sensor:
        logger.error("{0}: sensor not found ".format(str(param)))
        raise ConnectorError("CarbonBlack.get_process_list {0}: sensor not found ".format(str(param)))

    if sensor.status == 'Online':
        with sensor.lr_session() as lr_session:
            proc = lr_session.list_processes()
            logger.info("Success")
            return proc
    else:
        logger.error("{0}: sensor is offline".format(sensor.hostname))
        raise ConnectorError("CarbonBlack.get_process_list {0}: sensor is offline".format(sensor.hostname))


def terminate_process_pid(config, param):
    """"
    Kill a running processes on the remote endpoint
    :param input:server_url, api_key, verify-ssl
    :param param:host_ip, hostname, sensor_id, pid
    :return: True if success, False if failure
    """

    sensor = None
    server_url, api_key, verify_ssl = get_config(config)
    hostname, host_ip, sensor_id = validate_input_params(param)
    pids = param.get('process_value')
    pid_list = pids

    if not isinstance(pids, list):
        pid_list = []
        pid_list.append(pids)

    cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=verify_ssl)
    if host_ip:
        sensor = cb.select(Sensor).where("ip:{0}".format(host_ip)).first()
    elif hostname:
        sensor = cb.select(Sensor).where("hostname:{0}".format(hostname)).first()
    elif sensor_id:
        sensor_hostname = get_hostname_from_sensor_id(config, sensor_id)
        if sensor_hostname:
            sensor = cb.select(Sensor).where("hostname:{0}".format(sensor_hostname)).first()

    if not sensor:
        logger.error("{0}: sensor not found ".format(str(param)))
        raise ConnectorError("CarbonBlack.terminate_process {0}: sensor not found ".format(str(param)))

    terminated_proc = []
    if sensor.status == 'Online':
        with sensor.lr_session() as lr_session:
            for pid in pid_list:
                if lr_session.kill_process(pid) is True:
                    terminated_proc.append(pid)
                    logger.info("PID {0}: Success".format(pid))
            return {"terminated_process": terminated_proc}
    else:
        logger.error("{0}: sensor is offline".format(sensor.hostname))
        raise ConnectorError("CarbonBlack.terminate_process {0}: sensor is offline".format(sensor.hostname))


def terminate_process_name(config, param):
    sensor = None
    server_url, api_key, verify_ssl = get_config(config)
    hostname, host_ip, sensor_id = validate_input_params(param)
    target_process = param.get('process_value')
    if isinstance(target_process, bytes):
        target_process = target_process.decode("utf-8")

    cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=False)
    if host_ip:
        sensor = cb.select(Sensor).where("ip:{0}".format(str(host_ip))).first()

    elif hostname:
        sensor = cb.select(Sensor).where("hostname:{0}".format(str(hostname))).first()

    elif sensor_id:
        sensor_hostname = get_hostname_from_sensor_id(config, str(sensor_id))
        if sensor_hostname:
            sensor = cb.select(Sensor).where("hostname:{0}".format(sensor_hostname)).first()

    if not sensor:
        logger.error("{0}: sensor not found ".format(str(param)))
        raise ConnectorError("CarbonBlack.terminate_process_name {0}: sensor not found ".format(str(param)))

    terminated_proc = []
    if sensor.status == 'Online':
        with sensor.lr_session() as lr_session:
            process_list = lr_session.list_processes()
            target_pids = [proc['pid'] for proc in process_list if target_process in proc['path']]
            for pid in target_pids:
                if lr_session.kill_process(pid) is True:
                    terminated_proc.append(pid)
                    logger.info("{0}: Success".format(pid))
        return {"terminated_process": terminated_proc}
    else:
        logger.error("{0}: sensor is offline".format(sensor.hostname))
        raise ConnectorError("CarbonBlack.get_process_list {0}: sensor is offline".format(sensor.hostname))


def delete_file(config, param):
    sensor = None
    server_url, api_key, verify_ssl = get_config(config)
    hostname, host_ip, sensor_id = validate_input_params(param)
    file_name = param.get('file_name')
    if isinstance(file_name, bytes):
        file_name = file_name.decode("utf-8")

    cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=False)
    if host_ip:
        sensor = cb.select(Sensor).where("ip:{0}".format(str(host_ip))).first()

    elif hostname:
        sensor = cb.select(Sensor).where("hostname:{0}".format(str(hostname))).first()

    elif sensor_id:
        sensor_hostname = get_hostname_from_sensor_id(config, str(sensor_id))
        if sensor_hostname:
            sensor = cb.select(Sensor).where("hostname:{0}".format(sensor_hostname)).first()

    if not sensor:
        logger.error("{0}: sensor not found ".format(str(param)))
        raise ConnectorError("CarbonBlack.delete_file {0}: sensor not found ".format(str(param)))

    if sensor.status == 'Online':
        try:
            with sensor.lr_session() as lr_session:
                result = lr_session.delete_file(file_name)
                logger.info("Success")
            return {"status": result,
                    "message": "Successfully deleted file [{}]".format(str(file_name))}
        except Exception as err:
            return {"status": "failure",
                    "message": str(err.message)}
    else:
        logger.error("{0}: sensor is offline".format(sensor.hostname))
        raise ConnectorError("CarbonBlack.delete_file {0}: sensor is offline".format(sensor.hostname))


# cbapi

def isolate_sensor_process_name_match(config, param):
    try:
        resp = []
        server_url, api_key, verify_ssl = get_config(config)
        cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=verify_ssl)
        process_name = param.get('value')
        if isinstance(process_name, bytes):
            process_name = process_name.decode("utf-8")
        if not isinstance(process_name, str):
            process_name = str(process_name)

        if process_name:
            query = "process_name:" + process_name
            process = cb.select(Process).where(query)
            # Search the Process and extract the Sensor elements
            sensor = set()
            for p in process:
                sensor.add(p.sensor)
            # Set the Isolation to True and Save
            for s in sensor:
                s.network_isolation_enabled = True
                s.save()
                resp.append(s.hostname)
            if resp.__len__():
                logger.info('Isolated the sensors: [{0}]'.format(str(resp)))
            else:
                logger.info('No sensor/endpoint found for isolation')
            return {"isolated_hosts": resp}
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def isolate_sensor_md5_match(config, param):
    try:
        resp = []
        server_url, api_key, verify_ssl = get_config(config)
        cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=verify_ssl)
        process_md5 = param.get("value")
        if isinstance(process_md5, bytes):
            process_md5 = process_md5.decode("utf-8")

        result = isValidHash(process_md5.__len__(), process_md5)

        if not result:
            raise ConnectorError(
                'CarbonBlack.isolate_sensor_md5_match: Failed Not a valid MD5')

        query = "process_md5:" + process_md5
        process = cb.select(Process).where(query)
        sensor = set()
        for p in process:
            sensor.add(p.sensor)
        for s in sensor:
            s.network_isolation_enabled = True
            s.save()
            resp.append(s.hostname)
        if resp.__len__():
            logger.info('Isolated sensors: [{0}]'.format(str(resp)))
        else:
            logger.info('No sensor/endpoint found for isolation')
        return {"isolated_hosts": resp}
    except Exception as err:
        logger.error("{}".format(str(err)))
        raise ConnectorError("{}".format(str(err)))


def unisolate_sensor_process_name_match(config, param):
    try:
        resp = []
        server_url, api_key, verify_ssl = get_config(config)
        cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=verify_ssl)
        process_name = param.get('value')
        if isinstance(process_name, bytes):
            process_name = process_name.decode("utf-8")
        query = "process_name:" + process_name
        process = cb.select(Process).where(query)
        # Search the Process and extract the Sensor elements
        sensor = set()
        for p in process:
            sensor.add(p.sensor)
        # Set the Isolation to False and Save
        for s in sensor:
            s.network_isolation_enabled = False
            s.save()
            resp.append(s.hostname)
        if resp.__len__():
            logger.info('[{0}]'.format(str(resp)))
        else:
            logger.info('No sensor/endpoint found for Un-isolation')

        return {"unisolated_hosts": resp}
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def unisolate_sensor_md5_match(config, param):
    try:
        resp = []
        server_url, api_key, verify_ssl = get_config(config)
        cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=verify_ssl)
        process_md5 = param.get('value')

        if isinstance(process_md5, bytes):
            process_md5 = process_md5.decode("utf-8")
        result = isValidHash(process_md5.__len__(), process_md5)

        if not result:
            logger.error('Failed. Invalid MD5')
            raise ConnectorError(
                'CarbonBlack.unisolate_sensor_md5_match: Failed not a valid MD5')
        query = "process_md5:" + process_md5
        process = cb.select(Process).where(query)
        sensor = set()
        for p in process:
            sensor.add(p.sensor)
        for s in sensor:
            s.network_isolation_enabled = False
            s.save()
            resp.append(s.hostname)
        if resp.__len__():
            logger.info('[{0}]'.format(str(resp)))
        else:
            logger.info('No sensor/endpoint found for Un-isolation')
        return {"unisolated_hosts": resp}
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def unisolate_sensor_hostname_ip(config, param):
    try:
        resp = []
        sensor = None
        server_url, api_key, verify_ssl = get_config(config)
        hostname, host_ip, sensor_id = validate_input_params(param)
        cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=verify_ssl)
        if host_ip:
            sensor = cb.select(Sensor).where("ip:{}".format(host_ip)).first()
        elif hostname:
            sensor = cb.select(Sensor).where("hostname:{}".format(hostname)).first()

        if not sensor:
            logger.error("{0}: sensor not found ".format(str(param)))
            raise ConnectorError("CarbonBlack.unisolate_sensor_hostname_ip {0}: sensor not found ".format(str(param)))

        if sensor.status == 'Online':
            sensor.network_isolation_enabled = False
            sensor.save()
            resp.append(sensor.hostname)

        else:
            logger.error("Sensor {0} is Offline".format(sensor.hostname))
            raise ConnectorError("CarbonBlack:Failed to Un-isolate. Sensor {0} is Offline".format(sensor.hostname))
        return {"unisolated_hosts": resp}

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def isolate_sensor_hostname_ip(config, param):
    try:
        resp = []
        sensor = None
        server_url, api_key, verify_ssl = get_config(config)
        hostname, host_ip, sensor_id = validate_input_params(param)
        cb = cbapi.CbEnterpriseResponseAPI(url=server_url, token=api_key, ssl_verify=False)
        if host_ip:
            sensor = cb.select(Sensor).where("ip:{0}".format(host_ip)).first()
        elif hostname:
            sensor = cb.select(Sensor).where("hostname:{0}".format(hostname)).first()

        if not sensor:
            logger.error("{0}: sensor not found ".format(str(param)))
            raise ConnectorError("{0}: sensor not found ".format(str(param)))

        if sensor.status == 'Online':
            sensor.network_isolation_enabled = True
            sensor.save()
            resp.append(sensor.hostname)
        else:
            logger.error(
                "Sensor {0} is Offline".format(sensor.hostname))
            raise ConnectorError("CarbonBlack:Failed to Isolate Sensor {0} is Offline".format(sensor.hostname))
        return {"isolated_hosts": resp}

    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def list_connections(config, param):
    try:
        query_parameters = {}

        input_type = param.get('input_type')
        value = param.get('value')
        if value and input_type == "CB Process ID":
            query_parameters = {'cb.q.process_id': value}
            return _get_connections_for_process(config, query_parameters)

        pname_or_pid = param.get('pname_pid')
        proc_pid = param.get('proc_pid')
        if proc_pid and pname_or_pid == "Process Name":
            query_parameters['cb.q.process_name'] = proc_pid

        elif proc_pid and pname_or_pid == "Process ID":
            query_parameters['cb.q.process_pid'] = proc_pid

        datas = {}
        resp_json = get_host_details(config, param)
        for sensor in resp_json:
            if sensor.get('status') == 'Online':
                query_parameters['cb.q.hostname'] = sensor.get('computer_name')
                data = _get_connections_for_process(config, query_parameters)
                if data:
                    datas.setdefault("message", "Success")
                    datas.setdefault("hostname", sensor.get('computer_name'))
                    datas.setdefault("connections", data)
                else:
                    datas.setdefault("message", "No Connection Found")
                    datas.setdefault("hostname", None)
                    datas.setdefault("connections", None)

        if datas is None:
            logger.error("Invalid input {0}".format(value))
            raise ConnectorError(
                "carbon_black.list_connections: Invalid input {}".format(value))
        return datas

    except Exception as err:
        logger.error("Failure {0}".format(str(err)))
        raise ConnectorError("Failure {0}".format(str(err)))


def _get_connections_for_process(config, query_parameters):
    """ Get a list of all processes matching the search parameters """
    server_url, api_key, verify_ssl = get_config(config)
    query_parameters['rows'] = 0
    endPointUrl = server_url + '/api/v1/process'
    headers = {
        'x-auth-token': api_key
    }
    response = request("GET", endPointUrl, headers=headers, params=query_parameters, verify=verify_ssl)

    if response.status_code != 200:
        logger.error('Error finding processes with status code: {}'.format(str(response.status_code)))
        return ()

    resp_json = response.json()
    if resp_json['total_results'] == 0:
        logger.error('No connections found')
        return None
    query_parameters['rows'] = resp_json['total_results']

    response = request("GET", endPointUrl, headers=headers, params=query_parameters, verify=verify_ssl)

    if response.status_code != 200:
        logger.error('Error finding processes with status code: {0}'.format(str(response.status_code)))
        return 'Error while processing request with status code {0}'.format(str(response.status_code))

    resp_json = response.json()
    process_list = resp_json['results']
    total_processes = 0
    connection_list = list()
    for process in process_list:
        if process['netconn_count'] == 0:
            continue
        total_processes += 1
        connection = _get_connections_for_process_event(config, process.get('id'), process.get('segment_id'))
        connection_list.append(connection)
    return connection_list


def _get_connections_for_process_event(config, cb_id, segment_id):
    """ Get a process event and parse netconn """
    server_url, api_key, verify_ssl = get_config(config)
    protocol_dict = {'6': 'TCP', '17': 'UDP'}
    if cb_id is None or segment_id is None:
        return
    else:
        headers = {
            'x-auth-token': api_key
        }
        endpoint = 'api/v1/process/{0}/{1}/event'.format(str(cb_id), str(segment_id))

        endPointUrl = '{0}/{1}'.format(server_url, endpoint)

        response = request("GET", endPointUrl, headers=headers, verify=verify_ssl)

        if response.status_code != 200:
            logger.error('Error while fetching process event and parse netconn details. Status Code {}'.format(
                str(response.status_code)))
            return

        event_json = response.json()
        netconns = event_json['process']['netconn_complete']
        pid = event_json['process']['process_pid']
        name = event_json['process']['process_name']
        hostname = event_json['process']['hostname']
        connection_dict = {}
        connection_dict['connections'] = []
        connection = {}
        connection['process_name'] = name
        connection['pid'] = pid
        connection['hostname'] = hostname
        connection['carbonblack_process_id'] = cb_id
        for netconn in netconns:
            fields = netconn.split('|')
            connection['event_time'] = fields[0]
            ip = fields[1]
            connection['ip_addr'] = validate_ip(ip)
            connection['port'] = fields[2]
            connection['protocol'] = protocol_dict.get(fields[3], fields[3])
            connection['domain'] = fields[4]
            if fields[5] == 'true':
                connection['direction'] = 'outbound' if 1 else 'inbound'

        return connection


def validate_ip(input_ip):
    """ Convert 32 bit unsigned int to IP """
    if not input_ip:
        return ''
    import struct
    import ctypes
    import socket

    input_ip = int(input_ip)
    input_ip = ctypes.c_uint32(input_ip).value
    return socket.inet_ntoa(struct.pack('!L', input_ip))


isolate_operations = {
    'Process Name': isolate_sensor_process_name_match,
    'Filehash (MD5)': isolate_sensor_md5_match,
    'Hostname': isolate_sensor_hostname_ip,
    'IP Address': isolate_sensor_hostname_ip,
}

unisolate_operations = {
    'Process Name': unisolate_sensor_process_name_match,
    'Filehash (MD5)': unisolate_sensor_md5_match,
    'Hostname': unisolate_sensor_hostname_ip,
    'IP Address': unisolate_sensor_hostname_ip
}

terminate_process_operations = {
    'Process Name': terminate_process_name,
    'Process ID': terminate_process_pid
}
