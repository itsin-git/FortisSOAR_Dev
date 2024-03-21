import json, requests, xmltodict, time
from connectors.core.connector import get_logger, ConnectorError
from .const import *

logger = get_logger('prtg')

error_msgs = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Invalid credentials provided failed to authorize',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error',
    503: 'Service Unavailable',
    'time_out': 'The request timed out while trying to connect to the remote server',
    'ssl_error': 'SSL certificate validation failed'
}


class PTRGMonitoring(object):
    def __init__(self, config):
        self.server_url = config.get('server_url').strip('/')
        if self.server_url[:7] != 'http://' and self.server_url[:8] != 'https://':
            self.server_url = 'https://{}'.format(self.server_url)
        self.username = config.get('username')
        self.auth = config.get('auth')
        self.value = config.get('value')
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, endpoint, params=None, method='GET'):
        query_string = self.build_query_string(params)
        service_endpoint = '{0}{1}'.format(self.server_url, endpoint)
        logger.info('Request URL {}'.format(service_endpoint))
        try:
            resp_json = {}
            response = requests.request(method, service_endpoint, params=query_string, verify=self.verify_ssl)
            if response.ok:
                if "application/json" in response.headers.get('Content-Type'):
                    return response.json()
                else:
                    try:
                        return json.loads(json.dumps(xmltodict.parse(response.content.decode('utf-8'))))
                    except:
                        pass
                    return {}
            else:
                if response.status_code == 401:
                    raise ConnectorError('{}'.format(error_msgs[response.status_code]))
                if response.content.decode('utf-8'):
                    if 'text' in response.headers.get('Content-Type'):
                        resp_json = json.loads(json.dumps(xmltodict.parse(response.content.decode('utf-8'))))
                error = ''
                if resp_json.get('prtg'):
                    error = resp_json.get('prtg').get('error')
                if error_msgs[response.status_code]:
                    raise ConnectorError('{}: {}'.format(error_msgs[response.status_code], error))
        except requests.exceptions.SSLError as e:
            logger.exception(e)
            raise ConnectorError(error_msgs['ssl_error'])
        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
            raise ConnectorError(error_msgs['time_out'])
        except Exception as e:
            logger.exception(e)
            raise ConnectorError(e)

    def build_query_string(self, params):
        if self.auth.lower() == 'password':
            query_string = {'username': self.username, 'password': self.value}
        else:
            query_string = {'username': self.username, 'passhash': self.value}
        if params:
            query_string.update(params)
        query_string = {k: v for k, v in query_string.items() if v is not None and v != ''}
        return query_string


def list_object_detail(config, params):
    prtg = PTRGMonitoring(config)
    endpoint = '/api/table.json'
    response_fields = params.get('response_fields')
    content = CONTENT_TYPE.get(params.get('content'))
    list_status = params.get('status')
    fields = []
    if response_fields:
        for field in response_fields:
            fields.append(RESPONSE_FIELDS[field])
    fields = ','.join(fields)
    payload = {'content': content, 'columns': fields}
    count = params.get('count')
    if count:
        payload.update({'count': count})
    start = params.get('start')
    if start:
        payload.update({'start': start})
    if content == "messages" or content == "tickets":
        last_seen = params.get('last_seen')
        if last_seen:
            payload.update({'filter_drel': DURATIONS.get(last_seen)})
    if content == 'sensors':
        if list_status:
            endpoint += '?'
            for status in list_status:
                endpoint += 'filter_status={}&'.format(str(FILTER_STATUS.get(status)))
            endpoint = endpoint.rstrip('&')
        tags = params.get('tags')
        if tags:
            tags = '@tag({})'.format(tags)
            payload.update({'filter_tags': tags})
    sort = params.get('sortby')
    if sort:
        payload.update({'sortby': sort})
    open_filter = params.get('open_filter')
    if open_filter and not list_status:
        endpoint += '?{}'.format(str(open_filter))
    elif open_filter:
        endpoint += '&{}'.format(str(open_filter))
    return prtg.make_rest_call(endpoint, params=payload)


def pause_sensor(config, params):
    prtg = PTRGMonitoring(config)
    params.update({'action': 0})
    pause_url = '/api/pause.htm'
    if params.get('duration'):
        pause_url = "/api/pauseobjectfor.htm"
    resp = prtg.make_rest_call(pause_url, params=params)
    if resp.get('a').get('@title') == 'Resume':
        return {'status': 'success', 'message': 'Sensor paused successfully.'}
    else:
        return resp


def resume_sensor(config, params):
    prtg = PTRGMonitoring(config)
    resume_url = "/api/pause.htm?id={objid}&action=1".format(objid=params.get('id'))
    resp = prtg.make_rest_call(resume_url)
    if resp.get('a').get('@title') == 'Pause':
        return {'status': 'success', 'message': 'Sensor resumed successfully.'}
    return resp


def scan_sensor(config, params):
    prtg = PTRGMonitoring(config)
    resp = prtg.make_rest_call('/api/scannow.htm', params=params)
    if resp.get('HTML').get('BODY').get('B').get('#text') == 'OK':
        return {'status': 'success', 'message': 'Sensor scans successfully.'}
    else:
        return resp


def get_sensor_status(config, params):
    prtg = PTRGMonitoring(config)
    resp = prtg.make_rest_call('/api/getsensordetails.json', params=params)
    if '(Object not found)' in json.dumps(resp):
        return {'status': 'fail', 'result': 'Provided Sensor ID not founds.'}
    else:
        return {'status': 'success', 'result': resp}


def convert_datetime_to_minute(timestamp):
    epoch_time = time.mktime(time.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ'))
    current_time = time.time()
    timesince = int((epoch_time - current_time) / 60)
    return timesince


def acknowledge_alarm(config, params):
    duration = params.get('duration')
    if duration == 'Indefinitely':
        params.pop('duration')
    elif duration == 'Until':
        params.update({'duration': convert_datetime_to_minute(params.pop('until'))})
    else:
        params.update({'duration': ACK_DURATION.get(duration)})
    prtg = PTRGMonitoring(config)
    resp = prtg.make_rest_call('/api/acknowledgealarm.htm', params=params)
    if not resp:
        return {'status': 'success', 'message': 'Alarm successfully acknowledged.'}
    return resp


def delete_object(config, params):
    prtg = PTRGMonitoring(config)
    obj_type = params.pop('object')
    payload = {'id': params.get('id'), "name": "type", "show": "text"}
    resp = prtg.make_rest_call('/api/getobjectstatus.htm', params=payload)
    type = resp.get('prtg').get('result')
    if type == "Root":
        raise ConnectorError("You cannot delete the root object.")

    if type != obj_type and obj_type != 'Sensor':
        raise ConnectorError("Object does not matches of selected type.")

    if obj_type == 'Sensor' and type in SUPPORTED_OBJECT:
        raise ConnectorError("Object does not matches of selected type.")

    params.update({'approve': 1})
    resp = prtg.make_rest_call('/api/deleteobject.htm', params=params)
    if not resp:
        return {'status': 'success', 'message': '{} successfully deleted.'.format(obj_type)}
    return resp


def run_auto_discovery(config, params):
    prtg = PTRGMonitoring(config)
    templates = params.get('template')
    discovery = params.pop('discovery')
    if discovery == 'Run Auto-Discovery with Template':
        csv_template = ''
        temp_form = "\"{name}\""
        if isinstance(templates, str):
            templates = templates.split(',')
        for template in templates:
            template = template.strip()
            if not template.endswith('.odt'):
                template += '.odt'
            csv_template += temp_form.format(name=template) + ','
        csv_template = csv_template.strip(',')
        params.update({'template': csv_template})
    resp = prtg.make_rest_call('/api/discovernow.htm', params=params)
    if resp.get('HTML').get('BODY').get('B').get('#text') == 'OK':
        return {'status': 'success', 'message': '{} started successfully'.format(discovery)}
    else:
        return resp


def _check_health(config):
    prtg = PTRGMonitoring(config)
    resp = prtg.make_rest_call('/api/table.xml?content=sensors&columns=sensor')
    if resp:
        logger.info('connector available')
        return True


operations = {
    'list_object_detail': list_object_detail,
    'get_sensor_status': get_sensor_status,
    'pause_sensor': pause_sensor,
    'resume_sensor': resume_sensor,
    'acknowledge_alarm': acknowledge_alarm,
    'scan_sensor': scan_sensor,
    'delete_object': delete_object,
    'run_auto_discovery': run_auto_discovery

}

