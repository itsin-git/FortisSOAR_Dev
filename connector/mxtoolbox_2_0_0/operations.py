from connectors.core.connector import get_logger, ConnectorError
import requests

logger = get_logger('mxtoolbox')

API_METHOD_MAPPING = {"Lookup": "lookup", "Monitor": "monitor", "Usage": "usage"}
API_ENDPOINT = '/api/v1'
LOOKUP_ENDPOINT = '/lookup/'
MONITOR_ENDPOINT = '/monitor/'
USAGE_ENDPOINT = '/usage/'


def get_config(config):
    try:
        if config is not None:
            server_url = config.get('server_url')
            api_key = config.get('api_key')
            verify_ssl = config.get('verify_ssl')
            return server_url, api_key, verify_ssl
    except Exception as Err:
        logger.warn('Error occured while extracting conf :[{0}] '.format(Err))
        raise ConnectorError(Err)


def make_api_call(config, method='GET', endpoint=None, params=None, data=None, json=None):
    server, api_key, verify_ssl = get_config(config)
    if not server.startswith('https://'):
        server = 'https://{0}'.format(server)
    headers = {'Authorization': api_key}
    if endpoint:
        url = '{0}{1}'.format(server, endpoint)
    else:
        url = server
    logger.info('Request URL {}'.format(url))
    try:
        response = requests.request(method=method, url=url, headers=headers, params=params, verify=verify_ssl)
        if response.ok:
            try:
                return response.json()
            except Exception as err:
                logger.info(
                    'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url), str(response.content),
                                                                                        str(response.reason)))
                raise ConnectorError(
                    'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url), str(response.content),
                                                                                       str(response.reason)))
        elif response.status_code == 401:
            logger.info('Unauthorized: Invalid credentials')
            raise ConnectorError('Unauthorized: Invalid credentials')
        else:
            logger.info(
                'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url), str(response.content),
                                                                                    str(response.reason)))
            raise ConnectorError(
                'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url), str(response.content),
                                                                                   str(response.reason)))
    except requests.exceptions.SSLError as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format('SSL certificate validation failed'))
    except requests.exceptions.ConnectionError as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format('The request timed out while trying to connect to the remote server'))
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def build_payload(params):
    result = {k: v for k, v in params.items() if v is not None and v != ''}
    return result


def api_call(config, params):
    try:
        api_method = params.get('api_method', None)
        if API_METHOD_MAPPING.get(api_method) == 'lookup':
            command = params.get('command', None)
            payload = build_payload(params)
            payload.pop('command')
            payload.pop('api_method')
            endpoint_url = API_ENDPOINT + LOOKUP_ENDPOINT + command
            result = make_api_call(config, endpoint=endpoint_url,
                                   params=payload)
            return {"request_status": "Success", "result": result}
        elif API_METHOD_MAPPING.get(api_method) == 'monitor':
            endpoint_url = API_ENDPOINT + MONITOR_ENDPOINT
            payload = build_payload(params)
            payload.pop('api_method')
            if payload:
                result = make_api_call(config, endpoint=endpoint_url, params=payload)
            else:
                result = make_api_call(config, endpoint=endpoint_url)
            return {"request_status": "success", "result": result}
        elif API_METHOD_MAPPING.get(api_method) == 'usage':
            endpoint_url = API_ENDPOINT + USAGE_ENDPOINT
            result = make_api_call(config, endpoint=endpoint_url)
            return {"request_status": "success", "result": result}
    except Exception as err:
        logger.exception("Error making call to  MxToolbox. Error message as follows: {}".format(str(err)))
        raise ConnectorError("Error making call to MxToolbox. Error message as follows: {}".format(str(err)))


def _check_health(config):
    try:
        if make_api_call(config, endpoint=API_ENDPOINT + USAGE_ENDPOINT):
            return True
    except Exception as err:
        logger.exception("Error connecting to MxToolbox server. Error as follows: {}".format(str(err)))
        raise ConnectorError("Error connecting to MxToolbox server. Error as follows: {}".format(str(err)))


operations = {
    'api_call': api_call
}
