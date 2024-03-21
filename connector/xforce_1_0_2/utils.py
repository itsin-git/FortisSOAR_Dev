import base64
import requests
import validators
import urllib.parse as urlp
from sys import _getframe

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('xforce')


def _get(url, verify=True, headers={'content-type': 'application/json'}, timeout=12, display_standard_message=False):
    operation_name = str(_getframe(1).f_code.co_name)
    err = ''
    try:
        res = requests.get(url, headers=headers, timeout=timeout, verify=verify)
        return res
    except requests.exceptions.ConnectTimeout as e:
        err = e
        logger.error(
            "Operation Name: {operation_name}. Output: Timeout Error occured for url: {url} with error as: {error_text}".format(
                operation_name=operation_name, url=url, error_text=str(e)))
    except requests.exceptions.TooManyRedirects as e:
        err = e
        logger.error(
            "Operation Name: {operation_name}. Output: Redirect Error occured for url: {url} with error as: {error_text}".format(
                operation_name=operation_name, url=url, error_text=str(e)))
    except requests.exceptions.ConnectionError as e:
        err = e
        logger.error(
            "Operation Name: {operation_name}. Output: Connection Error occured for url: {url} with error as: {error_text}".format(
                operation_name=operation_name, url=url, error_text=str(e)))
    except requests.exceptions.RequestException as e:
        err = e
        logger.error('generic Exception')
        logger.error(
            "Operation Name: {operation_name}. Output: Generic Error occured for url: {url} with error as: {error_text}".format(
                operation_name=operation_name, url=url, error_text=str(e)))
    if display_standard_message:
        raise ConnectorError('Invalid URL or Credentials')
    else:
        raise ConnectorError(
            "Operation Name: {operation_name}. Output: API execution failed for url: {url} with error as: {error_text}".
                format(
                operation_name=operation_name,
                url=url,
                error_text=str(err)))


def _generate_api_key_basic_auth(username, password):
    b64_credential = base64.b64encode((username + ":" + password).encode('utf-8')).decode()
    return b64_credential


def _generate_headers(config):
    headers = {
        'Authorization': "Basic " + _generate_api_key_basic_auth(config.get('api_key'), config.get('api_password')),
        'Accept': 'application/json'}
    verify_ssl = config.get('verify_ssl', True)
    return headers, verify_ssl


def _check_and_convert_params(params):
    convert_params = dict()
    if params:
        for k, v in params.items():
            if type(v) == bytes:
                convert_params[k] = str(v, 'utf-8')
            else:
                convert_params[k] = v
    return convert_params


def _build_url(config, method_name, params=None, query_params=None):
    """ Concatenate URLs """
    base_url = 'https://{host_name}/'.format(host_name=config.get('host_name'))
    if not params and not query_params:
        url = '{base_url}{method_name}'.format(base_url=base_url,
                                               method_name=method_name)
    elif params and not query_params:
        url = '{base_url}{method_name}/{params}'.format(base_url=base_url,
                                                        method_name=method_name,
                                                        params=params)
    elif params and query_params:
        url = '{base_url}{method_name}/{params}?{query_params}'.format(base_url=base_url,
                                                                       method_name=method_name,
                                                                       params=params,
                                                                       query_params=query_params)
    elif query_params and not params:
        url = '{base_url}{method_name}?{query_params}'.format(base_url=base_url,
                                                              method_name=method_name,
                                                              query_params=query_params)
    else:
        url = base_url
    return url


def _validate_url(config):
    create_full_url = "https://{host_name}".format(host_name=config['host_name'])
    response = _get(create_full_url, verify=config.get('verify_ssl', True), display_standard_message=True)
    return response


def _validate_credential(config):
    headers, verify_ssl = _generate_headers(config)
    url = _build_url(config, method_name='version')
    response = _get(url, verify=verify_ssl, headers=headers, display_standard_message=True)
    return response


def _check_and_build_vulnerability_params(params):
    _strg = 'q=' + urlp.quote(params['query'])
    if params.get('start_date'):
        _strg += '&startDate=' + urlp.quote(params['start_date'])
    if params.get('end_date'):
        _strg += '&endDate=' + urlp.quote(params['end_date'])
    if params.get('bookmark'):
        _strg += 'bookmark=' + params['bookmark']
    return _strg.strip()


def error_handling(error_msg, api_response):
    logger.error(error_msg + "Server responded with {error_message} message".format(
        error_message=api_response.text))
    raise ConnectorError(error_msg + "Server responded with {error_message} message".format(
        error_message=api_response.text))


def check_config_url(config):
    if config.get('host_name').startswith('https://'):
        config['host_name'] = config.get('host_name')[8:]
    elif config.get('host_name').startswith('http://'):
        config['host_name'] = config.get('host_name')[7:]
    return config
