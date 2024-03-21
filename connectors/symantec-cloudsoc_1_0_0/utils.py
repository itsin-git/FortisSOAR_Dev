from connectors.core.connector import api_health_check as api_request
from connectors.core.connector import get_logger
from .const import VALIDATION_METHOD

logger = get_logger('symantec-casb')


def _check_and_convert_params(params):
    convert_params = dict()
    if params:
        for k, v in params.items():
            if type(v) == bytes:
                convert_params[k] = str(v, 'utf-8')
            else:
                convert_params[k] = v
    return convert_params


def _generate_headers():
    return {
        'X-Elastica-Dbname-Resolved': 'True',
        'Content-Type': 'application/json',
        'accept': 'application/json'
    }


def _build_url(config, api_method):
    url = '{host_name}/{tenant}/{api_method}'.format(host_name=config.get('host_name'),
                                                     tenant=config.get('tenant'),
                                                     api_method=api_method,
                                                     )
    """ Concatenate URLs """
    verify_ssl = config.get('verify_ssl', True)
    auth = (config.get('api_key'), config.get('api_password'))
    return url, verify_ssl, auth


def _validate_connectivity(config):
    api_method = VALIDATION_METHOD
    query_params = {'app': 'Detect', 'subtype': 'incidents'}
    url, verify_ssl, auth = _build_url(config, api_method)
    check_health = api_request(method='get', url=url, verify=verify_ssl, headers=_generate_headers(),
                               username=config.get('api_key'), password=config.get('api_password'),
                               params=query_params)
    logger.info('make api call end')
    return check_health


def convert_query_params(params):
    query_params = {}
    for key, value in params.items():
        if value is True:
            query_params[key] = "true"
        elif value is False:
            query_params[key] = "false"
        elif value:
            query_params[key] = value
    return query_params
