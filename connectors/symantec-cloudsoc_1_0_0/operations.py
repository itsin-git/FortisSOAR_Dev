from connectors.core.connector import get_logger, ConnectorError
from connectors.core.connector import api_health_check as api_request
from .utils import (_build_url, _generate_headers, convert_query_params)
from integrations.crudhub import maybe_json_or_raise
from .const import *
import json
from requests import request

logger = get_logger('symantec-casb')


def get_logs(config, params):
    query_params = {k: v for (k, v) in params.items() if v}
    url, verify_ssl, auth = _build_url(config, api_method=GET_LOGS)
    log_list = api_request(method='get', url=url, verify=verify_ssl, params=query_params,
                           username=config.get('api_key'), password=config.get('api_password'),
                           headers=_generate_headers())
    return maybe_json_or_raise(log_list)


def get_audit_data_source(config, params):
    url, verify_ssl, auth = _build_url(config, api_method=AUDIT_DATA_SOURCE)
    audit_data_source_list = api_request(method='get', url=url, verify=verify_ssl, headers=_generate_headers(),
                                         username=config.get('api_key'), password=config.get('api_password'))
    return maybe_json_or_raise(audit_data_source_list)


def get_audit_service(config, params):
    query_params = convert_query_params(params)
    url, verify_ssl, auth = _build_url(config, api_method=AUDIT_SERVICE)
    audit_service_list = api_request(method='get', url=url, verify=verify_ssl, params=query_params,
                                     username=config.get('api_key'), password=config.get('api_password'),
                                     headers=_generate_headers())
    return maybe_json_or_raise(audit_service_list)


def get_audit_user(config, params):
    query_params = convert_query_params(params)
    url, verify_ssl, auth = _build_url(config, api_method=AUDIT_USER)
    audit_user = api_request(method='get', url=url, verify=verify_ssl, params=query_params,
                                     username=config.get('api_key'), password=config.get('api_password'),
                                     headers=_generate_headers())
    return maybe_json_or_raise(audit_user)


def get_audit_username(config, params):
    try:
        limit = params.get('limit', 1000)
        if limit == '' or None:
            limit = 1000
        body = {
            "user_ids": params.get('user_ids') if type(params.get('user_ids')) == list else [params.get('user_ids')],
            "limit": limit
        }
        url, verify_ssl, auth = _build_url(config, api_method=AUDIT_USERNAME)
        audit_user = api_request(method='post', url=url, verify=verify_ssl, body=body,
                                 username=config.get('api_key'), password=config.get('api_password'),
                                 headers=_generate_headers())
        return maybe_json_or_raise(audit_user)
    except Exception as Err:
        if 'INTERNAL SERVER ERROR' in str(Err):
            logger.exception('Invalid input provided')
            raise ConnectorError('Invalid input provided')
        else:
            logger.exception(str(Err))
            raise ConnectorError(str(Err))


def get_audit_summary(config, params):
    query_params = convert_query_params(params)
    url, verify_ssl, auth = _build_url(config, api_method=AUDIT_SUMMARY)
    audit_summary = api_request(method='get', url=url, verify=verify_ssl, params=query_params,
                             username=config.get('api_key'), password=config.get('api_password'),
                             headers=_generate_headers())
    return maybe_json_or_raise(audit_summary)


def get_content_iqprofile(config, params):
    query_params = convert_query_params(params)
    url, verify_ssl, auth = _build_url(config, api_method=PROTECT_CONTENT_IQ_PROFILE)
    audit_summary = api_request(method='get', url=url, verify=verify_ssl, params=query_params,
                                username=config.get('api_key'), password=config.get('api_password'),
                                headers=_generate_headers())
    return maybe_json_or_raise(audit_summary)


def get_protect_policies(config, params):
    query_params = convert_query_params(params)
    url, verify_ssl, auth = _build_url(config, api_method=PROTECT_POLICICES)
    protect_policies = api_request(method='get', url=url, verify=verify_ssl, params=query_params,
                                   username=config.get('api_key'), password=config.get('api_password'),
                                   headers=_generate_headers())
    return maybe_json_or_raise(protect_policies)


def query_user(config, email):

    query_params = {"email": email}

    url, verify_ssl, auth = _build_url(config, api_method=USER_ACTIVATION)
    response = api_request(method='get', url=url, verify=verify_ssl, username=config.get('api_key'), params=query_params,
                           password=config.get('api_password'), headers=_generate_headers())

    if response.status_code != 200:
        logger.exception("Invalid response from server [{}]".format(str(response.status_code)))
        raise ConnectorError("Invalid response from server [{}]".format(str(response.status_code)))

    try:
        user_data = json.loads(response.text).get('objects', [])
    except Exception as e:
        logger.exception("Invalid data received from server")
        raise ConnectorError("Invalid data received from server")

    if len(user_data) != 1:
        logger.exception("Invalid email provided")
        raise ConnectorError("Invalid email provided")
    return user_data[0]


def change_activation_status(config, user_id, status):
    try:
        data = json.dumps({"is_active": status})
        url, verify_ssl, auth = _build_url(config, api_method=USER_ACTIVATION + str(user_id) + '/')
        response = request(method='patch', url=url, verify=verify_ssl, data=data, auth=auth, headers=_generate_headers())
        if response.status_code != 202:
            logger.exception("Failed to update user [{}]".format(response.text))
            raise ConnectorError("Failed to update user [{}]".format(response.text))

        return {"Status": 'Success'}
    except Exception as Err:
        logger.exception(str(Err))
        raise ConnectorError(str(Err))


def modify_user (config, params):
    user = query_user(config, params.get('email'))
    user_id = user.get('id', '')
    resp = change_activation_status(config, user_id=user_id, status= True if params.get("action") == "Activate User" else False )
    return resp


operations = {
    'get_logs'             : get_logs,
    'get_audit_data_source': get_audit_data_source,
    'get_audit_service'    : get_audit_service,
    'get_audit_user'       : get_audit_user,
    'get_audit_username'   : get_audit_username,
    'get_audit_summary'    : get_audit_summary,
    'get_content_iqprofile': get_content_iqprofile,
    'get_protect_policies' : get_protect_policies,
    'modify_user'          : modify_user
}
