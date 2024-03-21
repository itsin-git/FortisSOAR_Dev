"""
Steps related to making HTTP requests.
"""
import ast
import json
import requests

from connectors.core.connector import get_logger, ConnectorError
from .utils import maybe_json_or_raise
from .errors.error_constants import *


logger = get_logger('cyops_utilities.builtins.http')


def api_call(url, method='GET', params=None, body='', headers=None,
             verify=True, username='', password='', auth_config=None,
             *args, **kwargs):
    """
    A wrapper around the python requests library.

    Can be used to make any generic http call.

   :param str url: End point to hit
   :param str method: Http method
   :param dict params: Any query params to send as part of the url
   :param str body: The body (which won't be encoded) to send with the request
   :param dict headers: An object full of headers to add to the request
   :param bool verify: Boolean to indicate whether to verify certificates
   :param str username: Username used in basic auth
   :param str password: Password used in basic auth
   :param dict auth_config: Username and password used in basic auth, but in
       dict form

   :return: the API response either as a json-like dict if possible or as bytes
   :rtype: dict or bytes
    """
    return _api_call(url, method, params, body, headers, verify, username,
                     password, auth_config, *args, **kwargs)


def _api_call(url, method='GET', params=None, body='', headers=None,
              verify=True, username='', password='', auth_config=None,
              *args, **kwargs):
    """
    Helper method for api call step, notably lacks the vault decorator
    """
    # this takes precedence over using user/pass directly because this could be
    # a vault dict
    if auth_config:
        auth = (auth_config['username'], auth_config['password'])
    elif username or password:
        auth = (username, password)
    else:
        auth = None

    verify = _convert_verify(verify)

    # build **args for requests call
    request_args = {
        'verify': verify,
    }
    if auth:
        request_args['auth'] = auth
    if params:
        request_args['params'] = params
    if headers:
        request_args['headers'] = headers

    # get rid of the body on GET/HEAD requests
    bodyless_methods = ['head', 'get']
    if method.lower() not in bodyless_methods:
        request_args['data'] = _convert_body(body)

    # actual requests call
    logger.info('Starting request: Method %s, Url: %s', method, url)
    try:
        response = requests.request(method, url, **request_args)
    except requests.exceptions.SSLError as e:
        logger.exception("{0} ERROR :: {1}".format(cs_connector_utility_4,str(e)))
        raise ConnectorError(cs_connector_utility_4)
    return maybe_json_or_raise(response)


# type conversions :\
def _convert_verify(verify):
    if type(verify) == str and verify:
        try:
            verify = ast.literal_eval(verify.title())
        except Exception:
            logger.warn('Str verification failed.')
    if type(verify) != bool:
        # just default to true
        return True
    return verify


def _convert_body(body):
    if body and type(body) == str:
        try:
            logger.info('converting body into json %s', body)
            body = json.loads(body, strict=False)
        except:
            logger.warn('Json conversion failed.')

    if body and type(body) != str:
        body = json.dumps(body)
    return body
