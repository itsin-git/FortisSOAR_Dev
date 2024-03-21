from cshmac.requests import HmacAuth
import requests
from connectors.core.connector import get_logger

logger = get_logger("cyops_utilities.builtins.cyops_utilities-api")

basic = 'Basic'
hmac = 'CS HMAC'
anonymous = 'anonymous'

class JWTAuth(requests.auth.AuthBase):
    """
    Auth that builds a token Authorization header in the format:

        Bearer {token}

    where the JWT token is provided by the invoker of the auth class.
    """
    def __init__(self, token):
        self.token = token

    def __call__(self, request):
        if not self.token:
            raise Exception(cs_connector_utility_18)

        request.headers["Authorization"] = 'Bearer {}'.format(self.token)
        return request


def get_requests_auth(auth_info, url, request_method, public_key, private_key,
                      body='', *args, **kwargs):
    """
    Returns the appropriate requests Auth object based on the method specified \
    in auth_info

   :param dict auth_info: Defines the auth method for the containing workflow \
       and any information necessary to build auth requests
   :param str url: The absolute URL for the API request
   :param str request_method: The type of HTTP method to use
   :param str public_key: The public key to use for HMAC fingerprinting
   :param str private_key: The private key to use for HMAc fingerprinting
   :param str body: The body of the request

   :return: The Auth object to pass to requests, or None for anonymous auth
   :rtype: None or JWTAuth or HmacAuth
    """


    logger.info('get_requests_auth function: Returns the appropriate requests Auth object based on the method specified \
    in auth_info')
    env = kwargs.get('env', {})
    if auth_info and 'auth_method' in auth_info:
        auth_method = auth_info['auth_method']
        logger.info('Auth Method: %s', auth_method)
        if auth_method == basic:
            return JWTAuth(auth_info['token'])
        elif auth_method == hmac:
            if env.get('authorization') and 'Bearer ' in env.get('authorization'):
                return JWTAuth(env.get('authorization').replace('Bearer ', ''))
            return HmacAuth(url, request_method, public_key, private_key, body)
        elif auth_method == anonymous:
            if env.get('public_key') and env.get('private_key'):
                return HmacAuth(url, request_method, env.get('public_key'), env.get('private_key'), body)

    return None
