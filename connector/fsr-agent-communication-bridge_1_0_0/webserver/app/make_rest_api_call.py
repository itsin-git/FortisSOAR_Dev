import requests
from .log import get_logger
from app.config import config as mi_config

error_msg = {
    401: 'Authentication failed due to invalid credentials',
    429: 'Rate limit was exceeded',
    403: 'Token is invalid or expired',
    "ssl_error": 'SSL certificate validation failed',
    'time_out': 'The request timed out while trying to connect to the remote server',
}

logger = get_logger("fsr-agent-communication-bridge")


class MakeRestApiCall:

    def __init__(self, config=None):
        self.server_url = mi_config['INTEGRATION']['HOST']
        self.server_port = mi_config['INTEGRATION']['PORT']
        if not self.server_url.startswith('http') or not self.server_url.startswith('https'):
            self.server_url = 'http://' + self.server_url + ":" + self.server_port
        self.verify_ssl = False

    def make_request(self, endpoint='', data=None, method='GET', params=None, headers=None, url=None, json_data=None):
        try:
            if url is None:
                url = self.server_url + endpoint
            logger.info(url)
            response = requests.request(method=method, url=url,
                                        headers=headers, data=data, json=json_data,
                                        params=params, verify=self.verify_ssl)
            if response.ok:
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.text
            else:
                logger.error("Error: {0}".format(response.json()))
                raise Exception('{0}'.format(error_msg.get(response.status_code, response.text)))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise Exception('{0}'.format(error_msg.get('ssl_error')))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise Exception('{0}'.format(error_msg.get('time_out')))
        except Exception as e:
            logger.error('{0}'.format(e))
            if str(e).__contains__('404 Client Error'):
                return {"Error": "Not Found"}
            raise Exception('{0}'.format(e))
