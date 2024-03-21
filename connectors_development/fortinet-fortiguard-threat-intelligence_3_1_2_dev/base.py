import requests, time
from .fortiguard_client import connect_to_fgd
from connectors.core.connector import get_logger, ConnectorError
from .const import ERRORS as errors, MESSAGE_404, MAX_RETRY, SLEEP

logger = get_logger('fortinet-fortiguard-threat-intelligence')


class FortiguardThreatIntelligence(object):
    def __init__(self, config, *args, **kwargs):
        url = config.get('server_url')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/'.format(url.strip('/'))
        else:
            self.url = url.strip('/') + '/'
        
        self.verify_ssl = True
        if 'verify_ssl' in config.keys():
            self.verify_ssl = config['verify_ssl']

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            headers = {'Content-Type': 'application/json'}
            retry = 0
            while retry < MAX_RETRY:
                time.sleep(SLEEP)
                response = connect_to_fgd(method, url, headers, data, params, self.verify_ssl)
                if response.ok:
                    logger.info('Successfully got response for url {0}'.format(url))
                    if 'json' in str(response.headers):
                        return response.json()
                    else:
                        return response.text
                elif response.status_code == 404:
                    return {"message": MESSAGE_404}
                retry += 1
            logger.error("Status Code: {0}, {1}".format(response.status_code,
                                                        errors.get(response.status_code, '')))
            raise ConnectorError("Status Code: {0}, {1}".format(response.status_code,
                                                                errors.get(response.status_code, '')))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid URL or API token')
        except Exception as err:
            raise ConnectorError(str(err))
