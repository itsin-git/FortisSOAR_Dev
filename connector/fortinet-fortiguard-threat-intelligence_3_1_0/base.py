import requests, json
from .fortiguard_client import connect_to_fgd
from connectors.core.connector import get_logger, ConnectorError
from .const import ERRORS as errors, MESSAGE_404

logger = get_logger('fortinet-fortiguard-threat-intelligence')

class FortiguardThreatIntelligence(object):
    def __init__(self, config, *args, **kwargs):
        url = config.get('server_url')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/'.format(url.strip('/'))
        else:
            self.url = url.strip('/') + '/'

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            logger.debug("Endpoint URL: {0}".format(url))
            headers = {'Content-Type': 'application/json'}
            response = connect_to_fgd(method, url, headers, data, params)
            if response.ok:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
            elif response.status_code == 404:
                return {"message": MESSAGE_404}
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(response.text))
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