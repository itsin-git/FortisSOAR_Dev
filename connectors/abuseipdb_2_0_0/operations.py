import json
import base64
import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('abuseIPDB')

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

REPORT_CATEGORIES = {
    "DNS Compromise": 1,
    "DNS Poisoning": 2,
    "Fraud Orders": 3,
    "DDoS Attack": 4,
    "FTP Brute-Force": 5,
    "Ping of Death": 6,
    "Phishing": 7,
    "Fraud VoIP": 8,
    "Open Proxy": 9,
    "Web Spam": 10,
    "Email Spam": 11,
    "Blog Spam": 12,
    "VPN IP": 13,
    "Port Scan": 14,
    "Hacking": 15,
    "SQL Injection": 16,
    "Spoofing": 17,
    "Brute-Force": 18,
    "Bad Web Bot": 19,
    "Exploited Host": 20,
    "Web App Attack": 21,
    "SSH": 22,
    "IoT Targeted": 23
}


class AbuseIPDB(object):
    def __init__(self, config, *args, **kwargs):
        self.server_url = config.get('server_url')
        self.api_key = config.get('token')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/'.format(url)
        else:
            self.url = url + '/'
        self.ssl_verify = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            logger.debug("Endpoint URL: {0}".format(url))
            headers = {'Accept': 'application/json', 'Key': self.api_key}
            response = requests.request(method, url, headers=headers, verify=self.ssl_verify, data=data, params=params, timeout=30)
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
            else:
                if error_msgs.get(response.status_code):
                    logger.error("{0}".format(error_msgs.get(response.status_code, '')))
                    raise ConnectorError("{0}".format(error_msgs.get(response.status_code, '')))
                else:
                    response = json.loads(response.text)
                    logger.error(response)
                    raise ConnectorError(response)
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except Exception as err:
            raise ConnectorError(str(err))


def build_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def ip_lookup(config, params):
    try:
        ab = AbuseIPDB(config)
        url = 'api/v2/check'
        payload = {
            'ipAddress': params.get('ip'),
            'maxAgeInDays': params.get('days'),
            'verbose': params.get('verbose')
        }
        payload = build_payload(payload)
        response = ab.make_rest_call(method='GET', url=url, params=payload)
        if response:
            return response.get('data')
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def report_ip(config, params):
    try:
        ab = AbuseIPDB(config)
        endpoint = 'api/v2/report'
        category = []
        s1 = [category.append(str(REPORT_CATEGORIES.get(cat))) for cat in params.get('categories')]
        payload = {
            'ip': params.get('ip'),
            'categories': ",".join(category),
            'comment': params.get('comment')
        }
        payload = build_payload(payload)
        response = ab.make_rest_call(method='POST', url=endpoint, params=payload)
        if response:
            return response.get('data')
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_ip_blacklist(config, params):
    try:
        ab = AbuseIPDB(config)
        endpoint = 'api/v2/blacklist'
        payload = {
            'confidenceMinimum': params.get('confidenceMinimum'),
            'limit': params.get('limit')
        }
        payload = build_payload(payload)
        response = ab.make_rest_call(method='GET', url=endpoint, params=payload)
        if response:
            return response
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        response = ip_lookup(config, params={"ip": "127.0.0.1"})
        if response:
            return True
        else:
            raise ConnectorError("Invalid URL or API token")
    except Exception as err:
        logger.error("Invalid URL or API token")
        raise ConnectorError("Invalid URL or API token")


operations = {
    'ip_lookup': ip_lookup,
    'report_ip': report_ip,
    'get_ip_blacklist': get_ip_blacklist
}
