from connectors.core.connector import get_logger, ConnectorError
from integrations.requests_auth import get_requests_auth
from integrations.crudhub import maybe_json_or_raise
from cshmac.requests import HmacAuth
from django.conf import settings
import requests, argparse, textwrap, json, random, time, os, csv, re, jmespath
from .constants import CONNECTOR_VERSION

logger = get_logger('FortiSOARSocSimulator')  
  
  
supported_operations = {}


def load_threat():
    #These URLs require review. bad_domains updated @1.0.9
    threat_data = [{
        "name": "bad_ip",
        "url": "https://otx.alienvault.com/otxapi/indicators/?type=IPv4&include_inactive=0&sort=-modified&q=modified:<24h&page=1&limit=100",
        "filename": "malicious_ips"
    }, {
        "name": "bad_hashes",
        "url": "https://otx.alienvault.com/otxapi/indicators/?type=FileHash-SHA256&include_inactive=0&sort=-modified&q=modified:<24h&page=1&limit=100",
        "filename": "malware_hashes"
    },
    {
        "name": "bad_domains",
        "url": "https://otx.alienvault.com/otxapi/indicators/?type=domain&include_inactive=0&sort=-modified&q=modified:%3C1d&page=1&limit=100",
        "filename": "malicious_domains"
    }, {
        "name": "bad_urls",
        "url": "https://otx.alienvault.com/otxapi/indicators/?type=URL&include_inactive=0&sort=-modified&q=modified:<24h&page=1&limit=100",
        "filename": "malicious_urls"
    }
    ]
    threat_intel_dir = "{}/threat_intelligence/".format(os.path.dirname(__file__))
    for item in threat_data:
        lines=''
        try:
            response_json = maybe_json_or_raise(requests.get(url=item.get('url')))
            file_path = "{}{}.txt".format(threat_intel_dir, item.get('filename'))
            indicator_values = jmespath.search('results[].indicator',response_json)
            logger.debug('Indicators type:{} Values {}'.format(item.get('name'),indicator_values))
            with open(file_path, 'w') as f:
                f.write('\n'.join(indicator_values))

        except Exception as e:
            logger.error( "Error downloading threat intelligence data : {}".format(e) )
            raise ConnectorError( "Error downloading threat intelligence data : {}".format(e) )




def make_request(url, method, body=None,files=None, *args, **kwargs):
    """
    This function facilitates using the crud hub api.
    It is for general purpose requests, but takes care of authentication
    automatically.
   :param str collection: An IRI that points to the location of the \
       crud hub collection (E.g. /api/3/events)
   :param str method: HTTP method
   :param dict body: An object to json encode and send to crud hub
   :return: the API response either as a json-like dict if possible or as bytes
   :rtype: dict/bytes
    """
    # ctrl c/v
    # get rid of the body on GET/HEAD requests
    bodyless_methods = ['head', 'get']
    if method.lower() in bodyless_methods:
        body = None

    if type(body) == str:
        try:
            body = ast.literal_eval(body)
        except Exception:
            pass

    url = settings.CRUD_HUB_URL + url
    logger.info('Starting request: %s , %s', method, url)
    env = kwargs.get('env', {})
    # for default if no env HMAC method
    if not env or not env.get('auth_info', False):
        env['auth_info'] = {"auth_method": "CS HMAC"}

    # for public and private key in env
    if env.get('public_key', False) and env.get('private_key', False):
        env['auth_info'] = {"auth_method": "CS HMAC"}
        public_key = env.get('public_key')
        private_key = env.get('private_key')
    else:
        public_key = settings.APPLIANCE_PUBLIC_KEY
        private_key = settings.APPLIANCE_PRIVATE_KEY
    auth_info = env.get('auth_info')
    auth = get_requests_auth(auth_info, url, method,
                             public_key,
                             private_key,
                             json.dumps(body), *args, **kwargs)
    if files:
        auth = HmacAuth(url, method, public_key, private_key,public_key.encode('utf-8'))
        response = requests.request(method, url, auth=auth, files=files, verify=False)
        if response.status_code in [200,201,204,404]:
            return response
        else:
            logger.error("make_request Error, Status code: {0}, Server Response: {1}".format(response.status_code,response.text))
            raise ConnectorError("make_request Error, Status code: {0}, Server Response: {1}".format(response.status_code,response.text))
    else:
        response = requests.request(method, url, auth=auth, json=body, verify=False)
        if response.status_code in [200,201,204,404]:
            return response
        else:
            logger.error("make_request Error, Status code: {0}, Server Response: {1}".format(response.status_code,response.text))
            raise ConnectorError("make_request Error, Status code: {0}, Server Response: {1}".format(response.status_code,response.text))