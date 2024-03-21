import requests
import xmltodict
import tldextract
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('urlvoid')


def get_str_input(params, key):
    logger.info("Getting value for key {}".format(key))
    ret_val = params.get(key, None)
    if isinstance(ret_val, bytes):
        ret_val = ret_val.decode('utf-8')
    return ret_val


def get_config_params(config):
    base_url = config.get('base_url')
    if not base_url.startswith('http://'):
        base_url = 'https://' + base_url
    base_url.strip('/')
    apikey = config.get('api_key')
    identifier = config.get('identifier')
    verify_ssl = config.get('verify_ssl')
    url = '{0}/{1}/{2}/'.format(base_url, identifier, apikey)
    return url, verify_ssl


def make_request(params):
    try:
        domain = get_str_input(params, 'domain')
        list = tldextract.extract(domain)
        if list.subdomain and list.subdomain != 'www':
            domain_name = list.subdomain + '.' + list.domain + '.' + list.suffix
        else:
            domain_name = list.domain + '.' + list.suffix
        logger.info('input domain is {}'.format(domain_name))
        return domain_name
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_response(url, verify_ssl):
    try:
        response = requests.get(url, verify=verify_ssl)
        if response.ok:
            response_dict = xmltodict.parse(response.text)
            logger.info(response_dict)
            if 'error' in response_dict['response'].keys():
                logger.exception(str(response_dict['response']['error']))
                raise ConnectorError(response_dict['response']['error'])
            else:
                logger.info(response_dict['response'])
                return response_dict['response']
        else:
            logger.info(response.text())
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))
    raise ConnectorError(response.text())


def domain_reputation(config, params):
    url, verify_ssl = get_config_params(config)
    domain = make_request(params)
    rescan = params.get('rescan')
    if rescan:
        url = url + 'host/' + domain + '/scan/'
    else:
        url = url + 'host/' + domain + '/'
    return get_response(url, verify_ssl)


def test_connection(config):
    try:
        url, verify_ssl = get_config_params(config)
        url = url + 'stats/remained/'
        response = requests.post(url, verify=verify_ssl)
        response_dict = xmltodict.parse(response.text)
        logger.info(response_dict['response'])
        if 'error' in response_dict['response'].keys():
            logger.exception(str(response_dict['response']['error']))
            raise ConnectorError(response_dict['response']['error'])
        else:
            return True
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError('Invalid Server URL or Identifier')


operations = {
              'domain_reputation': domain_reputation
            }

