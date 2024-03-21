from connectors.core.connector import get_logger, ConnectorError
import requests
logger = get_logger('malsilo')

def raise_if_url_unreachable(url):
    site_ping = requests.head(url)
    if site_ping.status_code < 400:
        return True
    else:
        logger.error("Response code for URL '{}': {}".format(url, site_ping.status_code))
        raise ConnectorError("URL '{}' is not reachable".format(url))

def check(config):
    ipv4_url = config.get('ipv4_url', 'https://malsilo.gitlab.io/feeds/dumps/ip_list.txt')
    raise_if_url_unreachable(ipv4_url)
    url_url = config.get('url_url', 'https://malsilo.gitlab.io/feeds/dumps/url_list.txt')
    raise_if_url_unreachable(url_url)
    domain_url = config.get('domain_url', 'https://malsilo.gitlab.io/feeds/dumps/domain_list.txt')
    raise_if_url_unreachable(domain_url)
    return True