from connectors.core.connector import get_logger, Connector
from .health_check import check
from .get_feed import get_ipv4_feed, get_domain_feed, get_url_feed

logger = get_logger('malsilo')

class Malsiloipv4(Connector):

    def execute(self, config, operation, params, **kwargs):
        supported_operations = {'get_ipv4_feed': get_ipv4_feed,
                                'get_domain_feed': get_domain_feed,
                                'get_url_feed': get_url_feed
                                }
        return supported_operations[operation](config, params)

    def check_health(self, config):
        return check(config)
