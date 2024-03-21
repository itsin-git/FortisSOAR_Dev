from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations
from .utils import get_mitre_modules

logger = get_logger('Mitre')


class Mitre(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            op = operations.get(operation)
            result = op(config, params)
            return result
        except Exception as e:
            logger.exception('An exception occurred {}'.format(e))
            raise ConnectorError(e)

    def check_health(self, config):
        return get_mitre_modules(config=config)
