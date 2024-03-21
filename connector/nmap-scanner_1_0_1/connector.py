from connectors.core.base_connector import ConnectorError
from connectors.core.connector import Connector, get_logger
from .operation import operations, _check_health

logger = get_logger('nmap-scanner')


class NMAPScanner(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            if not operation:
                raise ConnectorError('Unsupported operation')
            result = operation(params)
            return result
        except Exception as e:
            logger.error('Failure: {}'.format(e))
            raise ConnectorError('{}'.format(e))

    def check_health(self, config):
        return _check_health()
