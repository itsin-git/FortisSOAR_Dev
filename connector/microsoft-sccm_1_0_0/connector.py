from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import operations
logger = get_logger('sccm')


class MicrosoftSCCM(Connector):
    def execute(self, config, operation, params, **kwargs):
        op = operations.get(operation, None)
        if not operation:
            raise ConnectorError('Unsupported operation')
        result = op(config, params)
        return result

    def check_health(self, config):
        return operations.get('check_health')(config)
