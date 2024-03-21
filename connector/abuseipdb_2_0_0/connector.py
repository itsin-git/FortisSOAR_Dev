from connectors.core.connector import get_logger, ConnectorError, Connector

from .operations import operations, _check_health

logger = get_logger('AbuseIPDB')


class AbuseIPDB(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            action = operations.get(operation)
            logger.info('Executing action {0}'.format(action))
            return action(config, params)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def check_health(self, config):
        try:
            _check_health(config)
        except Exception as e:
            raise ConnectorError(e)
