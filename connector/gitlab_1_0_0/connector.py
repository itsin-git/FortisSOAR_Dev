from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('gitlab')


class GitLab(Connector):

    def execute(self, config, operation, params, **kwargs):
        try:
            logger.debug('executing function')
            action = operations.get(operation)
            return action(config, params)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def check_health(self, config):
        try:
            logger.debug(" check_health() executing")
            status = _check_health(config)
            logger.info("status: check_health() excecuted ")
            return status
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
