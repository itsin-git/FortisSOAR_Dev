from connectors.core.connector import get_logger, Connector, ConnectorError
from .operations import operations, _check_health

logger = get_logger('mxtoolbox')


class MxToolbox(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            action = operations.get(operation)
            return action(config, params)
        except Exception as Err:
            logger.exception("An exception occurred: {}".format(Err))
            raise ConnectorError("Error in MxToolbox Connector: {}".format(Err))

    def check_health(self, config):
        return _check_health(config)
