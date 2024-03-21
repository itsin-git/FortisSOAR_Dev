from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations

logger = get_logger('cyops-schedule-report')


class CyOPsReport(Connector):
    def execute(self, config, operation, operation_params, **kwargs):
        try:
            operation = operations.get(operation)
            return operation(config, operation_params)
        except Exception as err:
            logger.exception('{}'.format(err))
            raise ConnectorError('{}'.format(err))

    def check_health(self, config):
        return True

