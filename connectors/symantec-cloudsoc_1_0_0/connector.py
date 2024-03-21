"""
Symantec CASB Connector
"""
from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations
from .utils import (_check_and_convert_params,
                    _validate_connectivity)

logger = get_logger('symantec-casb')


class SymantecCASB(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        params = _check_and_convert_params(params)
        return action(config, params)

    def check_health(self, config):
        logger.info('Symantec CASB Health check Start')
        try:
            validate_connectivity_response = _validate_connectivity(config)
            logger.info('Symantec CASB Health check Stop')
            if not validate_connectivity_response.ok:
                logger.error(validate_connectivity_response.text)
                raise ConnectorError('Invalid URI or Credentials')
            return True
        except Exception as Err:
            raise ConnectorError(Err)
