# -----------------------------------------
# Qualys
# -----------------------------------------

from .operations import api_request, check_health_ex
from .symbol_table import api_symtab
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('qualys')


class Qualys(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info('execute [{}]'.format(operation))
            if api_symtab.get(operation, '') != '':
                return api_request(config, params, operation)

        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred [{}]".format(err))

    def check_health(self, config):
        logger.info('starting health check')
        check_health_ex(config)
        logger.info('completed health check no errors')
