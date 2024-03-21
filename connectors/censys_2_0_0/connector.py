""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('censys')


class Censys(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        logger.info('executing {0}'.format(action))
        return action(config, params)

    def check_health(self, config):
        try:
            logger.info('executing check health')
            return _check_health(config)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
