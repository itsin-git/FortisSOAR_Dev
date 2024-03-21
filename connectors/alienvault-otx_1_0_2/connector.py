""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import operations, test_connection
logger = get_logger('AlienVaultOtx')


class AlienVaultOtx(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        return action(config, params)

    def check_health(self, config):
        try:
            logger.info('executing check health')
            connection_response = test_connection(config)
            return connection_response
        except Exception as exp:
            logger.exception(str(exp))
            raise ConnectorError(str(exp))



