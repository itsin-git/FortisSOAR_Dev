""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from connectors.core.connector import Connector, get_logger, ConnectorError

from .operation import check_health, fortigate_operations

logger = get_logger('fortigate-firewall')


class FortiGate(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info('In execute() Operation:[{}]'.format(operation))
            operation = fortigate_operations.get(operation, None)
            result = operation(config, params)
            return result
        except Exception as e:
            logger.error(e)
            raise ConnectorError(e)

    def check_health(self, config):
        try:
            return check_health(config)
        except Exception as e:
            raise ConnectorError(e)
