""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
# -----------------------------------------
# Fortinet FortiEDR
# -----------------------------------------

from .operations import *
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('fortinet-fortiedr')


class FortiEDR(Connector):
    def execute(self, config, operations, params, **kwargs):
        try:
            operation_info = get_current_operation(self._info_json, operations)
            if operation_info['handler_method'] is False:
                return api_request(config, params, operation_info)
            else:
                operation = fortiedr_ops.get(operations, None)
                if not operation:
                    logger.info('Unsupported operation [{0}]'.format(operations))
                    raise ConnectorError('Unsupported operation')
                result = operation(config, params, operation_info)
                return result
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)


    def check_health(self, config):
        logger.info('starting health check')
        check_health_ex(config)
        logger.info('completed health check no errors')
