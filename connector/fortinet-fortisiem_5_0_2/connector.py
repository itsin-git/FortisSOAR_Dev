""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


from connectors.core.connector import Connector, get_logger
from .operations import operations, _check_health

logger = get_logger('fortinet-fortisiem')


class FortiSIEM(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        logger.info('Action name {0}'.format(action))
        return action(config, params)

    def check_health(self, config):
        _check_health(config)
