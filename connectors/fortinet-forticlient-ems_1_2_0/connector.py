"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

from connectors.core.connector import Connector, get_logger
from .operations import operations, _check_health

logger = get_logger('fortinet-forticlient-ems')


class FortiClientEMS(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        logger.info('Action name {}'.format(action))
        return action(config, params)

    def check_health(self, config):
        _check_health(config)
