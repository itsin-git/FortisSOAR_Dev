""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('tenable-io')


class Tenable(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            action = operations.get(operation)
            logger.info('Action name {}'.format(action))
            return action(config, params)
        except Exception as e:
            logger.error("An exception occurred: {}".format(e))
            raise ConnectorError("An exception occurred: {}".format(e))

    def check_health(self, config):
        try:
            _check_health(config)
        except Exception as e:
            logger.error("An exception occurred: {}".format(e))
            raise ConnectorError("An exception occurred: {}".format(e))

