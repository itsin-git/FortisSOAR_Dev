""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations, check_health

logger = get_logger('jira')


class Jira(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            return operation(config, params, **kwargs)
        except Exception as Err:
            raise ConnectorError(Err)

    def check_health(self, config):
        try:
            return check_health(config)
        except Exception as e:
            raise ConnectorError(e)
