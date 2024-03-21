""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('text_extractor')


class TextExtractor(Connector):
    """Main Class"""

    def execute(self, config, operation, params, *args, **kwargs):
        params.update({"operation": operation})
        action = operations.get(operation)
        return action(config, params, *args, **kwargs)

    def check_health(self, config):
        _check_health(config)
