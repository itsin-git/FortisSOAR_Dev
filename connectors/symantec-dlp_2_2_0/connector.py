""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _validate_connectivity
from .utils import (check_config_url)


logger = get_logger('symantec-dlp')


class SymantecDLP(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        config = check_config_url(config)
        return action(config, params)

    def check_health(self, config):
        try:
            config = check_config_url(config)
            validate_connectivity_response = _validate_connectivity(config)
            if not validate_connectivity_response:
                logger.error(validate_connectivity_response)
                raise ConnectorError('Invalid URI or Credentials')
            return True
        except Exception as Err:
            if 'not licensed' in str(Err):
                raise ConnectionError('Invalid License/License Not Found')
            raise ConnectorError(Err)
