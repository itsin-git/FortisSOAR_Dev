""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

# Intefration connector imports
from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations, MACRO_LIST, CONNECTOR_NAME
from integrations.crudhub import make_request
from django.conf import settings
from .utils import (_check_and_convert_params,
                    _validate_credential,
                    _validate_url,
                    check_config_url)

logger = get_logger('xforce')


class XForce(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        params = _check_and_convert_params(params)
        config = check_config_url(config)
        return action(config, params)

    def check_health(self, config):
        try:
            if not (config['host_name'] and config['api_key'] and config['api_password']):
                raise ConnectorError("Required config params missing")

            validate_url_response = _validate_url(config)
            if not validate_url_response.ok:
                raise ConnectorError('Status Code : {status_code}, Message Source {host_name} is unreachable'.format(
                    status_code=validate_url_response.status_code,
                    host_name=config.get('host_name')))
            config = check_config_url(config)
            validate_credential_response = _validate_credential(config)
            if not validate_credential_response.ok:
                raise ConnectorError("Invalid URI or Credentials")
        except Exception as Err:
            raise ConnectorError(Err)

    def del_micro(self, config):
        if not settings.LW_AGENT:
            for macro in MACRO_LIST:
                try:
                    resp = make_request(f'/api/wf/api/dynamic-variable/?name={macro}', 'GET')
                    if resp['hydra:member']:
                        logger.info("resetting global variable '%s'" % macro)
                        macro_id = resp['hydra:member'][0]['id']
                        resp = make_request(f'/api/wf/api/dynamic-variable/{macro_id}/?format=json', 'DELETE')
                except Exception as e:
                    logger.error(e)

    def on_deactivate(self, config):
        self.del_micro(config)

    def on_activate(self, config):
        self.del_micro(config)

    def on_add_config(self, config, active):
        self.del_micro(config)

    def on_delete_config(self, config):
        self.del_micro(config)
