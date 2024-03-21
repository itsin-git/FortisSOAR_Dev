""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
# -----------------------------------------
# Anomali ThreatStream
# -----------------------------------------

from .operations import *
from connectors.core.connector import Connector, get_logger, ConnectorError
from integrations.crudhub import make_request
from django.conf import settings

logger = get_logger('anomali-threatstream')


class ThreatStream(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('execute(): operation is {0}'.format(str(operation)))
        try:
            logger.info('execute [{0}]'.format(operation))
            operation_info = get_curr_oper_info(self._info_json, operation)
            if operation_info['handler_method'] is False:
                return api_request(config, params, operation_info)
            else:
                operation = operation_sym.get(operation)
                return operation(config, params)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config):
        logger.info('Performing health check')
        check_health(config)
        logger.info('Completed health check with no error')

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
