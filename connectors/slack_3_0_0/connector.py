""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

# -----------------------------------------
# Slack
# -----------------------------------------

from .operations import *
from .bot_handler import start_listener, stop_listener
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('slack')


class Slack(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('execute(): operation is {}'.format(str(operation)))
        try:
            operation = operations.get(operation)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config, params)

    def check_health(self, config):
        logger.info('Performing health check')
        check_health_ex(config)
        logger.info('Completed health check with no error code')

    def on_add_config(self, config, active):
        if active and config.get('enable_slack_bot') and check_health_ex(config):
            try:
                start_listener(config)
            except Exception as e:
                logger.exception(e)

    def on_app_start(self, config, active):
        if active:
            config_list = list(config.values())
            for each_config in config_list:
                if each_config.get('enable_slack_bot') and check_health_ex(each_config):
                    try:
                        start_listener(each_config)
                    except Exception as e:
                        logger.error("on app start", e)

    def on_activate(self, config):
        for each_config in config.values():
            if each_config.get('enable_slack_bot') and check_health_ex(each_config):
                try:
                    start_listener(each_config)
                except Exception as e:
                    logger.error(e)

    def on_delete_config(self, config):
        if config.get('enable_slack_bot'):
            stop_listener(config)

    def on_update_config(self, old_config, new_config, active):
        if old_config.get('enable_slack_bot'):
            stop_listener(old_config)
        if active and new_config.get('enable_slack_bot') and check_health_ex(new_config):
            try:
                start_listener(new_config)
            except Exception as e:
                logger.exception(e)

    def on_deactivate(self, config):
        for conf in config.values():
            try:
                if conf.get('enable_slack_bot'):
                    stop_listener(conf)
            except Exception as e:
                logger.error(e)

    def teardown(self, config):
        logger.debug('on teardown')
        self.on_deactivate(config)
