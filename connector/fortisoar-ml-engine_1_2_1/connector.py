""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import pandas
import numpy
import json

from connectors.core.connector import get_logger, Connector, ConnectorError
from .operations import operations
from .client import ConfigHandler, LISTENER_DEFAULT_PORT

logger = get_logger('fortisoar-ml-engine')


class MachineLearning(Connector):

    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info("execute [{}]".format(operation))
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred: {}".format(err))

    def on_app_start(self, config, active):
        if active:
            config_list = list(config.values())
            for each_config in config_list:
                config_handler = ConfigHandler(each_config)
                config_handler.start_listener()
                config_handler.update_module_config_map()
                config_handler.load_model()

    def on_add_config(self, config, active):
        config_handler = ConfigHandler(config)
        config_handler.translate_config_display_fields()
        if active:
            config_handler.start_listener()
            config_handler.update_module_config_map()

    def on_update_config(self, old_config, new_config, active):
        old_config_handler = ConfigHandler(old_config)
        new_config_handler = ConfigHandler(new_config)
        try:
            old_config_handler.mark_stale()
            server_started = False
        except Exception:
            logger.info("No active server found during config update. Starting a server with new config...")
            new_config_handler.start_listener()
            server_started = True
        new_config_handler.translate_config_display_fields()
        # if there is a port change, the old listener would have to be stopped
        if old_config['listener_port'] != new_config['listener_port']:
            try:
                old_config_handler.delete_model()
            except Exception:
                logger.info("Could not delete old config model. "
                            "This is most likely due to an improper port configuration and can be ignored. Skipping...")
            if active and not server_started:
                new_config_handler.start_listener()

    def on_delete_config(self, config):
        ConfigHandler(config).delete_model()

    def on_activate(self, config):
        self.on_app_start(config, True)

    def on_deactivate(self, config):
        visited_ports = []
        for conf in config.values():
            try:
                if conf.get('port', LISTENER_DEFAULT_PORT) not in visited_ports:
                    visited_ports.append(conf.get('listener_port', LISTENER_DEFAULT_PORT))
                    ConfigHandler(config).stop_listener()
            except Exception as e:
                logger.exception(e)

    def teardown(self, config):
        logger.debug("Teardown listener setup for ML connector")
        self.on_deactivate(config)

    def check_health(self, config):
        response = ConfigHandler(config).check_listener_health()
        response = json.loads(response.decode('utf-8'))
        if response['status'] == -1:
            raise ConnectorError(response['message'])
        return True
