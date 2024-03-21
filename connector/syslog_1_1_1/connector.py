from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import ConfigHandler, parse_message, stop_socket_server
import time

logger = get_logger('syslog')


class Syslog(Connector):
    def on_app_start(self, config, active):
        if active:
            config_list = list(config.values())
            for each_config in config_list:
                ConfigHandler(each_config).start_listener()

    def on_add_config(self, config, active):
        if active:
            ConfigHandler(config).start_listener()

    def on_delete_config(self, config):
        ConfigHandler(config).stop_listener()

    def on_update_config(self, old_config, new_config, active):
        ConfigHandler(old_config).stop_listener()
        if active:
            time.sleep(5)
            new_obj = ConfigHandler(new_config)
            new_obj.start_listener()

    def on_activate(self, config):
        for conf in config.values():
            ConfigHandler(conf).start_listener()

    def on_deactivate(self, config):
        stop_socket_server()

    def teardown(self):
        stop_socket_server()

    def execute(self, config, operation, params, **kwargs):
        syslog_obj = ConfigHandler(config)

        operations = {
            'start': syslog_obj.start_listener,
            'stop': syslog_obj.stop_listener,
            'restart': syslog_obj.restart_listener,
            'parse': parse_message
        }

        op = operations.get(operation, None)
        if not op:
            raise ConnectorError('Unsupported operation')
        if operation == 'parse':
            result = op(params)
        else:
            result = op()
        return result

    def check_health(self, config):
        syslog_obj = ConfigHandler(config)
        syslog_obj.check_listener_health()
