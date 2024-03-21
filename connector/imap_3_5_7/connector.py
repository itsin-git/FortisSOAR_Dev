from connectors.core.connector import Connector, get_logger, ConnectorError
from .builtins import fetch_email, fetch_email_new, _make_imap_client, start_notification, stop_notification, exit_notifier, check_listener_health
from .errors.error_constants import *
pass_encrypt = True
try:
    from connectors.utils import manage_password
except:
    pass_encrypt = False
import time

logger = get_logger('IMAP')


class IMAP(Connector):

    def execute(self, config, operation, operation_params, **kwargs):
        logger.info('on operation execution')
        supported_operations = {'fetch_email': fetch_email,
                                'fetch_email_new': fetch_email_new
                                }
        operation = supported_operations.get(operation)
        return operation(config, operation_params, **kwargs)

    def on_app_start(self, config, active):
        logger.info('on app start')
        if active:
            for conf in config.values():
                if conf.get('notification_service'):
                    try:
                        start_notification(conf)
                    except Exception as e:
                        logger.info(e)

    def on_add_config(self, config, active):
        logger.info('on add config')
        if pass_encrypt:
            if config.get('password'):
                config['password'] = manage_password(config.get('password'),'decrypt')
        if active and config.get('notification_service'):
            try:
                start_notification(config)
            except Exception as e:
                logger.exception(e)

    def on_delete_config(self, config):
        logger.info('on delete config')
        if config.get('notification_service'):
            stop_notification(config)

    def on_update_config(self, old_config, new_config, active):
        logger.info('on update config')
        if pass_encrypt:
            if new_config.get('password'):
                new_config['password'] = manage_password(new_config.get('password'),'decrypt')
        if old_config.get('notification_service'):
            stop_notification(old_config)
        if active and new_config.get('notification_service'):
            time.sleep(5)
            try:
                start_notification(new_config)
            except Exception as e:
                logger.exception(e)

    def on_activate(self, config):
        logger.info('on active')
        for conf in config.values():
            if conf.get('notification_service'):
               try:
                   start_notification(conf)
               except Exception as e:
                   logger.info(e)

    def on_deactivate(self, config):
        logger.info('on deactivate')
        visited_ports = []
        for conf in config.values():
            try:
                if conf.get('notification_service') and not conf.get('port', 10010) in visited_ports:
                    visited_ports.append(conf.get('port', 10010))
                    exit_notifier(conf)
            except Exception as e:
                logger.error(e)

    def teardown(self, config):
        logger.info('on teardown')
        self.on_deactivate(config)

    def check_health(self, config):
        try:
            client = _make_imap_client(config.get('host'),
                                       config.get('port'),
                                       config.get('username'),
                                       config.get('password'),
                                       config.get('ssl'),
                                       config.get('verify')
                                       )
            # end the imap session
            client.logout()
        except Exception as e:
            raise ConnectorError(e)

        if config.get('notification_service'):
            try:
               check_listener_health(config)
            except Exception as e:
                logger.exception(e)
                raise ConnectorError(e)
