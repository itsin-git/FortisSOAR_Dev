"""
Steps related to fetching and parsing email
"""

from .fetch_mail_utility import _fetch_email, _make_imap_client, logout_client
from connectors.core.connector import get_logger, ConnectorError
from .handler import ConfigHandler

logger = get_logger("builtins.imap")

# py 3.6 when
DISPLAY_SIZE_LIMIT = 20000

def fetch_email(config, *args, **kwargs):
    """
   :return: a list of extracted email parts
   :rtype: list
    """
    client = _make_imap_client(config.get('host'), config.get('port'),
                               config.get('username'), config.get('password'), config.get('ssl'), config.get('verify'))

    fetched_mails = _fetch_email(client, config.get('source'), config.get('destination'), new=True, **kwargs)
    logout_client(client)
    return fetched_mails

def fetch_email_new(config, params, *args, **kwargs):
    """
   :return: a list of extracted email parts
   :rtype: list
    """
    limit_count = params.get('limit_count', 30)
    parse_inline_image = params.get('parse_inline_image', False)
    client = _make_imap_client(config.get('host'), config.get('port'),
                               config.get('username'), config.get('password'), config.get('ssl'), config.get('verify'))

    fetched_mails = _fetch_email(client, config.get('source'), config.get('destination'), limit_count, optimize=True, new=True, parse_inline_image=parse_inline_image, **kwargs)
    logout_client(client)
    return fetched_mails

def start_notification(config,*args, **kwargs):
    return ConfigHandler(config).start_listener()

def stop_notification(config):
    return ConfigHandler(config).stop_listener()

def check_listener_health(config):
    return ConfigHandler(config).check_listener_health()

def exit_notifier(config=None):
    return ConfigHandler(config).exit_socket()
