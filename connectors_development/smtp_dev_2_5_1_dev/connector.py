from connectors.core.connector import Connector, get_logger
from .builtins import send_email, send_richtext_email, get_users, get_teams, get_email_templates, send_email_new
from django.core.mail.backends.smtp import EmailBackend

logger = get_logger("builtins.smtp")


class SMTP(Connector):

    def execute(self, config, operation, params, **kwargs):
        env = kwargs.get('env', {})
        params.update({'env': env})
        operations = {
            'send_email': send_email,
            'send_richtext_email': send_richtext_email,
            'send_email_new': send_email_new,
            'get_users': get_users,
            'get_teams': get_teams,
            'get_email_templates': get_email_templates
        }
        action = operations.get(operation)
        return action(config, params)

    def check_health(self, config):
        backend = EmailBackend(host=config['host'], port=config['port'],
                               username=config.get('username', ''),
                               password=config.get('password', ''),
                               use_tls=config['useTLS'],
                               timeout=config.get('timeout', 10))
        backend.open()
        try:
            backend.close()
        except Exception as e:
            logger.exception("Message: SMTP Connection logout unsuccessful %s", str(e))
