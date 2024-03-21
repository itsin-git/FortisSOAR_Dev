import os
import subprocess
import psutil
import json
import sys
from .utils.bot_utils import encrypt
from connectors.core.connector import get_logger, ConnectorError
logger = get_logger('slack')

listener_path = os.path.join(os.path.dirname(__file__), 'listener', 'slack_listener.py')
try:
    import uwsgi
    _python_path = uwsgi.opt['virtualenv'].decode('utf-8') + '/bin/python'
except:
    # when run locally
    _python_path = str(sys.executable)

def start_listener(config):
    config_id = config.get('config_id')
    bot_token = config.get('slack_token')
    app_token = config.get('app_token')
    if not config_id or not bot_token or not app_token:
        raise ConnectorError('Missing required parameters to start the listener')
    try:
        payload = encrypt(json.dumps({"bot_token": bot_token, "app_token": app_token}), config_id)
        subprocess.Popen([_python_path, listener_path, '--config_id', config_id, '--payload', payload])
    except:
        logger.exception('Failed to start listener')


def stop_listener(config):
    config_id = config.get('config_id')
    if not config_id:
        raise ConnectorError('Missing required parameters to stop the listener')
    for proc in psutil.process_iter():
        if listener_path in proc.cmdline() and config_id in proc.cmdline():
            pid = proc.pid
            logger.debug('Stopping slack listener with pid {0}'.format(pid))
            try:
                proc.kill()
            except:
                logger.warn("Failed to terminate listener process")
                try:
                    # during connector uninstall or upgrade, the command is run with nginx user, hence proc.kill fails
                    subprocess.run(['sudo', '-u', 'fsr-integrations', '/bin/kill', '-9', str(pid)], stdout=subprocess.DEVNULL, 
                        stderr=subprocess.STDOUT, timeout=20)

                except:
                    logger.exception("Failed to stop the listener with sudo kill also")
            break