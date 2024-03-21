from os.path import join, exists, dirname
import subprocess
import sys
import logging
import time
import socket
import json
from connectors.core.connector import Connector, ConnectorError
from .errors.error_constants import *

LISTENER_HOST = 'localhost'
listener_path = join(dirname(__file__), 'scripts/imap_push_notification.py')
logger = logging.getLogger(__name__)


def send_socket_message(message, listener_port):
    validate_listener_port(listener_port)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((LISTENER_HOST, listener_port))
    client.sendall(message.encode('utf-8'))
    response = client.recv(1024)
    client.close()
    response_json = json.loads(response.decode('utf-8'))
    status = response_json['status']
    if status != 0:
        raise ConnectorError(response_json['message'])
    else:
        return response_json

def validate_listener_port(listener_port):
    pid = subprocess.check_output('/usr/sbin/lsof -titcp:' + str(listener_port), shell=True).decode(
        "utf-8")
    cmd = subprocess.check_output('ps -f -o cmd -p ' + str(pid), shell=True).decode("utf-8")
    cmd_list = cmd.split(' ')
    if listener_path not in cmd_list:
        raise subprocess.CalledProcessError(returncode=-1, cmd=cmd,
                                            output='Port is busy with running different script')

class ConfigHandler:
    def __init__(self, config={}):
        try:
            import uwsgi
            self._python_path = uwsgi.opt['virtualenv'].decode('utf-8') + '/bin/python'
        except Exception:
            # when run locally
            self._python_path = str(sys.executable)
        self._config = config
        self._listener_port = config.get('listener_port', 10010)

    def start_listener_socket(self):
        try:
            validate_listener_port(self._listener_port)
        except subprocess.CalledProcessError as e:
            logger.info('Socket listener is not up. Starting...')
            subprocess.Popen([self._python_path, listener_path, str(self._listener_port)])
            # wait for 5 seconds
            time.sleep(5)
            try:
                validate_listener_port(self._listener_port)
            except subprocess.CalledProcessError as e2:
                logger.error("{0} ERROR :: {1}".format(cs_imap_15, str(e2)))
                raise ConnectorError(cs_imap_15)

    def start_listener(self):
        self.start_listener_socket()
        return send_socket_message('--start --host {0} --port {1} --username {2} '
                                   ' --password {3} --ssl {4} --source {5} --verify {6}'
                                   ' --trigger {7}'
                                   .format(self._config.get('host'), str(self._config.get('port')),
                                           self._config.get('username'), self._config.get('password'),
                                           str(self._config.get('ssl')), self._config.get('source'),
                                           self._config.get('verify',True),self._config.get('trigger')),
                                   self._listener_port)

    def stop_listener(self):
        try:
            return send_socket_message('--stop --host {0} --port {1} --username {2} --source {3}'
                                       .format(self._config.get('host'), str(self._config.get('port')),
                                               self._config.get('username'), self._config.get('source')),
                                       self._listener_port)
        except subprocess.CalledProcessError as e2:
            logger.error("{0} ERROR :: {1}".format(cs_imap_16, str(e2)))
        except ConnectionRefusedError:
            logger.warning(cs_imap_16)

    def exit_socket(self):
        try:
            return send_socket_message('--exit', self._listener_port)
        except subprocess.CalledProcessError as e2:
            logger.error("{0} ERROR :: {1}".format(cs_imap_16, str(e2)))
        except ConnectionRefusedError:
            logger.warning(cs_imap_16)
            return 'Success'

    def restart_listener(self):
        try:
            return send_socket_message('--restart --transport {0} --port {1} --trigger {2} --username {3}'
                                       ' --password {4} --filter "{5}"'.format(self._protocol, str(self._port),
                                                                               self._trigger, self._username,
                                                                               self._password, self._filter),
                                       self._listener_port)
        except ConnectionRefusedError:
            logger.warning(cs_imap_17)
            return self.start_listener

    def check_listener_health(self):
        try:
            logger.info("Checking health of notification service")
            return send_socket_message('--check --host {0} --port {1} --username {2} --source {3}'
                                       .format(self._config.get('host'), str(self._config.get('port')),
                                               self._config.get('username'), self._config.get('source')),
                                       self._listener_port)
        except subprocess.CalledProcessError as e2:
            logger.error("{0} ERROR :: {1}".format(cs_imap_15, str(e2)))
            raise ConnectorError(cs_imap_15)
        except ConnectionRefusedError:
            logger.warning(cs_imap_16)
            raise ConnectorError(cs_imap_16)
