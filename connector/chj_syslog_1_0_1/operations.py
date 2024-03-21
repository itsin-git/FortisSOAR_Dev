from os.path import join, exists, dirname
from os import makedirs
import subprocess
import shutil
import sys
import logging
import time
import socket
import json
from .parser import Parser

deployment_dir = '/opt'
connector_dir = 'cyops-connector-syslog'
LISTENER_HOST = '127.0.0.1'
LISTENER_PORT = 10000

connector_path = join(deployment_dir, connector_dir)
listener_path = join(connector_path, 'sysloglistener.py')


logger = logging.getLogger(__name__)


class ConnectorError(Exception):
    pass


def parse_message(params):
    parser = Parser(params['rfc'])
    message = params['message']
    logger.info('Parsing %s' % message)
    try:
        response = parser.parse(message)
        logger.info('Parsed message: %s' % response)
        return response
    except Exception:
        logger.exception('Message parsing failed')
        raise ConnectorError('Message parsing failed. Not a valid RFC%s message' % params['rfc'])


def send_socket_message(message):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((LISTENER_HOST, LISTENER_PORT))
    logger.info('Sending message')
    client.sendall(message.encode('utf-8'))
    response = client.recv(1024)
    client.close()
    logger.info('response: %s' % response.decode('utf-8'))
    response_json = json.loads(response.decode('utf-8'))
    status = response_json['status']
    if status != 0:
        raise ConnectorError(response_json['message'])
    else:
        return response_json


def stop_socket_server():
    # check if server is up
    try:
        pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:' + str(LISTENER_PORT)])
        logger.info('Socket listener is up with pid %s' % pid)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((LISTENER_HOST, LISTENER_PORT))
        client.sendall('--exit'.encode('utf-8'))
        client.close()
        logger.info('shutdown listeners')
    except subprocess.CalledProcessError as e:
        logger.info('Socket listener is not up. Exiting.')


class ConfigHandler:
    def __init__(self, config):
        try:
            import uwsgi
            self._python_path = uwsgi.opt['virtualenv'].decode('utf-8') + '/bin/python'
        except Exception:
            # when run locally
            self._python_path = str(sys.executable)
        self._protocol = config['protocol']
        self._port = config['port']
        if self._port < 1024:
            raise ConnectorError('Cannot start listener on a system port. Port must be 1024 or higher.')
        self._trigger = config['trigger']
        self._filter = config.get('filter_str', '')
        self._filter = config.get('filter_str', '')
        self._name = self._protocol + ':' + str(self._port)
        logger.info('config- %s:%s, trigger %s' % (self._protocol, str(self._port),
                                                                     self._trigger))

    def start_listener_socket(self):
        # check if a process is already listening on the socket
        try:
            pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:' + str(LISTENER_PORT)])
            logger.info('Socket listener is up with pid %s' % str(pid))
        except subprocess.CalledProcessError as e:
            logger.info('Socket listener is not up. Starting...')
            logger.info('python path %s' % self._python_path)
            subprocess.Popen([self._python_path, listener_path])
            # wait for 5 seconds
            time.sleep(5)
            try:
                pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:' + str(LISTENER_PORT)])
            except subprocess.CalledProcessError as e2:
                raise ConnectorError('Error starting listener')

    def start_listener(self):
        logger.info('starting listener %s' % self._name)
        self.start_listener_socket()
        return send_socket_message('--start --transport {0} --port {1} --trigger {2}'
                                   ' --filter "{3}"'.format(self._protocol, str(self._port), self._trigger, self._filter))

    def stop_listener(self):
        logger.info('stopping listener %s' % self._name)
        try:
            return send_socket_message('--stop --transport {0} --port {1}'.format(self._protocol, str(self._port)))
        except ConnectionRefusedError:
            logger.warning('Listener already stopped. Returning')
            return {'status': 0, 'message': 'Listener already stopped'}

    def restart_listener(self):
        logger.info('restarting listener %s' % self._name)
        try:
            return send_socket_message('--restart --transport {0} --port {1} --trigger {2} --filter "{3}"'.format(self._protocol, str(self._port),
                                                                               self._trigger, self._filter))
        except ConnectionRefusedError:
            logger.warning('Listener already stopped. Starting')
            return self.start_listener

    def check_listener_health(self):
        logger.info('check health for listener %s' % self._name)
        return send_socket_message('--check --transport {0} --port {1}'.format(self._protocol, str(self._port)))

