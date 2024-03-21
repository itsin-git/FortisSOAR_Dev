import json
import os
import signal
import socket
import subprocess
import sys
import time

from pathlib import Path

from .operations import operations
from .utils import config
from .check_health import _check_health
from connectors.core.connector import Connector, get_logger, ConnectorError
from .constants import LOGGER_NAME, WEBSERVER_ROOT_DIR, WEBSERVER_CONTROLLER, HOSTNAME

logger = get_logger(LOGGER_NAME)

PORT = config['SERVER']['port']

try:
    import uwsgi

    PYTHON_PATH = uwsgi.opt['virtualenv'].decode('utf-8') + '/bin/python'
except Exception as e:
    PYTHON_PATH = str(sys.executable)


def start_mi_service(config):
    logger.info("Trying to start mi service")
    # check if a process is already listening on the socket
    try:
        logger.info("Starting mi service")
        port = config.get('port', PORT)
        pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(port)])
        logger.info("MI service is already up with pid: {}".format(pid[:-1]))
    except subprocess.CalledProcessError:
        logger.info("MI service is not up. Starting...")

        root_directory = Path(__file__).parent.resolve()
        service_directory = os.path.join(root_directory, WEBSERVER_ROOT_DIR)
        webserver = os.path.join(service_directory, WEBSERVER_CONTROLLER)

        # Add ml-service directory to pythonpath
        pythonpath = os.environ.get('PYTHONPATH', service_directory).split(os.pathsep)

        if service_directory not in pythonpath:
            pythonpath.append(service_directory)
        my_env = os.environ.copy()
        my_env['PYTHONPATH'] = os.pathsep.join(service_directory)

        # Starting with Python 3.8, python -m http.server supports IPv6
        # To listen on all all available interfaces:
        # python -m http.server --bind ::
        hostname = HOSTNAME
        if socket.has_dualstack_ipv6():
            hostname = '::'
        command = [PYTHON_PATH, webserver, 'start', hostname, json.dumps(config)]
        subprocess.Popen(command, env=my_env, cwd=service_directory)
        time.sleep(5)
        try:
            port = config.get('port', PORT)
            pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(port)])
        except subprocess.CalledProcessError as err:
            logger.error('Error starting service: %s', str(err))
            raise ConnectorError("Error starting service: {}".format(err))


def stop_mi_service(config):
    try:
        logger.debug("Stopping MI service")
        port = config.get('port', PORT)
        pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(port)])
        os.kill(int(pid.decode().strip()), signal.SIGTERM)
        logger.debug("Stopped MI service")
    except subprocess.CalledProcessError:
        logger.error("Either the MI service is not up, or we don't have the required privileges to stop.")


class ManualInputConnector(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            config['connector_error'] = {"connector_name": self._info_json.get('name'),
                                         "connector_version": self._info_json.get('version')}
            operation = operations.get(operation)
            if not operation:
                logger.error('Unsupported operation: {}'.format(operation))
                raise ConnectorError('Unsupported operation')
            return operation(config, params)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config):
        config['connector_error'] = {"connector_name": self._info_json.get('name'),
                                     "connector_version": self._info_json.get('version')}
        return _check_health(config)

    def on_app_start(self, config, active):
        logger.info("on app start")
        for uuid, conf in config.items():
            start_mi_service(conf)

    def on_add_config(self, config, active):
        logger.info("on update config")
        start_mi_service(config)

    def on_update_config(self, old_config, new_config, active):
        logger.info("on update config")
        stop_mi_service(old_config)
        start_mi_service(new_config)

    def on_delete_config(self, config):
        logger.info("on delete config")
        stop_mi_service(config)

    def on_activate(self, config):
        logger.info("on activate")
        for uuid, conf in config.items():
            start_mi_service(conf)

    def on_deactivate(self, config):
        logger.info("on deactivate")
        for uuid, conf in config.items():
            stop_mi_service(conf)

    def teardown(self, config):
        logger.info("on teardown")
        for uuid, conf in config.items():
            stop_mi_service(conf)
