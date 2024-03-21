""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pandas
import numpy
import json

from connectors.core.connector import get_logger, Connector, ConnectorError
from connectors.core.utils import update_connnector_config

from .util import translate_config_display_fields, config
from .constants import LOGGER_NAME, FSR_MODULE_DATA_SOURCE, PRE_TRAINED_DATA_SOURCE, DATA_SOURCE, \
    ML_SERVICE_CONTROLLER, ML_SERVICE_ROOT_DIR
from .operations import operations
from .ml_service_client import MLServiceClient

ML_SERVICE_PORT = config['SERVER']['port']

logger = get_logger(LOGGER_NAME)

try:
    import uwsgi
    PYTHON_PATH = uwsgi.opt['virtualenv'].decode('utf-8') + '/bin/python'
except Exception:
    PYTHON_PATH = str(sys.executable)


def start_ml_service():
    # check if a process is already listening on the socket
    try:
        logger.info("Starting ml service")
        pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(ML_SERVICE_PORT)])
        logger.info("ML service is already up with pid: {}".format(pid[1:-2]))
    except subprocess.CalledProcessError:
        logger.info("ML service is not up. Starting...")

        root_directory = Path(__file__).parent.resolve()
        service_directory = os.path.join(root_directory, ML_SERVICE_ROOT_DIR)
        ml_server = os.path.join(service_directory, ML_SERVICE_CONTROLLER)

        # Add ml-service directory to pythonpath
        pythonpath = os.environ.get('PYTHONPATH', service_directory).split(os.pathsep)

        if service_directory not in pythonpath:
            pythonpath.append(service_directory)
        my_env = os.environ.copy()
        my_env['PYTHONPATH'] = os.pathsep.join(service_directory)

        command = [PYTHON_PATH, ml_server, 'start']
        subprocess.Popen(command, env=my_env, cwd=service_directory)
        time.sleep(5)
        try:
            pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(ML_SERVICE_PORT)])
        except subprocess.CalledProcessError as err:
            logger.error('Error starting service: %s', str(err))
            raise ConnectorError("Error starting service: {}".format(err))


def stop_ml_service():
    try:
        logger.debug("Stopping ml service")
        pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(ML_SERVICE_PORT)])
        os.kill(int(pid.decode('utf-8').strip()), signal.SIGKILL)
        logger.debug("Stopped ml service")
    except Exception as err1:
        try:
            # during connector uninstall or upgrade, the command is run with nginx user, hence os.kill fails
            subprocess.run(['sudo', '-u', 'fsr-integrations', '/bin/kill', '-9', str(pid)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.STDOUT, timeout=20)
            logger.debug("Stopped ml service (using sudo kill)")
        except Exception as err2:
            logger.exception("Failed to stop the listener with sudo kill also")
    logger.info("ML service is not up.")


class MachineLearning(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info("execute [{}]".format(operation))
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred: {}".format(err))

    def on_app_start(self, all_configs, active):
        logger.info("on app start")
        start_ml_service()

    def on_add_config(self, config, active):
        logger.info("on add config")
        # update translations
        updated_config = translate_config_display_fields(config)
        update_connnector_config(connector_name='phishing-classifier', version=None, updated_config=updated_config,
                                    configId=config.get('config_id'), agent=None)

        # on_app_start does not get called on connector imported using tgz. Hence, starting the service on add config
        start_ml_service()

    def on_update_config(self, old_config, new_config, active):
        logger.info("on update config")
        updated_config = translate_config_display_fields(new_config)
        update_connnector_config(connector_name='phishing-classifier', version=None, updated_config=updated_config,
                                     configId=new_config.get('config_id'), agent=None)
        if old_config['module_data_translated'] != updated_config['module_data_translated']:
            MLServiceClient(new_config).mark_stale(old_config)
    def on_delete_config(self, config):
        logger.info("on delete config")
        MLServiceClient(config).untrain(config)

    def on_activate(self, all_configs):
        logger.info("on activate")
        self.on_app_start(all_configs, True)

    def on_deactivate(self, all_configs):
        logger.info("on deactivate")
        stop_ml_service()

    def teardown(self, all_configs):
        logger.info("on teardown")
        MLServiceClient(all_configs).cleanup()
        # Wait for cleanup
        time.sleep(2)
        stop_ml_service()

    def check_health(self, config):
        logger.info("Request received for health check")
        response = MLServiceClient(config).check_health(config)
        logger.debug(response)
        if response['status'] == -1:
            raise ConnectorError(response['message'])
        return True
