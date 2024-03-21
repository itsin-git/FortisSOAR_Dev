""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import sys
import arrow
import requests
from requests.exceptions import ConnectionError

from connectors.core.connector import get_logger, ConnectorError

from .util import config
from .constants import LOGGER_NAME

ML_SERVICE_PORT = config['SERVER']['port']

DATE_FIELD = 'modifyDate'

logger = get_logger(LOGGER_NAME)
try:
    import uwsgi

    PYTHON_PATH = uwsgi.opt['virtualenv'].decode('utf-8') + '/bin/python'
except Exception:
    PYTHON_PATH = str(sys.executable)


def _set_date_filters(date_selection, custom_value=0):
    if date_selection == 'Last month':
        arrow_argument = {'months': -1}
    elif date_selection == 'Last 6 months':
        arrow_argument = {'months': -6}
    elif date_selection == 'Last year':
        arrow_argument = {'years': -1}
    elif date_selection == 'Last 2 years':
        arrow_argument = {'years': -2}
    elif date_selection == 'Last 5 years':
        arrow_argument = {'years': -5}
    else:
        arrow_argument = {'days': -custom_value}

    filters = [{
                    'field': DATE_FIELD,
                    'operator': 'gte',
                    'value': '{}{}'.format(arrow.now().shift(**arrow_argument).format('YYYY-MM-DDTHH:mm:ss'), 'Z'),
                    'type': 'datetime'
                }
    ]
    return filters


def _make_rest_call(method, url, body):
    try:
        response = requests.request(method, url, json=body)
        if response.status_code == 200:
            if response.json().get('status') == -1:
                raise ConnectorError(response.json().get('message')[:200])
            return response.json()
        else:
            logger.error('Invalid response received')
            logger.error(response.status_code)
            logger.error(response.content)
            raise ConnectorError("Incorrect response received from ML service")
    except ConnectionError as error:
        logger.error("Could not connect to ML service.")
        raise ConnectorError("ML Service is not running")

class MLServiceClient():
    def __init__(self, config):
        self.config = config

    def get_train_size(self):
        if not self.config.get('train_size'):
            train_size = 100000
        else:
            train_size = self.config.get('train_size')
        return train_size

    def get_date_filter(self):
        if not self.config.get('date_range') == 'Custom':
            filters = _set_date_filters(self.config.get('date_range'))
        else:
            filters = _set_date_filters('Custom', self.config.get('custom_value'))
        return filters

    def train(self, config, params):
        logger.info('self.config: %s', config)
        body = {
            "action": "train",
            "data": {
                "config": config,
                "param": params
            }
        }
        return _make_rest_call('POST', "http://localhost:" + ML_SERVICE_PORT + "/classifier", body)

    def get_training_results(self, config, params):
        logger.info('self.config: %s', config)
        body = {
            "action": "get_training_results",
            "data": {
                "config": config,
                "param": params
            }
        }
        return _make_rest_call('POST', "http://localhost:" + ML_SERVICE_PORT + "/classifier", body)

    def predict(self, config, params, record):
        logger.debug("calling ml service predict operation")
        body = {
            "action": "predict",
            "data": {
                "config": config,
                "params": params,
                "record": record
            }
        }
        return _make_rest_call('POST', "http://localhost:" + ML_SERVICE_PORT + "/classifier", body)

    def check_health(self, config):
        body = {
            "action": "check-health",
            "data": {
                "config": config
            }
        }
        return _make_rest_call('POST', "http://localhost:" + ML_SERVICE_PORT + "/classifier", body)

    def untrain(self, config):
        logger.debug("calling ml service untrain endpoint")
        body = {
            "action": "untrain",
            "data": {
                "config": config
            }
        }
        return _make_rest_call('POST', "http://localhost:" + ML_SERVICE_PORT + "/classifier", body)

    def cleanup(self):
        logger.debug("calling ml service cleanup endpoint")
        body = {
            "action": "cleanup",
            "data": {
            }
        }
        try:
            _make_rest_call('POST', "http://localhost:" + ML_SERVICE_PORT + "/classifier", body)
        except ConnectorError:
            logger.info("Could not run cleanup as ML service is down")

    def mark_stale(self, config):
        logger.debug("calling ml service mark-stale endpoint")
        body = {
            "action": "mark_stale",
            "data": {
                "config": config
            }
        }
        try:
            _make_rest_call('POST', "http://localhost:" + ML_SERVICE_PORT + "/classifier", body)
        except ConnectorError:
            logger.info("Could not mark stale as ML service is down")