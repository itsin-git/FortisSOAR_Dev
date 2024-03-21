""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import subprocess
import sys
import time
import socket
import os
import json
import arrow

from struct import pack
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.crudhub import make_cyops_request
from connectors.core.utils import update_connnector_config

LISTENER_HOST = 'localhost'
LISTENER_DEFAULT_PORT = 10443

DATE_FIELD = 'modifyDate'

logger = get_logger('fortisoar-ml-engine')
try:
    import uwsgi

    PYTHON_PATH = uwsgi.opt['virtualenv'].decode('utf-8') + '/bin/python'
except Exception:
    PYTHON_PATH = str(sys.executable)


def _get_module_type(module_name):
    type_body_dict = {
        'logic': 'OR',
        'filters': [{
            'operator': 'eq',
            'field': 'name',
            'value': module_name}
        ]
    }
    return make_cyops_request('/api/query/modules', 'POST', body=type_body_dict)['hydra:member'][0]['type']


def _map_module_fields(module, feature_set):
    response = make_cyops_request('/api/3/model_metadatas?type={}&$relationships=true'.format(module), 'GET')[
        'hydra:member']

    mapped_feature_set = []

    for field in response[0]['attributes']:
        if field['descriptions']['singular'] in feature_set:
            mapped_feature_set.append(field['name'])

    return mapped_feature_set


def _set_date_filters(date_selection, custom_value=0):
    if date_selection == 'Last month':
        difference_type = 'months'
        difference_value = -1
        arrow_argument = {'months': -1}
    elif date_selection == 'Last 6 months':
        difference_type = 'months'
        difference_value = -6
        arrow_argument = {'months': -6}
    elif date_selection == 'Last year':
        difference_type = 'years'
        difference_value = -1
        arrow_argument = {'years': -1}
    elif date_selection == 'Last 2 years':
        difference_type = 'years'
        difference_value = -2
        arrow_argument = {'years': -2}
    elif date_selection == 'Last 5 years':
        difference_type = 'years'
        difference_value = -5
        arrow_argument = {'years': -5}
    else:
        difference_type = 'days'
        difference_value = custom_value
        arrow_argument = {'days': -custom_value}

    filters = [{
                    'field': DATE_FIELD,
                    'operator': 'gte',
                    'value': '{}{}'.format(arrow.now().shift(**arrow_argument).format('YYYY-MM-DDTHH:mm:ss'), 'Z'),
                    'type': 'datetime'
                }
    ]
    return filters


def send_socket_message(port, message):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((LISTENER_HOST, port))
        logger.info("Sending message: {}".format(message))
        encoded_message = message.encode('utf-8')
        length = pack('>Q', len(encoded_message))
        client.sendall(length)
        client.sendall(encoded_message)
        response = b''
        BUFF_SIZE = 4096
        while True:
            part = client.recv(BUFF_SIZE)
            response += part
            if len(part) < BUFF_SIZE:
                # either 0 or end of data
                break
        client.close()
        decode_response = response.decode('utf-8')
        if decode_response:
            response_json = json.loads(decode_response)
            if int(response_json.get('status')) != 0:
                raise ConnectorError(response_json.get('message'))
        return response
    except Exception as err:
        raise ConnectorError(err)


def stop_socket_server(port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((LISTENER_HOST, port))
        logger.info("Sending shutdown message")
        client.sendall('--exit'.encode('utf-8'))
        client.close()
    except Exception as err:
        raise ConnectorError(err)


def start_socket_server(port):
    # check if a process is already listening on the socket
    try:
        pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(port)])
        logger.info("Socket listener is already up with pid: {}".format(pid[1:-2]))
    except subprocess.CalledProcessError:
        logger.info("Socket listener is not up. Starting...")
        listener_path = os.path.join(os.path.dirname(__file__), 'scripts', 'server.py')
        command = [PYTHON_PATH, listener_path, str(port)]
        subprocess.Popen(command)
        time.sleep(10)
        try:
            pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(port)])
        except subprocess.CalledProcessError as err:
            logger.error('Error starting listener: %s', str(err))
            raise ConnectorError("Error starting listener: {}".format(err))


class ConfigHandler:
    def __init__(self, config):
        self.config = config

    def get_port(self):
        port = self.config.get('listener_port', LISTENER_DEFAULT_PORT)
        if port < 1024:
            raise ConnectorError("Cannot start listener on a system port. Port must be 1024 or higher.")
        return port

    def get_algo(self):
        model_mappings = {
            'Logistic Regression': 'LR',
            'Linear Discriminant': 'LDA',
            'K-Nearest Neighbors': 'KNN',
            'Decision Tree': 'CART',
            'Naive Bayes': 'NB',
            'Support Vector Machine': 'SVM'
        }
        algo = self.config.get('algo', 'K-Nearest Neighbors')
        return model_mappings[algo]

    def get_module(self):
        return self.config.get('fsr_module')

    def get_verdict(self):
        return self.config.get('verdict')

    def get_config_id(self):
        return self.config.get('config_id')

    def get_feature_set(self):
        return self.config.get('feature_set')

    def get_train_size(self):
        if not self.config.get('train_size'):
            train_size = 100000
        else:
            train_size = self.config.get('train_size')
        return train_size

    def get_module_data_translated(self):
        return self.config.get('module_data_translated')

    def get_date_filter(self):
        if not self.config.get('date_range') == 'Custom':
            filters = _set_date_filters(self.config.get('date_range'))
        else:
            filters = _set_date_filters('Custom', self.config.get('custom_value'))
        return filters

    def start_listener(self):
        return start_socket_server(self.get_port())

    def stop_listener(self):
        return stop_socket_server(self.get_port())

    def translate_config_display_fields(self):
        module_translated = _get_module_type(self.get_module())
        verdicts_translated = _map_module_fields(module_translated, self.get_verdict())
        features_translated = _map_module_fields(module_translated, self.get_feature_set())
        filters_translated = {
            'logic': 'AND',
            'filters': self.get_date_filter(),
            '__selectFields': list(set(verdicts_translated + features_translated))
        }
        module_data_translated = {'module': module_translated,
                                  'verdicts': verdicts_translated,
                                  'features': features_translated,
                                  'filters_translated': filters_translated
                                  }
        self.config['module_data_translated'] = module_data_translated
        update_connnector_config(connector_name='fortisoar-ml-engine', version=None, updated_config=self.config,
                                 configId=self.get_config_id(), agent=None)

    def _get_filters(self):
        verdicts_translated = self.get_verdicts_translated()
        features_translated = self.get_features_translated()
        select_fields = list(set(verdicts_translated + features_translated))
        if 'uuid' not in select_fields:
            select_fields.append('uuid')
        return {
            'logic': 'AND',
            'filters': self.get_date_filter(),
            '__selectFields': select_fields
        }

    def mark_stale(self):
        return send_socket_message(self.get_port(), '--stale --configid {}'.format(self.get_config_id()))

    def get_module_translated(self):
        return self.config.get('module_data_translated', {}).get('module')

    def get_verdicts_translated(self):
        return self.config.get('module_data_translated', {}).get('verdicts')

    def get_features_translated(self):
        return self.config.get('module_data_translated', {}).get('features')

    def get_filters_translated(self):
        return self.config.get('module_data_translated', {}).get('filters_translated')

    def load_model(self):
        start_socket_server(self.get_port())
        try:
            return send_socket_message(self.get_port(), '--load_model --configid {}'.format(self.get_config_id()))
        except Exception as err:
            logger.error(err)
            raise ConnectorError(err)

    def delete_model(self):
        try:
            return send_socket_message(self.get_port(), '--delete_model --configid {}'.format(self.get_config_id()))
        except Exception as err:
            logger.error(err)
            raise ConnectorError(err)

    def train(self):
        try:
            logger.info('self.config: %s', self.config)
            return send_socket_message(self.get_port(), '--train --configid {} --algo "{}" --module {} '
                                                        '--filter {} --train_size {} --features {} --verdicts {}'
                                       .format(
                self.get_config_id(), self.get_algo(), self.get_module_translated(),
                json.dumps(self._get_filters()).encode('utf-8'),
                self.get_train_size(),
                json.dumps(self.get_features_translated()).encode('utf-8'),
                json.dumps(self.get_verdicts_translated()).encode('utf-8')))
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    # for verdict prediction
    def predict(self, records, predict_action):
        try:
            response = send_socket_message(self.get_port(), '--predict --predict_action {} --configid {} '
                                                            '--records {} --module {} '
                                                            '--features {} --verdicts {}'
                                           .format(predict_action, self.get_config_id(),
                                                   json.dumps(json.dumps(records)),
                                                   self.get_module_translated(),
                                                   json.dumps(self.get_features_translated()).encode('utf-8'),
                                                   json.dumps(self.get_verdicts_translated()).encode('utf-8')))
            response_json = json.loads(response.decode('utf-8'))
            if int(response_json.get('status')) != 0:
                raise ConnectorError(response_json.get('message'))
            else:
                return response_json.get('message')
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    # for similar record
    def similar(self, records):
        try:
            response = send_socket_message(self.get_port(), '--similar --configid {} '
                                                            '--records {} --module {} '
                                                            '--features {} --verdicts {}'
                                           .format(self.get_config_id(), records, self.get_module_translated(),
                                                   json.dumps(self.get_features_translated()).encode('utf-8'),
                                                   json.dumps(self.get_verdicts_translated()).encode('utf-8')))
            response_json = json.loads(response.decode('utf-8'))
            if int(response_json.get('status')) != 0:
                raise ConnectorError(response_json.get('message'))
            else:
                return response_json.get('message')
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_listener_health(self):
        return send_socket_message(self.get_port(), '--check --configid {}'.format(self.get_config_id()))

    def update_module_config_map(self):

        return send_socket_message(self.get_port(),
                                   '--update_config_map --module {} --configid {}'.format(self.get_module_translated(),
                                                                                          self.get_config_id()))
