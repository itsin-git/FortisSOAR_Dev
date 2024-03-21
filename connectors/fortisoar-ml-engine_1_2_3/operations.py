""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json
import ast

from connectors.cyops_utilities.crudhub import make_cyops_request
from connectors.core.connector import get_logger, ConnectorError
from .client import ConfigHandler
from connectors.models import Configuration

logger = get_logger('fortisoar-ml-engine')


def predict(config, params, predict_action='verdict'):
    records = params.get('records')
    module = params.get('fsr_module')

    if not records:
        raise ConnectorError('No record to predict.')
    try:
        records = json.loads(records)
    except:
        try:
            records = ast.literal_eval(records)
        except:
            pass

    if not isinstance(records, list):
        records = [records]

    if module:
        config_id = config.get('config_id')
        connector = Configuration.objects.get(config_id=config_id).connector
        all_config_obj = Configuration.objects.filter(connector=connector)
        module_config = [obj for obj in all_config_obj if obj.config.get('fsr_module', '').lower() == module]

        matched = False
        for conf in module_config:
            if conf.config_id == config_id:
                matched = True
                break
        if matched:
            pass
        elif not matched:
            config = module_config[0].config
            config_id = module_config[0].config_id
            config.update({'config_id': config_id})
        else:
            raise ConnectorError('No config exist for module: %s', module)
    if config.get('algo') == 'Decision Tree' and predict_action == 'similar':
        raise ConnectorError('Similar records with Decision Tree algorithm is not supported')
    return ConfigHandler(config).predict(records, predict_action)


def similar(config, params):
    return predict(config, params, predict_action='similar')


def train(config, params):
    return ConfigHandler(config).train()


def get_modules(config, params):

    # TODO: Change this when CH system modules filter is implemented
    system_modules = ['Agents', 'Appliances', 'People', 'Routers', 'Tenants']

    module_names = []
    response = make_cyops_request('/api/3/modules?$limit=100', 'GET')['hydra:member']
    for module in response:
        if module['name'] not in system_modules:
            module_names.append(module['name'])

    module_names.sort()

    return module_names


def get_feature_set(config, params):
    module_type = _get_module_type(params.get('fsr_module'))

    feature_set = []

    response = make_cyops_request('/api/3/model_metadatas?type={}&$relationships=true'.format(module_type), 'GET')[
        'hydra:member']

    for field in response[0]['attributes']:
        feature_set.append(field['descriptions']['singular'])

    feature_set.sort()

    return feature_set


def get_verdict_set(config, params):
    module_type = _get_module_type(params.get('fsr_module'))

    verdict_set = []

    response = make_cyops_request('/api/3/model_metadatas?type={}&$relationships=true'.format(module_type), 'GET')[
        'hydra:member']

    for field in response[0]['attributes']:
        if field['formType'] in ['picklist', 'lookup', 'multiselectpicklist']:
            verdict_set.append(field['descriptions']['singular'])

    verdict_set.sort()

    return verdict_set


def get_output_schema(config, params):
    output_schema = {}
    for verdict in ConfigHandler(config).get_verdicts_translated():
        output_schema[verdict] = ''
    output_schema['accuracy'] = ''
    return output_schema


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


operations = {
    'predict': predict,
    'similar': similar,
    'train': train,
    'get_modules': get_modules,
    'get_feature_set': get_feature_set,
    'get_verdict_set': get_verdict_set,
    'get_output_schema': get_output_schema
}
