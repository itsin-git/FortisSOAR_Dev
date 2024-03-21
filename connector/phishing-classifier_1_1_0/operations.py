""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json
import ast

from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.crudhub import make_cyops_request
from connectors.models import Configuration

from .constants import LOGGER_NAME, DATA_SOURCE, FSR_MODULE_DATA_SOURCE
from .util import get_module_type_from_name
from .ml_service_client import MLServiceClient
from integrations.crudhub import make_request

logger = get_logger(LOGGER_NAME)


def is_iri(string):
    if string.startswith('/api/3'):
        return True
    return False


def _retrieve_record(uuid, module):
    if is_iri(uuid):
        iri = uuid
    elif not module:
        raise ConnectorError("Invalid IRI")
    else:
        iri = f"/api/3/{module}/{uuid}"
    resp = make_request(iri, 'GET', verify=False)
    return resp


def get_verdict_set(config, params):
    module_type = params.get('fsr_module')

    verdict_set = []

    response = make_cyops_request('/api/3/model_metadatas?type={}&$relationships=true'.format(module_type), 'GET')[
        'hydra:member']

    for field in response[0]['attributes']:
        if field['formType'] in ['picklist', 'lookup', 'multiselectpicklist']:
            verdict_set.append(field['descriptions']['singular'])

    verdict_set.sort()
    return verdict_set


def get_modules(config, params):

    # TODO: Change this when CH system modules filter is implemented
    system_modules = ['agents', 'appliances', 'people', 'routers', 'tenants']

    module_names = []
    response = make_cyops_request('/api/3/staging_model_metadatas?$limit=100', 'GET')['hydra:member']
    for module in response:
        if module['type'] not in system_modules:
            module_names.append(module['type'])

    module_names.sort()

    return module_names


def predict(config, params):
    record = params.get('record')
    module = params.get('module')

    # The "record" could be an IRI or a json
    if isinstance(record, str) and is_iri(record):
        module = record.split('/')[3]

    # When triggered from recommendation engine, UI sends config as null. That means a default must be specified during
    # configuration otherwise this operation will fail.
    # If the module of configuration(default or explicit) does not match with the module provided as input, then one of
    # the configs for that module is selected as the config.
    if module and config.get(DATA_SOURCE) == FSR_MODULE_DATA_SOURCE:
        config_id = config.get('config_id')
        connector = Configuration.objects.get(config_id=config_id).connector
        all_config_obj = Configuration.objects.filter(connector=connector)
        all_configs_for_given_module = [obj for obj in all_config_obj if obj.config.get('fsr_module', '').lower() == module]

        matched = False
        for conf in all_configs_for_given_module:
            if conf.config_id == config_id:
                matched = True
                break
        if matched:
            pass
        elif not matched:
            config = all_configs_for_given_module[0].config
            config_id = all_configs_for_given_module[0].config_id
            config.update({'config_id': config_id})
        else:
            raise ConnectorError('No config exist for module: %s', module)

    if not record:
        raise ConnectorError('No record to predict.')
    try:
        record = json.loads(record)
    except:
        try:
            record = ast.literal_eval(record)
        except:
            pass

    # Retrieve record if the input record is an iri or uuid
    if not isinstance(record, dict):
        # Retrieve only if the input record is an iri or it is uuid provided module is supplied
        if is_iri(record) or module is not None:
            record = _retrieve_record(record, module)
        # Text based prediction
        elif isinstance(record, str):
            # Convert to the required format
            record = {"emailBody": record}
            params['is_json'] = True
    else:
        # When direct json is sent for prediction, it must be in a specific format i.e.
        # { "emailFrom": "<emailFrom>", "emailSubject": "<emailSubject>", "emailBody": "<emailBody>" }
        params['is_json'] = True
    return MLServiceClient(config).predict(config, params, record)


def get_training_results(config, params):
    return MLServiceClient(config).get_training_results(config, params)


def train(config, params):
    return MLServiceClient(config).train(config, params)


operations = {
    'predict': predict,
    'train': train,
    'get_training_results': get_training_results,
    'get_modules': get_modules,
    'get_verdict_set': get_verdict_set
}
