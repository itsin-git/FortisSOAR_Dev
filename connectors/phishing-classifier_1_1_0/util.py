import configparser
import json
import os
from pathlib import Path

import arrow

from connectors.core.connector import get_logger
from connectors.cyops_utilities.crudhub import make_cyops_request


from .constants import MODULE, VERDICT_FIELD, FEATURE_MAPPING, DATE_RANGE,CUSTOM_DAYS, FILTERS, LOGGER_NAME, \
    PRE_TRAINED_DATA_SOURCE, DATA_SOURCE

logger = get_logger(LOGGER_NAME)

DATE_FIELD = 'modifyDate'



def get_module_type_from_name(module_name):
    type_body_dict = {
        'logic': 'OR',
        'filters': [{
            'operator': 'eq',
            'field': 'name',
            'value': module_name}
        ]
    }
    return make_cyops_request('/api/query/modules', 'POST', body=type_body_dict)['hydra:member'][0]['type']


def get_attribute_metadata(module):
    response = make_cyops_request('/api/3/model_metadatas?type={}&$relationships=true'.format(module), 'GET')[
        'hydra:member']

    return response[0]['attributes']
    # mapped_feature_set = []
    #
    # for field in response[0]['attributes']:
    #     if field['descriptions']['singular'] in feature_set:
    #         mapped_feature_set.append(field['name'])
    #
    # return mapped_feature_set


def create_combined_filer(feature_fields, verdict_field, filter_criteria, date_filter):
    select_fields = feature_fields
    select_fields.append(verdict_field)
    if 'uuid' not in select_fields:
        select_fields.append('uuid')

    if filter_criteria:
        filter_criteria.get('filters').append(date_filter)
        filter_criteria['__selectFields'] = select_fields
        return filter_criteria
    else:
        return {
            "logic": "AND",
            "filters": date_filter,
            "__selectFields": select_fields
        }


def translate_config_display_fields(config):
    module_type = config.get(MODULE)    # feature mapping is saved in string format
    feature_mapping = config.get(FEATURE_MAPPING)
    if isinstance(config.get(FEATURE_MAPPING), str):
        feature_mapping = json.loads(config.get(FEATURE_MAPPING))

    # For pre-trained model, only feature_mapping and module_type is needed.
    if config.get(DATA_SOURCE) == PRE_TRAINED_DATA_SOURCE:
        config['module_data_translated'] = {
            'module': module_type,
            'feature_mapping': feature_mapping
        }
        return config
    verdict_field = config.get(VERDICT_FIELD)

    if not config.get(DATE_RANGE) == 'Custom':
        date_filter = convert_date_range_to_date_filter(config.get(DATE_RANGE))
    else:
        date_filter = convert_date_range_to_date_filter('Custom', config.get(CUSTOM_DAYS))

    feature_fields_translated = list(feature_mapping.values())

    filter_criteria = config.get(FILTERS)
    if isinstance(config.get(FILTERS), str):
        filter_criteria = json.loads(config.get(FILTERS))
    filters_translated = create_combined_filer(feature_fields_translated, verdict_field,
                                               filter_criteria, date_filter)

    module_data_translated = {'module': module_type,
                              'verdict': verdict_field,
                              'feature_mapping': feature_mapping,
                              'filter': filters_translated
                              }
    logger.debug(module_data_translated)
    config['module_data_translated'] = module_data_translated
    return config


def convert_date_range_to_date_filter(date_selection, custom_value=0):
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


root_directory = Path(__file__).parent.resolve()
config_file_path = os.path.join(root_directory, 'ml_service','config', 'config.ini')
config = configparser.ConfigParser()
config.read(config_file_path)