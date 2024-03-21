""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import os
import re
import sys
import socket
import argparse
import json
import joblib
import logging
import pandas
import numpy
import time
import shlex
from os import path
from struct import unpack
from collections import defaultdict
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MultiLabelBinarizer

sys.path.append(path.abspath('/opt/cyops-integrations/integrations'))

from integrations.crudhub import make_request

LOG_DIR_PATH = '/var/log/cyops/cyops-integrations/ml-engine/'
LOG_FILE_PATH = path.join(LOG_DIR_PATH, 'ml_server.log')
os.makedirs(LOG_DIR_PATH, exist_ok=True)
INTEGRATIONS_WORKSPACE = '/opt/cyops/configs/integrations/workspace'
TRAINING_DIR_PATH = '/opt/cyops-integrations/integrations/.training'
if os.path.exists(INTEGRATIONS_WORKSPACE):
    TRAINING_DIR_PATH = INTEGRATIONS_WORKSPACE + '/ml-engine/'
os.makedirs(TRAINING_DIR_PATH, exist_ok=True)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
handler = logging.FileHandler(LOG_FILE_PATH)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)

trained_dataset = {}
module_config_map = defaultdict(list)
MAX_LENGTH = 102400
SERVER_HOST = 'localhost'

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def health_check(config_id):
    global trained_dataset
    if trained_dataset.get(config_id):
        if trained_dataset.get(config_id).get('stale'):
            message = 'The configuration was updated after the last training run. New changes will only reflect after the next training. ' \
                      'Any predict action run while this message is visible will be applied on the old training model.'
            status = -1
        else:
            message = 'Trained dataset available for the specified configuration'
            status = 0
    else:
        message = 'Trained dataset not available for the specified configuration. ' \
                  'If this is the initial configuration, this error will disappear upon running the train action.'
        status = -1

    return status, message


def mark_stale(config_id):
    global trained_dataset
    if trained_dataset.get(config_id, {}):
        trained_dataset[config_id]['stale'] = True
    return 0, "Model for config {} is marked stale".format(config_id)


def load_model(config_id):
    global trained_dataset
    data_loaded = load_model_file(config_id)
    if data_loaded:
        message = 'Trained dataset loaded for the specified config'
        status = 0
    else:
        message = 'Trained dataset not found for the specified config'
        status = -1
    logger.info(message)
    return status, message


def delete_model(config_id):
    global trained_dataset
    dir_loc = TRAINING_DIR_PATH
    model_filename = 'model_{}.sav'.format(config_id)
    path = os.path.join(dir_loc, model_filename)
    try:
        os.remove(path)
        logger.info("Removed model file: {}".format(model_filename))
    except FileNotFoundError:
        pass
    trained_dataset.pop(config_id, None)
    # remove config from config map
    update_config(configid=config_id, action='delete')
    if len(trained_dataset.keys()) == 0:
        logger.info("No active config found. Shutting down server...")
        sys.exit()

    return 0, "Config {0} is deleted".format(config_id)


def load_model_file(config_id):
    global trained_dataset
    dir_loc = TRAINING_DIR_PATH
    model_filename = 'model_{}.sav'.format(config_id)
    path = os.path.join(dir_loc, model_filename)
    try:
        trained_dataset[config_id] = joblib.load(path)
        return True
    except FileNotFoundError:
        logger.error('No model file found for config id %s', config_id)
    return False


def update_config(configid, module=None, action='add'):
    global module_config_map
    logger.info('updating config in config map for module: %s configid: %s', module, configid)
    if action == 'add':
        if configid not in module_config_map[module]:
            module_config_map[module].append(configid)
    if action == 'delete':
        for k, v in module_config_map.items():
            if configid in v:
                v.remove(configid)
                break
    return 0, 'Config id successfully updated in module config map'


def _preprocess_text_util(text):
    text = text.lower()
    # remove html markup
    text = re.sub('(<.*?>)', '', text)
    # remove non-ascii and digits
    text = re.sub('(\\W|\\d)', ' ', text)
    # remove whitespace
    text = text.strip()
    return text


def format_message_util(message, *args, **kwargs):
    if message.startswith('b[') or message.startswith('b{'):
        message = message[1:]
    if type(message) == dict or isinstance(message, list):
        return json.loads(json.dumps(message))
    try:
        message_json = json.loads(bytes.decode(message))
    except Exception as e:
        try:
            message_json = json.loads(message)
        except Exception as e:
            message_json = message
    return message_json


def map_field_types(module, feature_list, verdict_list):
    try:
        url = '/api/3/attrib_model_metadatas?sattrib.type={}&$limit=500'.format(module)
        attributes = make_request(url, 'GET', verify=False)['hydra:member']
    except Exception as err:
        raise Exception(err)

    _unsupported_type = ['date', 'decimal', 'file', 'password']
    field_type_mappings = {
        'checkbox': 'categorical',
        'email': 'categorical',
        'integer': 'categorical',
        'ipv4': 'categorical',
        'ipv6': 'categorical',
        'url': 'categorical',
        'filehash': 'categorical',
        'decimal': 'categorical',
        'lookup': 'categorical',
        'manyToMany': 'multiLabelBinariser',
        'multiselectpicklist': 'multiLabelBinariser',
        'object': 'tfidf',
        'oneToMany': 'categorical',
        'phone': 'categorical',
        'picklist': 'multiLabelBinariser',
        'richtext': 'tfidf',
        'text': 'tfidf',
        'textarea': 'tfidf'
    }

    featuremap = {'multiLabelBinariser': [], 'categorical': [], 'tfidf': []}
    verdictmap = {'multiLabelBinariser': [], 'categorical': [], 'tfidf': []}
    unsupported_fields = []
    for field in attributes:
        field_name = field['name']
        if field_name in feature_list or field_name in verdict_list:
            form_type = field['formType']
            if field_type_mappings.get(form_type) == 'tfidf':
                featuremap['tfidf'].append(field_name)
            elif field_type_mappings.get(form_type) == 'multiLabelBinariser':
                if field['name'] in feature_list:
                    featuremap['multiLabelBinariser'].append(field_name)
                if field['name'] in verdict_list:
                    verdictmap['multiLabelBinariser'].append(field_name)
            elif field_type_mappings.get(form_type) == 'categorical':
                if field_name in feature_list:
                    featuremap['categorical'].append(field_name)
                if field_name in verdict_list:
                    verdictmap['categorical'].append(field_name)
            else:
                logger.info('Unsupported field type')
                unsupported_fields.append(field_name)

    return featuremap, verdictmap


def create_dataframe(record_list, feature_fields, featuremap, verdictmap, tfidfvectorizer=None):
    train_df = defaultdict(list)
    verdict_df = defaultdict(list)
    featurelist_multiple_label_binarizer = featuremap.get('multiLabelBinariser', [])
    verdictlist_multiple_label_binarizer = verdictmap.get('multiLabelBinariser', [])
    featurelist_text = featuremap.get('tfidf', [])
    featurelist_categorical = featuremap.get('categorical', [])
    verdictlist_categorical = verdictmap.get('categorical', [])

    feature_fields = list(set(featurelist_multiple_label_binarizer + featurelist_text + featurelist_categorical))
    verdict_fields = list(set(verdictlist_multiple_label_binarizer + verdictlist_categorical))
    index = []
    for idx, train_data in enumerate(record_list):
        uuid = train_data.pop('uuid', None)
        if uuid:
            index.append(uuid)
        else:
            index.append(idx)
        for key in feature_fields:
            value = train_data.get(key)
            if not value: value = 'N/A'
            if key in featurelist_multiple_label_binarizer:
                if not isinstance(value, list): value = [value]
            train_df[key].append(value)

        for key in verdict_fields:
            value = train_data.get(key)
            if not value: value = 'N/A'
            if key in verdictlist_multiple_label_binarizer:
                if not isinstance(value, list): value = [value]
            verdict_df[key].append(value)

    train_df = pandas.DataFrame(train_df, index=index)
    verdict_df = pandas.DataFrame(verdict_df, index=index)

    # Dataframe for M2M field using multiple label binariser
    for key in featurelist_multiple_label_binarizer:
        if key in train_df:
            dummy_df = multiple_label_binariser(train_df, key, index)
            train_df = pandas.concat([train_df, dummy_df], axis=1, )

    for key in verdictlist_multiple_label_binarizer:
        if key in verdict_df:
            dummy_df = multiple_label_binariser(verdict_df, key, index)
            verdict_df = pandas.concat([verdict_df, dummy_df], axis=1, )

    # Dataframe for text field using tfidf vectoriser
    if featurelist_text:
        dummy_df, tfidfvectorizer = tfidf_vectoriser(train_df, featurelist_text, index, tfidfvectorizer)
        train_df = pandas.concat([train_df, dummy_df], axis=1)

    # label encoding for categorical type
    for key in featurelist_categorical:
        if key in train_df:
            dummy_df = categorical_encoding(train_df, key, index)
            train_df = pandas.concat([train_df, dummy_df], axis=1)

    for key in verdictlist_categorical:
        if key in verdict_df:
            dummy_df = categorical_encoding(verdict_df, key, index)
            verdict_df = pandas.concat([verdict_df, dummy_df], axis=1)
    return train_df, verdict_df, tfidfvectorizer


def multiple_label_binariser(df, key, index):
    mlb = MultiLabelBinarizer()
    dummy_df = pandas.DataFrame(mlb.fit_transform(df.pop(key)), index=index, columns=mlb.classes_)
    dummy_df = dummy_df.add_prefix(key + '_')
    return dummy_df


def tfidf_vectoriser(df, keys, index, tfidfvectorizer=None):
    for key in keys:
        df[key] = df[key].apply(lambda x: _preprocess_text_util(x))
    df['feature_text'] = df[keys].agg(' '.join, axis=1)
    for key in keys: df.pop(key)
    if tfidfvectorizer:
        tf = tfidfvectorizer.transform(df.pop('feature_text'))
    else:
        tfidfvectorizer = TfidfVectorizer(stop_words='english', max_features=200 * len(keys))
        tf = tfidfvectorizer.fit_transform(df.pop('feature_text'))
    try:
        dummy_df = pandas.DataFrame(tf.toarray(), index=index, columns=tfidfvectorizer.get_feature_names())
    except:
        dummy_df = pandas.DataFrame()
    return dummy_df, tfidfvectorizer


def categorical_encoding(df, key, index):
    dummy_df = pandas.get_dummies(df.pop(key), prefix=key)
    return dummy_df


def train(config_id, algo_name, module, filter_body, train_size, feature_list, verdict_list):
    try:
        filter_body = format_message_util(filter_body)
        feature_list = format_message_util(feature_list)
        verdict_list = format_message_util(verdict_list)
        update_config(config_id, module)
        try:
            response = []
            max_limit = 5000
            for start_index in range(0, train_size, max_limit):
                page = start_index // max_limit + 1
                limit = train_size if train_size <= max_limit else max_limit
                train_size = train_size - limit
                url = '/api/query/{}?$limit={}&$relationships=true&$export=true&$page={}'.format(module, limit, page)
                res = make_request(url, 'POST', body=filter_body, verify=False)['hydra:member']
                response.extend(res)
            if not response:
                return -1, 'Failure! No record found for training'
        except Exception as err:
            raise Exception('{}: {}'.format(err, 'Please verify that the module is accessible.'))
        logger.debug('length of response: %s', len(response))
        featuremap, verdictmap = map_field_types(module, feature_list, verdict_list)
        train_df, verdict_df, tfidfvectorizer = create_dataframe(response, feature_list, featuremap, verdictmap)
        models = {
            'LR': LogisticRegression(solver='liblinear', multi_class='ovr'),
            'LDA': LinearDiscriminantAnalysis(),
            'KNN': KNeighborsClassifier(),
            'CART': DecisionTreeClassifier(),
            'NB': GaussianNB(),
            'SVM': SVC(gamma='auto')
        }

        classifier = models.get(algo_name, 'KNN')
        try:
            classifier.fit(train_df, verdict_df)
        except ValueError as e:
            raise Exception('The feature(s) set data resulted in an invalid/null value. '
                            'Please check the data of features selected, at least one feature should have some data.')

        model_file_content = {'model': classifier, 'featuremap': featuremap, 'verdictmap': verdictmap,
                              'train_columns': train_df.columns, 'verdict_columns': verdict_df.columns,
                              'train_index': train_df.index, 'median': train_df.median(), 'tfidfvectorizer': tfidfvectorizer
                              }
        model_file_name = os.path.join(TRAINING_DIR_PATH, 'model_{}.sav'.format(config_id))
        joblib.dump(model_file_content, model_file_name)
        logger.info('Saved model file as {}'.format(model_file_name))
        trained_dataset[config_id] = model_file_content
        trained_dataset[config_id]['stale'] = False
        return 0, 'Success. Saved as {}'.format(model_file_name)
    except Exception as e:
        logger.exception('Training failed with error:%', str(e))
        raise e


def predict(config_id, records, module, features, verdicts, action='verdict'):
    global module_config_map
    if module_config_map.get('module') and config_id not in module_config_map.get('module', []):
        config_id = module_config_map[module][0]
    records = format_message_util(records)
    features = format_message_util(features)
    verdicts = format_message_util(verdicts)
    if records and not isinstance(records, list): records = [records]

    try:
        global trained_dataset
        if config_id not in trained_dataset:
            logger.info('Trained data set for config id %s was not loaded , loading', config_id)
            load_model(config_id)
        if config_id not in trained_dataset:
            return -1, 'Trained dataset not available for the selected configuration.'

        transformed_prediction = []

        update_record_request = False
        if records and isinstance(records[0], dict) and not records[0].get('@id'):
            # This is create record request
            records_iri = []
        elif records and isinstance(records[0], dict) and records[0].get('@id'):
            # This is update record request
            records_iri = [record.get('@id') for record in records]
            update_record_request = True
        else:
            records_iri = records

        if records_iri:
            filter_dict = {'logic': 'OR', 'filters': []}
            for record in records_iri:
                filter_dict['filters'].append({'operator': 'eq', 'field': 'uuid', 'value': record.split('/')[-1]})
            url = '/api/query/{0}?$relationships=true&$export=true&__selectFields={1}&$limit={2}'.format(module,
                                                                                                         ','.join(
                                                                                                             features),
                                                                                                         len(records))
            resp = make_request(url, 'POST', body=filter_dict, verify=False)['hydra:member']

            if update_record_request:
                records = [{**u, **v} for u, v in zip(resp, records)]
            else:
                records = resp
        if not records:
            raise Exception('The record with @id {0} does not exist.'.format(records))

        trained_dataset_for_config = trained_dataset[config_id]
        featuremap = trained_dataset_for_config.get('featuremap')
        train_columns = trained_dataset_for_config.get('train_columns')
        verdict_columns = trained_dataset_for_config.get('verdict_columns')
        median = trained_dataset_for_config.get('median')
        tfidfvectorizer = trained_dataset_for_config.get('tfidfvectorizer')
        train_df= pandas.DataFrame(columns=train_columns)
        predict_x, predict_y, _ = create_dataframe(records, features, featuremap, {}, tfidfvectorizer)
        cols_to_pop = predict_x.columns.difference(train_columns)
        [predict_x.pop(col) for col in cols_to_pop]
        predict_x = pandas.concat([train_df, predict_x], axis=0)
        model = trained_dataset_for_config['model']
        [predict_x[col].fillna(0, inplace=True) for col in predict_x if '_' in col]
        if action == 'verdict':
            return get_verdict(model, predict_x, verdict_columns)

        elif action == 'similar':
            return get_similar_records(model, predict_x, trained_dataset_for_config['train_index'])

    except Exception as e:
        logger.exception('Predict failed with error')
        return -1, str(e)


def get_verdict(model, predict_x, verdict_columns):
    prediction = model.predict(predict_x)
    predict_indexes = predict_x.index.tolist()
    transformed_prediction = []
    for value, uuid in zip(prediction, predict_indexes):
        # transformed_prediction_record = {'uuid': uuid}
        transformed_prediction_record = {}
        positions = numpy.where(value == 1)[0]
        for position in positions:
            value = verdict_columns[position]
            value = value.split('_')
            relation_name = value[0]
            relation_value = value[1] if value[1] != 'N/A' else None
            if relation_name not in transformed_prediction_record:
                transformed_prediction_record[relation_name] = relation_value
            else:
                transformed_prediction_record[relation_name] = [transformed_prediction_record[relation_name],
                                                                relation_value]
        transformed_prediction.append(transformed_prediction_record)
    return 0, transformed_prediction


def get_similar_records(model, predict_x, index):
    similar_records_index = model.kneighbors(predict_x, n_neighbors=6, return_distance=False)
    similar_records_uuids = [index[record] for record in similar_records_index]
    if similar_records_uuids:
        similar_records_uuids = similar_records_uuids[0].values.tolist()
        for uuid in predict_x.index.tolist():
            if uuid in similar_records_uuids:
                similar_records_uuids.remove(uuid)
    return 0, similar_records_uuids




def handle(client_socket):
    message = {}
    BUFF_SIZE = 4096
    payload_bytes = b''
    bs = client_socket.recv(8)
    (length,) = unpack('>Q', bs)
    while len(payload_bytes) < length:
        to_read = length - len(payload_bytes)
        payload_bytes += client_socket.recv(BUFF_SIZE if to_read > BUFF_SIZE else to_read)

    if payload_bytes:
        payload = payload_bytes.decode()
        parser = argparse.ArgumentParser(description='ML Engine Server')
        parser.add_argument('--load_model', help='Load Trained Dataset for Configuration', action='store_true',
                            default=False, required=False)
        parser.add_argument('--delete_model', help='Delete Trained Dataset for Configuration', action='store_true',
                            default=False, required=False)
        parser.add_argument('--check', help='Check Health', action='store_true', default=False, required=False)
        parser.add_argument('--train', help='Train the ML component with existing records in the system',
                            action='store_true', default=False, required=False)
        parser.add_argument('--predict', help='Predicts the selected fields for a given record', action='store_true',
                            default=False, required=False)
        parser.add_argument('--similar', help='Predicts the similar records  for a given record', action='store_true',
                            default=False, required=False)
        parser.add_argument('--predict_action', help='Predict verdict/similarity record(s)', required=False, type=str)
        parser.add_argument('--update_config_map', help='Prepare module and config map', action='store_true',
                            default=False, required=False)
        parser.add_argument('--records', help='Record to be predicted', required=False, type=str)
        parser.add_argument('--verdicts', help='Fields to be predicted', required=False, type=str)
        parser.add_argument('--features', help='Selected feature set', required=False, type=str)
        parser.add_argument('--filter', help='Body dict of the API request', required=False, type=str)
        parser.add_argument('--algo', help='ML algorithm that will be used during prediction', required=False)
        parser.add_argument('--configid', help='The ID of the connector configuration', required=False)
        parser.add_argument('--module', help='Selected module in config', required=False)
        parser.add_argument('--train_size', help='Size of the training set', required=False)
        parser.add_argument('--exit', help='Stop Server', action='store_true', default=False, required=False)
        parser.add_argument('--stale', help='Mark old model file as stale', action='store_true', default=False,
                            required=False)
        status = -1
        args_parsed = False
        try:
            args = parser.parse_args(shlex.split(payload))
            args_parsed = True
        except SystemExit as se:
            message = se
            logger.exception(se)
        except ValueError:
            error = 'The payload is too large for the server'
            logger.exception(error)
            status, message = -1, error
        if args_parsed:
            try:
                if not args.exit:
                    if not args.configid:
                        raise Exception("configid is a mandatory argument")
                if args.check:
                    status, message = health_check(args.configid)
                elif args.load_model:
                    status, message = load_model(args.configid)
                elif args.predict:
                    if not args.records:
                        raise Exception("record id is a mandatory argument")
                    if not args.module:
                        raise Exception("module is a mandatory argument")
                    if not args.features:
                        raise Exception("features is a mandatory argument")
                    if not args.verdicts:
                        raise Exception("verdicts is a mandatory argument")
                    status, message = predict(args.configid, args.records, args.module, args.features, args.verdicts,
                                              args.predict_action)
                elif args.similar:
                    status, message = get_similar_records(args.configid, args.records, args.module)
                elif args.train:
                    if not args.algo:
                        raise Exception("algo is a mandatory argument")
                    if not args.module:
                        raise Exception("module is a mandatory argument")
                    if not args.filter:
                        raise Exception("filter is a mandatory argument")
                    if not args.features:
                        raise Exception("features is a mandatory argument")
                    if not args.verdicts:
                        raise Exception("verdicts is a mandatory argument")
                    status, message = train(args.configid, args.algo, args.module, args.filter,
                                            int(args.train_size), args.features, args.verdicts)
                elif args.delete_model:
                    status, message = delete_model(args.configid)
                elif args.stale:
                    status, message = mark_stale(args.configid)
                elif args.update_config_map:
                    status, message = update_config(args.configid, args.module)
                else:
                    raise Exception("Unsupported function")
            except Exception as err:
                logger.exception(err)
                message = str(err)

        client_socket.sendall(json.dumps({'status': status, 'message': message}).encode('utf-8'))
        client_socket.close()

        if args.exit:
            logger.info("Server is shutting down")
            serversocket.close()
            sys.exit()


try:
    PORT = int(sys.argv[1])
    serversocket.bind((SERVER_HOST, PORT))
    logger.info("Server bind for IP: {}, Port: {}".format(SERVER_HOST, PORT))
except socket.error as msg:
    logger.exception("Bind failed: {}".format(msg))
    sys.exit()

logger.info("Server is listening")
serversocket.listen(5)

while True:
    (client, address) = serversocket.accept()
    logger.info("**** {0} ****".format(client))
    handle(client)

