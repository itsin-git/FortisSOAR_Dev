import sys
import pandas
from os import path

from ml_utils.constants import PHISHING_LABEL, NON_PHISHING_LABEL


# Include integrations path to retrieve records directly using make_request call. Adding this support will enable
# installation of connector on Agent
sys.path.append(path.abspath('/opt/cyops-integrations/integrations'))
from integrations.crudhub import make_request

from ml_utils import log
logger = log.get_logger(__name__)


def retrieve_data_from_fsr(module, filter_criteria, train_size):
    records = []
    max_limit = 5000
    for start_index in range(0, train_size, max_limit):
        page = start_index // max_limit + 1
        limit = train_size if train_size <= max_limit else max_limit
        train_size = train_size - limit
        url = 'https://localhost/api/query/{}?$limit={}&$export=true&$page={}'.format(module, limit, page)
        res = make_request(url, 'POST', body=filter_criteria, verify=False)['hydra:member']
        records.extend(res)
    return records


def create_dataframe_from_train_data(records, feature_mapping, verdict_field, verdict_mapping):
    # Based on verdict field mapping, some records may not fit in any of phishing or non-phishing classification, hence
    # those records need to be dropped from training data
    final_training_records = []
    phishing_values = verdict_mapping['phishing']
    non_phishing_values = verdict_mapping['non_phishing']
    for record in records:
        training_record = {}
        verdict_field_value = record.get(verdict_field)
        if verdict_field_value in phishing_values:
            # 1 represents phishing and 0 represents non-phishing
            training_record['ml_label'] = PHISHING_LABEL
        elif verdict_field_value in non_phishing_values:
            training_record['ml_label'] = NON_PHISHING_LABEL
        else:
            continue
        if not record[feature_mapping["body"]]:
            continue
        training_record["from"] = record[feature_mapping["from"]]
        training_record["subject"] = record[feature_mapping["subject"]]
        training_record["body"] = record[feature_mapping["body"]]
        final_training_records.append(training_record)

    df = pandas.DataFrame(final_training_records)
    return df


def create_dataframe_from_predict_data(record, feature_mapping):
    # Body is required parameter
    if not record.get(feature_mapping['body']):
        raise Exception(
            "Mandatory field \"body\" not present in the record")
    predict_data = {'from': record.get(feature_mapping['from']), 'subject': record.get(feature_mapping['subject']),
                    'body': record.get(feature_mapping['body'])}
    df = pandas.DataFrame.from_records([predict_data])
    return df
