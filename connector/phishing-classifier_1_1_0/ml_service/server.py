import os
import pickle
from pathlib import Path

import pandas as pd
import shutil

from models.PredictionResult import PredictionResult
from models.TrainingResult import TrainingResult
from ml_utils.constants import WORKSPACE_DIR, WORKSPACE_DIR_OLD, TRAINED_MODEL_FILE_NAME, NON_PHISHING, PHISHING, PHISHING_LABEL, \
    PRE_TRAINED_DATA_SOURCE, DATA_SOURCE, FSR_MODULE_DATA_SOURCE
from data_preparation.data_collection import retrieve_data_from_fsr, create_dataframe_from_train_data, create_dataframe_from_predict_data
from feature_engg.feature_extraction import extract_rule_based_features, extract_tfidf_features
from ml_models.naive_baiye import NaiveBaiye
from data_preparation.preprocessing import preprocess_data
from models.MlModelEntity import MlModelEntity
from ml_utils import log
from ml_utils.util import get_fsr_version, version_compare

logger = log.get_logger(__name__)

ml_model_entities = {}


def _get_workspace_dir_for_config(config_id):
    return _get_workspace_dir() + "/" + "connector-phishing-classifier" + "/" + config_id


def _create_workspace():
    # Create workspace dir if it doest not exist for FSR versions >= 7.3.0
    if not os.path.isdir(WORKSPACE_DIR):
        try:
            fsr_version = get_fsr_version()
            result = version_compare("7.3.0", fsr_version)
            if result == 0 or result == 2:
                #Create new workspace directory
                os.makedirs(WORKSPACE_DIR)
        except:
            pass


def _get_workspace_dir():
    if os.path.exists(WORKSPACE_DIR):
        workspace_dir = WORKSPACE_DIR
    else:
        workspace_dir = WORKSPACE_DIR_OLD
    return workspace_dir


def train(payload):
    try:
        logger.debug(f"training payload\n{payload}")
        config = payload.get("config")
        config_id = config.get('config_id')

        workspace_dir = _get_workspace_dir_for_config(config_id)
        os.makedirs(workspace_dir, exist_ok=True)

        data_source = config.get(DATA_SOURCE)
        if data_source == PRE_TRAINED_DATA_SOURCE:
            root_directory = Path(__file__).parent.resolve()
            pre_trained_model_path = os.path.join(root_directory, 'resources', 'model.sav')
            shutil.copy(pre_trained_model_path, workspace_dir)
            # load the pre-trained model
            with open(pre_trained_model_path, 'rb') as model_file:
                ml_model_entity = pickle.load(model_file)
                ml_model_entities[config_id] = ml_model_entity
            return TrainingResult("success")
        train_size = config.get('train_size')
        verdict_mapping = config.get('verdict_field_value_mapping')
        training_config = config.get("module_data_translated")

        module = training_config.get('module')
        filter_criteria = training_config.get('filter')
        feature_mapping = training_config.get('feature_mapping')
        verdict_field = training_config.get('verdict')
        records = retrieve_data_from_fsr(module, filter_criteria, train_size)
        if not records:
            raise Exception("No record available for module")
        else:
            logger.debug("{} records retrieved from FortiSOAR".format(len(records)))
        df = create_dataframe_from_train_data(records, feature_mapping, verdict_field, verdict_mapping)
        if df.empty:
            raise Exception("No record available for training. Either email body is empty for all records or no record fit the verdict mapping")
        else:
            logger.debug("{} records available for training")
        df = preprocess_data(df)
        df['clean_text_tok'] = df['clean_text'].str.split()
        logger.debug("Extracting features")
        df1 = extract_rule_based_features(df)
        df2, vectorizer = extract_tfidf_features(df)
        X = pd.concat([df1, df2], axis=1)
        y = df[['ml_label']]

        naive_baiye_model = NaiveBaiye()
        training_results, trained_model = naive_baiye_model.train(X, y)

        ml_model_entity = MlModelEntity(trained_model, vectorizer, training_results, False)
        ml_model_entity_file_path = workspace_dir + "/" + TRAINED_MODEL_FILE_NAME
        ml_model_entities[config_id] = ml_model_entity

        # Remove all the saved model first
        if os.path.exists(ml_model_entity_file_path):
            os.remove(ml_model_entity_file_path)
        # Save trained model to a file
        with open(ml_model_entity_file_path, 'wb') as model_file:
            pickle.dump(ml_model_entity, model_file)

        return training_results
    except Exception as error:
        logger.exception(error)
        return TrainingResult(status=-1, message=str(error))


def predict(payload):
    try:
        logger.debug(f"predict payload\n{payload}")
        config = payload.get("config")
        config_id = config.get('config_id')

        params = payload.get('params')
        if params and params.get('is_json'):
            feature_mapping = {"from": "emailFrom", "subject": "emailSubject", "body": "emailBody"}
        else:
            training_config = config.get("module_data_translated")
            feature_mapping = training_config.get('feature_mapping')

        workspace_dir = _get_workspace_dir_for_config(config_id)
        ml_model_entity_file_path = os.path.join(workspace_dir, TRAINED_MODEL_FILE_NAME)
        if config_id in ml_model_entities:
            ml_model_entity = ml_model_entities[config_id]
        elif not os.path.exists(ml_model_entity_file_path):
            return PredictionResult(status=-1, message="No trained model present for prediction")
        else:
            with open(ml_model_entity_file_path, 'rb') as model_file:
                ml_model_entity = pickle.load(model_file)
                ml_model_entities[config_id] = ml_model_entity

        if ml_model_entity.is_stale:
            return PredictionResult(status=-1, message="Training data is stale. Retrain the model")

        model = NaiveBaiye(ml_model_entity.ml_model)
        vectorizer = ml_model_entity.vectorizer

        record = payload.get('record')
        df = create_dataframe_from_predict_data(record, feature_mapping)
        df = preprocess_data(df)
        df['clean_text_tok'] = df['clean_text'].str.split()    # print_data_summary(test_df)
        logger.debug("Extracting features from prediction data")
        df1 = extract_rule_based_features(df)
        df2, vectorizer = extract_tfidf_features(df, vectorizer)
        test_df = pd.concat([df1, df2], axis=1)
        prediction_result = model.predict(test_df)
        return prediction_result
    except Exception as error:
        logger.exception(error)
        return PredictionResult(status=-1, message=str(error))


def untrain(payload):
    logger.debug(f"untrain payload\n{payload}")
    config = payload.get("config")
    config_id = config.get('config_id')

    workspace_dir = _get_workspace_dir_for_config(config_id)

    shutil.rmtree(workspace_dir)
    if config_id in ml_model_entities:
        ml_model_entities.pop(config_id)
    logger.debug(f"Removed saved model data for config {config_id}")
    return {"status": 0, "message": "success"}

def cleanup(payload):
    logger.debug(f"cleanup payload\n{payload}")
    ## Placeholder for cleanup code
    return {"status": 0, "message": "success"}


def mark_trained_data_stale(payload):
    logger.debug(f"payload\n{payload}")
    config = payload.get("config")
    config_id = config.get('config_id')

    workspace_dir = _get_workspace_dir_for_config(config_id)
    ml_model_entity_file_path = os.path.join(workspace_dir, TRAINED_MODEL_FILE_NAME)

    if config_id in ml_model_entities:
        ml_model_entity = ml_model_entities[config_id]
        ml_model_entity.is_stale=True
        with open(ml_model_entity_file_path, 'rb') as model_file:
            pickle.dump(ml_model_entity, model_file)
    elif not os.path.exists(ml_model_entity_file_path):
        raise Exception("No trained model present for this configuration")
    else:
        with open(ml_model_entity_file_path, 'rb') as model_file:
            saved_model_entity = pickle.load(model_file)
            saved_model_entity.is_stale = True

        with open(ml_model_entity_file_path, 'wb') as model_file:
            pickle.dump(saved_model_entity, model_file)
    return {"status": 0, "message": "success"}

def get_training_results(payload):
    logger.debug(f"payload\n{payload}")
    config = payload.get("config")
    config_id = config.get('config_id')

    workspace_dir = _get_workspace_dir_for_config(config_id)
    ml_model_entity_file_path = os.path.join(workspace_dir, TRAINED_MODEL_FILE_NAME)
    if config_id in ml_model_entities:
        training_results = ml_model_entities[config_id].training_results
    elif not os.path.exists(ml_model_entity_file_path):
        return TrainingResult(status=-1, message="No trained model present for this configuration")
    else:
        with open(ml_model_entity_file_path, 'rb') as model_file:
            saved_model_entity = pickle.load(model_file)
            training_results = saved_model_entity.training_results
    return training_results

def check_health(payload):
    try:
        logger.debug(f"payload\n{payload}")
        config = payload.get("config")
        config_id = config.get('config_id')
        workspace_dir = _get_workspace_dir_for_config(config_id)
        ml_model_entity_file_path = os.path.join(workspace_dir, TRAINED_MODEL_FILE_NAME)

        if ml_model_entities.get(config_id):
            if ml_model_entities.get(config_id).is_stale:
                message = 'The configuration was updated after the last training run. New changes will only reflect after the next training. ' \
                          'Any predict action run while this message is visible will be applied on the old training model.'
                status = -1
            else:
                message = 'Trained dataset available for the specified configuration'
                status = 0
        elif not os.path.exists(ml_model_entity_file_path):
            message = 'Trained model not available for the specified configuration. ' \
                        'Either train the model, or check the logs for any failures if the training already triggered'
            status = -1
        else:
            with open(ml_model_entity_file_path, 'rb') as model_file:
                saved_model_entity = pickle.load(model_file)
                if saved_model_entity.is_stale:
                    message = 'The configuration was updated after the last training run. New changes will only reflect after the next training. ' \
                              'Any predict action run while this message is visible will be applied on the old training model.'
                    status = -1
                else:
                    message = 'Trained dataset available for the specified configuration'
                    status = 0
        logger.debug("health check successful")
        return {"status": status, "message": message}
    except Exception as error:
        logger.exception(error)
        return {"status": -1, "message": "Error retrieving health status"}

_create_workspace()