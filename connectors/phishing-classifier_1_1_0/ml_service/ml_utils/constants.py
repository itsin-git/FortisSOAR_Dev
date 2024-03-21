WORKSPACE_DIR_OLD = '/opt/cyops-integrations/integrations/workspace'
WORKSPACE_DIR = '/opt/cyops/configs/integrations/workspace'
TRAINED_MODEL_FILE_NAME = 'model.sav'

MODULE="fsr_module"
FILTER="filter"
VERDICT_FIELD = "verdict_field"
FEATURE_MAPPING = "feature_mapping"
VERDICT_FIELD_VALUE_MAPPING = "verdict_field_value_mapping"
DATE_RANGE = "date_range"
TRAINING_DATA_SIZE = "train_size"
DATA_SOURCE = "type_of_training_data"

PRE_TRAINED_DATA_SOURCE = "Pre-Trained"
FSR_MODULE_DATA_SOURCE = "FortiSOAR Module"

PHISHING_LABEL = 1
NON_PHISHING_LABEL = 0
LABELS = [PHISHING_LABEL, NON_PHISHING_LABEL]

PHISHING = "Phishing"
NON_PHISHING = "Non-Phishing"

VERDICT = [NON_PHISHING, PHISHING]

STEM = 'stem'
LEMMATIZE = 'lemmatize'
