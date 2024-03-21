from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn import metrics

from ml_utils.util import timeit
from models.PredictionResult import PredictionResult
from models.TrainingResult import TrainingResult
from ml_models.ml_model import MlModel

from ml_utils import log
from ml_utils.constants import LABELS,VERDICT

logger = log.get_logger(__name__)


class NaiveBaiye(MlModel):
    def __init__(self, model=None):
        if model:
            self.model = model
        else:
            self.model = MultinomialNB()

    @timeit
    def train(self, X, y):
        logger.debug("Model training started")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        self.model.fit(X_train, y_train.values.ravel())
        y_predict_test = self.model.predict(X_test)
        conf_matrix = metrics.confusion_matrix(y_test.values.ravel(), y_predict_test, labels=LABELS)
        classification_report = metrics.classification_report(y_test.values.ravel(), y_predict_test, labels=LABELS,
                                                              output_dict=True)

        accuracy = metrics.accuracy_score(y_test, y_predict_test)
        recall = metrics.recall_score(y_test, y_predict_test)
        precision = metrics.precision_score(y_test, y_predict_test)
        f1_score = metrics.f1_score(y_test, y_predict_test)
        training_result = TrainingResult(status="success", message="success", confusion_matrix=conf_matrix.tolist(),
                                         classification_report=classification_report, accuracy=accuracy, recall=recall,
                                         precision=precision, f1_score=f1_score, training_size=len(X.index),
                                         num_features = len(X.columns))
        logger.debug("model training completed")
        return training_result, self.model

    def predict(self, X_test):
        logger.debug("Ml model predict operation called")
        y_pred_prob = self.model.predict_proba(X_test)
        ix = y_pred_prob.argmax(1).item()
        prediction_result = PredictionResult("success", message="success", verdict=VERDICT[ix], label=ix , confidence=y_pred_prob[0,ix])
        return prediction_result
