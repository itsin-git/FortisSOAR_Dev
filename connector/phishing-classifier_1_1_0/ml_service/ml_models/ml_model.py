import abc


class MlModel(abc.ABC):
    model = None

    @abc.abstractmethod
    def train(self, X_train, y_train):
        """train the ml model"""
        return

    def predict(self, X_test):
        """predict the output"""
        return
