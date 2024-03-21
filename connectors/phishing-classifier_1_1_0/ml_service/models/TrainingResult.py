class TrainingResult:
    def __init__(self, status, message=None, confusion_matrix=None, classification_report=None,
                 accuracy=None, recall=None, precision=None, f1_score=None, training_size=0, num_features=0):
        self.status = status
        self.message = message
        self.confusion_matrix = confusion_matrix
        self.classification_report = classification_report
        self.accuracy = accuracy
        self.recall = recall
        self.precision = precision
        self.f1_score = f1_score
        self.training_size = training_size
        self.num_features = num_features
