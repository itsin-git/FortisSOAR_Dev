class MlModelEntity:
    def __init__(self, ml_model, vectorizer, training_results, is_stale):
        self.ml_model = ml_model
        self.vectorizer = vectorizer
        self.training_results = training_results
        self.is_stale = is_stale
