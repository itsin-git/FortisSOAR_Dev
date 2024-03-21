class PredictionResult:
    def __init__(self, status, message=None, label=None, confidence=None, verdict=None):
        self.status = status
        self.message = message
        self.label = label
        self.confidence = confidence
        self.verdict = verdict
