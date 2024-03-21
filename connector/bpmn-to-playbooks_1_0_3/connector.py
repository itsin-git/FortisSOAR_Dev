from connectors.core.connector import Connector
from .operations import operations


class BPMNToPlaybooks(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        return action(config, params, **kwargs)
