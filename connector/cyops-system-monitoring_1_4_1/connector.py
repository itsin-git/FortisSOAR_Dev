from connectors.core.connector import Connector
from .operations import operations, _check_health


class Monitoring(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        return action(config, params, **kwargs)

    def check_health(self, config):
        _check_health(config)
