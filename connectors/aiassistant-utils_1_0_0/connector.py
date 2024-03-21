from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations
from .listener_client import start_socket_server, stop_socket_server, check_listener_health
import json

logger = get_logger("ai-assistant")


class AIAssistant(Connector):
    def execute(self, config, operation, params, *args, **kwargs):
        try:
            logger.info("execute [{}]".format(operation))
            operation = operations.get(operation)
            return operation(config, params, *args, **kwargs)
        except Exception as err:
            logger.exception("Exception occurred while executing action")
            raise ConnectorError("An exception occurred: {}".format(err))

    def on_app_start(self, config, active):
        if active:
            start_socket_server()

    def on_activate(self, config):
        self.on_app_start(config, True)

    def on_deactivate(self, config):
        stop_socket_server()

    def teardown(self, config):
        logger.debug("Teardown listener setup for AI connector")
        self.on_deactivate(config)

    def check_health(self, config):
        response = check_listener_health()
        response = json.loads(response.decode('utf-8'))
        if response['status'] == -1:
            raise ConnectorError(response['message'])
        return True
