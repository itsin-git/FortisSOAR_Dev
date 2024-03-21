from connectors.core.connector import Connector, get_logger, ConnectorError
from .builtins import run_remote_command, run_remote_python, run_sftp_copy, _prepare_ssh_client
logger = get_logger('connector.ssh')

class SSH(Connector):

    def execute(self, config, operation, operation_params, **kwargs):
        operations = {'run_remote_command': run_remote_command,
                      'run_remote_python': run_remote_python,
                      'run_sftp_copy': run_sftp_copy}
        operation = operations.get(operation)
        return operation(config, operation_params)

    def check_health(self, config):
        try:
            _prepare_ssh_client(config)
        except Exception as e:
            logger.error("Error occurred while creating the ssh client ERROR :: {0}".format(str(e)))
            raise ConnectorError("Error occurred while creating the ssh client ERROR :: {0}".format(str(e)))