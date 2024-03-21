from connectors.core.connector import Connector
from .builtins import soap_call, get_wsdl_details, soap_client, get_output_schema, check_health


class SOAP(Connector):

    def execute(self, config, operation, operation_params, **kwargs):
        operations = {
            'soap_call': soap_call,
            'get_wsdl_details': get_wsdl_details,
            'soap_client': soap_client,
            'get_output_schema': get_output_schema
        }
        operation = operations.get(operation)
        return operation(config, operation_params)

    def check_health(self, config):
        check_health(config)
