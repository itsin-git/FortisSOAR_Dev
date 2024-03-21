"""
Steps related to making SOAP requests
"""
import os
import json
import operator
import xmltodict
import zeep
import zeep.helpers
from voluptuous import (
    Required, All, Length,
    Schema, Optional,
)
from zeep.wsse.username import UsernameToken as WsseToken
from connectors.core.connector import get_logger, ConnectorError
from zeep.transports import Transport
from requests import Session
from connectors.cyops_utilities.builtins import download_file_from_cyops
from zeep import Settings
from zeep import xsd

logger = get_logger('builtins.soap')


def soap_call(config, params, *args, **kwargs):
    """
    Takes a soap connector out of the defined connectors and makes a soap call.
    Also see: :class:`SoapConnector.call`

    :param str func_name: name of the soap function to call
    :param list params: a list of arguments to send along
    :return: result of the soap call
    """
    extra_headers = params.pop('extra_headers', {})
    config.update({'extra_headers': extra_headers})
    client = SoapConnector(config)
    return client.call(params.get('func_name'), params.get('func_params'),
                       raw_response=config.get('raw_response', False))


def soap_client(config, params, *args, **kwargs):
    """
        Takes a soap connector out of the defined connectors and makes a soap call.
        Also see: :class:`SoapConnector.call`

        :param str func_name: name of the soap function to call
        :param list params: a list of arguments to send along
        :return: result of the soap call
        """
    extra_headers = params.pop('extra_headers', None) or {}
    extra_param_keys = ['service_name', 'port_type', 'header']
    new_params = {}

    for param_key in params:
        param_list = param_key.split(':')
        if len(param_list) == 3 and param_list[0] == 'header':
            # header params are defined as header:header_name:inner_header_name
            header_name = param_list[1]
            inner_header_name = param_list[2]
            if not header_name in extra_headers:
                extra_headers[header_name] = {}
            if params[param_key]:
                extra_headers[header_name].update({inner_header_name: params[param_key]})
            extra_param_keys.append(param_key)
        if len(param_list) == 2 and param_list[0] == 'file':
            # encode the file content here to bytes
            file_content = params[param_key]
            if file_content:
                file_content = get_file_content(file_content)
                new_params[param_list[1]] = file_content
            extra_param_keys.append(param_key)

    config.update({'extra_headers': extra_headers})
    client = SoapConnector(config)
    func_name = params.pop('func_name', None)
    for extra_key in extra_param_keys:
        params.pop(extra_key, None)
    params.update(new_params)

    if not func_name:
        raise ConnectorError('Function name not provided')

    return client.call(func_name, params, raw_response=config.get('raw_response', False))


def get_file_content(file_content):
    if isinstance(file_content, str):
        if 'api/3/attachments' in file_content or 'api/3/files' in file_content:
            file_content = get_file_content({"@id": file_content})
        else:
            file_content = file_content.encode('utf-8')
    elif isinstance(file_content, dict):
        if file_content.get('@id'):
            file_path = download_file_from_cyops(iri=file_content.get('@id')).get('cyops_file_path')
            file_path = os.path.join('/tmp', file_path)
            with open(file_path, 'rb') as file_object:
                file_content = file_object.read()
            file_content = get_file_content(file_content)
        else:
            file_content = get_file_content(json.dumps(file_content))
    return file_content


def get_wsdl_details(config, params, *args, **kwargs):
    client = SoapConnector(config)
    wsdl_details = client.get_wsdl_details()
    service_list = wsdl_details.keys()
    return {'options': service_list, 'onchange': wsdl_details}


def get_output_schema(config, params, *args, **kwargs):
    client = SoapConnector(config)
    return client.get_output_schema(params)


def check_health(config, *args, **kwargs):
    client = SoapConnector(config)


class SoapConnector():
    """
    Soap connector. Configured by a WSDL file provided by the soap service. Does
    not currently support the sending of arbitrary xml.
    """
    soap_connector_schema = Schema({
        Required('wsdl'): All(str, Length(min=1)),
        Optional('username', default=None): str,
        Optional('password', default=None): str,
        Optional('verify_ssl', default=False): bool,
        Optional('cert_file', default={}): dict,
        Optional('raw_response', default=False): bool,
        Optional('extra_headers', default={}): dict,
    })

    def __init__(self, soap_config, *args, **kwargs):
        """
        Creates a new soap connector. Requires a WSDL file that describes the
        soap service.

       :param str wsdl_path: url to WSDL file
       :return: An object that can be used to make soap calls
       :rtype: SoapConnector
       :raises requests.exceptions.InvalidSchema: if no wsdl file could be
           fetched
       """
        # pop any extra keys
        allowed_keys = ['wsdl', 'username', 'password', 'verify_ssl', 'cert_file', 'raw_response', 'extra_headers']
        extra_keys = [key for key in soap_config.keys() if key not in allowed_keys]
        for extra_key in extra_keys:
            soap_config.pop(extra_key, None)
        if not soap_config.get('cert_file'):
            soap_config['cert_file'] = {}
        soap_config = self.soap_connector_schema(soap_config)
        wsdl_path = soap_config['wsdl']
        username = soap_config['username']
        password = soap_config['password']
        verify_ssl = soap_config.get('verify_ssl', False)
        cert_file_iri = soap_config.get('cert_file', {}).get('@id')
        raw_response = soap_config.get('raw_response', False)
        extra_headers = soap_config.get('extra_headers', {})

        session = Session()
        session.verify = verify_ssl if verify_ssl else False
        if cert_file_iri:
            filename = download_file_from_cyops(cert_file_iri).get('cyops_file_path')
            session.cert = os.path.join('/tmp', filename)
        transport = Transport(session=session)
        settings = Settings(strict=False, raw_response=raw_response)

        if username and password:
            wsse_combo = WsseToken(username, password)
            self.client = zeep.Client(wsdl=wsdl_path, wsse=wsse_combo, transport=transport, settings=settings)
        else:
            self.client = zeep.Client(wsdl=wsdl_path, transport=transport, settings=settings)

        headers = []
        for header in extra_headers:
            # ns:0 is the mostly used namespace, change required if any other namespace used
            header_element = self.client.get_element('ns0:' + header)
            header_value = header_element(**extra_headers[header])
            headers.append(header_value)
        if headers:
            self.client.set_default_soapheaders(headers=headers)

    def get_input_type(self, type):
        integer_type_template = ['integer', 'int']
        select_type_template = ['select']
        checkbox_type_template = ['bool', 'boolean']
        file_type_template = ['base64Binary']
        date_type_template = ['dateTime', 'date']
        password_type_template = ['password', 'apikey']

        if type in integer_type_template:
            return 'integer'
        elif type in select_type_template:
            return 'select'
        elif type in checkbox_type_template:
            return 'checkbox'
        elif type in file_type_template:
            return 'file'
        elif type in date_type_template:
            return 'date'
        elif type in password_type_template:
            return 'password'
        else:
            return 'text'

    def get_operation_inputs(self, elements):
        inputs = []
        for name, element in elements:
            is_optional = element.is_optional if hasattr(element, 'is_optional') else True
            is_nullable = element.nillable if hasattr(element, 'nillable') else True
            if not is_nullable:
                is_optional = False
            elif is_nullable and not is_optional:
                is_optional = True
            input_details = self.get_input_template(name, name, element.type.name, is_optional)
            inputs.append(input_details)
        return inputs

    def get_input_template(self, name, title='', type='string', is_optional=True):
        type = self.get_input_type(type)
        if type == 'file':
            name = "file:" + name
        input_details = {
            'name': name,
            'title': title,
            'type': type,
            'visible': True,
            'editable': True,
            'required': not is_optional
        }
        return input_details

    def get_operation_outputs(self, elements):
        outputs = {}
        sequence = False
        for name, element in elements:
            if isinstance(element, (xsd.Sequence, xsd.Choice)):
                sequence = True
                type = element
            else:
                type = element.type
            try:
                inner_elements = type.elements_nested
                if not sequence:
                    output = self.get_operation_outputs(inner_elements)
                    outputs[name] = output
                if sequence:
                    outputs = []
                    output = self.get_operation_outputs(inner_elements)
                    outputs.append(output)
            except:
                dict_type = ['json', 'dict']
                list_type = ['array', 'list']
                type = element.type.name.lower()
                if type in dict_type:
                    outputs[name] = {}
                elif type in list_type:
                    outputs[name] = []
                else:
                    outputs[name] = ""
        return outputs

    def clean_output_schema(self, output_template, level=0):
        if len(output_template) == 1:
            if isinstance(output_template, list):
                output_template = self.clean_output_schema(output_template[0], level)
            elif isinstance(output_template, dict) and level < 1:
                keys = list(output_template.keys())
                output_template = self.clean_output_schema(output_template[keys[0]], level)
        else:
            for out_schema_key in output_template:
                output_template[out_schema_key] = self.clean_output_schema(output_template[out_schema_key], level=1)
        return output_template

    def get_header_inputs(self, headers, elements):
        if not headers:
            headers = self.get_input_template('header', 'Header', 'select')
        headers_onchange = headers.get('onchange', {})
        headers_options = headers.get('options', [])
        for name, element in elements:
            header_params = []
            header_name = element.name
            if not header_name in headers_options:
                headers_options.append(header_name)
                header_type = element.type
                inner_elements = header_type.elements
                for inner_element_name, inner_element in inner_elements:
                    type = 'password' if inner_element_name.lower() == 'password' else 'text'
                    header_details = self.get_input_template(name="header:" + header_name + ":" + inner_element_name,
                                                             title="Header::" + inner_element_name,
                                                             type=type)
                    header_params.append(header_details)
                headers_onchange[element.name] = header_params
        headers.update({"options": headers_options, "onchange": headers_onchange})
        return headers

    def get_output_schema(self, params):
        service_name = params.get('service_name')
        port_name = params.get('port_type')
        operation_name = params.get('func_name')
        output_template = {}
        for service in self.client.wsdl.services.values():
            if service.name == service_name:
                for port in service.ports.values():
                    if port.name == port_name:
                        operations = sorted(port.binding._operations.values(), key=operator.attrgetter('name'))
                        for operation in operations:
                            if operation.name == operation_name:
                                output_template = self.get_operation_outputs(operation.output.body.type.elements_nested)

        is_output_list = isinstance(output_template, list)
        cleaned_output_template = self.clean_output_schema(output_template)
        return [cleaned_output_template] if is_output_list and cleaned_output_template else cleaned_output_template

    def get_wsdl_details(self):
        services_onchange = {}
        for service in self.client.wsdl.services.values():
            headers = {}
            all_ports = []
            port_type_onchange = {}
            for port in service.ports.values():
                all_ports.append(port.name)
                operations = sorted(port.binding._operations.values(), key=operator.attrgetter('name'))
                all_functions = []
                all_functions_onchange = {}
                for operation in operations:
                    all_functions.append(operation.name)
                    try:
                        headers = self.get_header_inputs(headers, operation.input.header.type.elements)
                    except Exception as e:
                        pass
                    all_functions_onchange[operation.name] = self.get_operation_inputs(
                        operation.input.body.type.elements)

                function_template = self.get_input_template('func_name', 'Function Name', 'select', True)
                function_template.update({'options': all_functions, 'onchange': all_functions_onchange})
                port_type_onchange[port.name] = [function_template]

            port_template = self.get_input_template('port_type', 'Port Type', 'select', True)
            port_template.update({'options': all_ports, 'onchange': port_type_onchange})
            services_onchange[service.name] = [headers, port_template]

        return services_onchange

    def call(self, func_name, params, raw_response=False, *args, **kwargs):
        """
        Makes a soap call.

        :param str func_name: name of the soap function to call
        :param list params: a list of arguments to send along
        :param bool raw_response: raw_response
        :return: result of the soap call
        :raises zeep.exceptions.Fault: if the service was called incorrectly.
            There are many reasons this could happen: incorrect param arity,
            incorrect values, the function name being incorrect, etc.
        """
        # zeep will use the wsdl to construct these helper functions dynamically
        logger.info('makes a soap call.')
        result = {}
        func = getattr(self.client.service, func_name)
        if params:
            if type(params) == list:
                result = func(*params)
            elif type(params) == dict:
                result = func(**params)
            else:
                result = func(params)
        else:
            result = func()

        if raw_response:
            try:
                result = json.loads(json.dumps(xmltodict.parse(result.text)))
            except Exception as e:
                logger.error('Failed to parse raw response from soap endpoint duw to error : %s', str(e))
                raise e

        # results can be primitives or objects. In the case that the soap
        # service returns an object, zeep will turn it from xml into a custom
        # 'object' like thing that will let one access properties of the result
        # as if they were object attributes. This helper function will turn the
        # result into an ordinary python object, which, importantly,  will json
        # serialize.

        from collections import OrderedDict
        from zeep.xsd.valueobjects import CompoundValue

        # this replaces the use of zeep.helpers.serialize_object()
        def serialize_object(obj):
            if obj is None:
                return obj

            if isinstance(obj, list):
                return [serialize_object(sub) for sub in obj]

            result = OrderedDict()
            for key in obj:
                value = obj[key]
                # this is the only change (to add the check for lists V)
                if isinstance(value, CompoundValue) or isinstance(value, list):
                    value = serialize_object(value)
                result[key] = value
            return result

        try:
            result = serialize_object(result)
        except Exception:
            pass

        return result

