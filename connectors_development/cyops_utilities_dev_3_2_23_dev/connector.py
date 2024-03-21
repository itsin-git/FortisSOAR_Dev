from connectors.core.connector import Connector, get_logger
logger = get_logger(__name__)
from .builtins import *


class Cyops(Connector):
    def __init__(self):
        super(Cyops, self).__init__()
        self.supported_operations = {
            'map_json': map_json,
            'xml_to_dictionary': xml_to_dictionary,
            'convert_to_json': convert_to_json,
            'html_table_to_dictionary': html_table_to_dictionary,
            'download_file_from_url': download_file_from_url,
            'create_file_from_string': create_file_from_string,
            'upload_file_to_url': upload_file_to_url,
            'api_call': api_call,
            'make_cyops_request': make_cyops_request,
            'query_cyops_resource': query_cyops_resource,
            'update_cyops_records': update_cyops_records,
            'insert_cyops_resource': insert_cyops_resource,
            'update_cyops_resource': update_cyops_resource,
            'upsert_cyops_resource': upsert_cyops_resource,
            'download_file_from_cyops': download_file_from_cyops,
            'download_file_from_cyops_alias': download_file_from_cyops,
            'zip_and_protect_file': zip_and_protect_file,
            'unzip_protected_file': unzip_protected_file,
            'create_cyops_attachment': create_cyops_attachment,
            'attach_indicators': attach_indicators,
            'ip_cidr_check': ip_cidr_check,
            'extract_artifacts': extract_artifacts,
            'parse_cef': parse_cef,
            'arrow_timestamp_diff': arrow_timestamp_diff,
            'no_op': no_op,
            'raise_exception': raise_exception,
            'convert_periodic_time_to_minutes': convert_periodic_time_to_minutes,
            'extract_email_metadata': extract_email,
            'extract_email_metadata_new': extract_email,
            'upload_file_to_cyops': upload_file_to_cyops,
            'updatemacro': setmacro,
            'get_macro_list': get_macro_list,
            'format_richtext': format_richtext,
            'format_richtext_html': format_richtext,
            'json_to_html': json_to_html,
            'get_attachment_types': get_attachment_types,
            'xor_byte_file_decryption': xor_byte_file_decryption,
            'markdown_to_html': markdown_to_html,
            'read_pem_certificate': read_pem_certificate
        }

    def execute(self, config, operation, operation_params, **kwargs):
        operation = self.supported_operations.get(operation)
        env = kwargs.get('env', {})
        request = kwargs.get('request')
        operation_params.update({'env': env, 'request': request})
        return operation(**operation_params)
