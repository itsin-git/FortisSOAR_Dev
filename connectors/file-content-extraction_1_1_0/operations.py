""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import download_file_from_cyops, extract_artifacts, save_file_in_env
import os
import json
import requests

logger = get_logger('file-content-extraction')

# consts
TMP_PATH = '/tmp/'


def extract_text(config, params, *args, **kwargs):
    '''Extracts text from file and return it as utf8 or HTML formatted'''
    parser, tika_config = _set_env()
    try:
        if params.get('file_iri') and '/api/3/files/' not in params.get('file_iri'):
            file_path = os.path.join(TMP_PATH, params.get('file_iri'))
        else:
            file_iri = params.get('file_iri')
            dw_file_md = download_file_from_cyops(file_iri)
            file_path = TMP_PATH + dw_file_md['cyops_file_path']
        html_output_format = params.get('html_output_format')
        if html_output_format is None:
            html_output_format = False
        parsed_file = parser.from_file(file_path, xmlContent=html_output_format)
        if os.path.exists(file_path):
            save_file_in_env(kwargs.get('env', {}), file_path)
        return {'metadata': parsed_file['metadata'], 'extracted_text': parsed_file['content']}

    except requests.exceptions.HTTPError as e:
        logger.error('Error: File with IRI:<< {} >> does not exist'.format(file_iri))
        raise ConnectorError('Error: File with IRI:<< {} >> does not exist'.format(file_iri))
    except Exception as exp:
        logger.error('Error Parsing the File: {}'.format(exp))
        raise ConnectorError('Error Parsing the File: {}'.format(exp))


def extract_indicators(config, params, *args, **kwargs):
    '''Extracts artifacts from extracted text'''
    extracted_text = extract_text(config, params, *args, **kwargs)
    return extract_artifacts(extracted_text)


def get_backend_config(config, params, *args, **kwargs):
    '''Get Tika Server Attr'''
    parser, tika_config = _set_env()
    try:
        verbose_config = params.get('verbose_config')
        parsers = json.loads(tika_config.getParsers())
        mime_types = json.loads(tika_config.getMimeTypes())
        detectors = json.loads(tika_config.getDetectors())
        if verbose_config:
            return {'Parsers': parsers, 'MimeTypes': mime_types, 'Detectors': detectors}
        else:
            return {'MimeTypes': mime_types}
    except Exception as exp:
        logger.error('Error Reading Engine Config: {}'.format(exp))
        raise ConnectorError('Error Reading Engine Config: {}'.format(exp))


def _set_env():
    try:
        from tika import parser
        from tika import config as tika_config
        return parser, tika_config
    except Exception as exp:
        logger.error('Error initiating local engine: {}'.format(exp))
        raise ConnectorError('Error initiating local engine {}'.format(exp))


def _check_health(config):
    '''Computes tika's jar md5 hashcode'''
    _set_env()


operations = {
    'extract_text': extract_text,
    'extract_indicators': extract_indicators,
    'get_backend_config': get_backend_config
}
