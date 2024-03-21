import json

from connectors.core.connector import get_logger, ConnectorError
from django.conf import settings
import sys
import re
import ast
import traceback
import yaml
from yaml.parser import ParserError
from yaml import YAMLError
from io import StringIO
from .utils import import_list, _import_modules, list_to_dict

logger = get_logger('code_snippet')


def python_inline(config, params):
    code = params['python_function']
    allow_os_packages = settings.APPLICATION_CONFIG.getboolean('connector_configuration', 'allow_os_packages',
                                                               fallback=False)
    error_message = 'The connector configuration does not allow importing from (os, subprocess, sys) modules. ' \
                    'Remove import statements for these modules and retry.'

    if not allow_os_packages:
        if config['allow_imports']:
            if _regex_for_imports(code):
                raise ConnectorError(error_message)
        else:
            list_to_import = import_list(config['restrict_imports'])
            if _regex_for_imports(list_to_import):
                raise ConnectorError(error_message)
    if not config['allow_imports']:
        # import statements should not be present in the statement
        if 'import ' in code:
            raise ConnectorError('The connector configuration does not allow imports in the code snippet. '
                                 'Remove import statements from the code snippet and retry.')

    result = {
        'code_output': ''
    }
    redirected_output = sys.stdout = StringIO()
    code_object = compile(code, 'code_run', 'exec')

    if config['allow_imports']:
        try:
            exec(code_object, {})
            code_output = redirected_output.getvalue().replace('\n', '')
            return _parse(code_output, result)
        except (ParserError, YAMLError) as err:
            logger.error('A parser error has occurred: {}'.format(err))
            raise ConnectorError('A parser error has occurred: {}'.format(err))
        except Exception:
            traceback_str = str(traceback.format_exc())
            logger.error(
                'Invalid code snippet: {}'.format(traceback_str[traceback_str.find('code_run') + len('code_run') + 3:]))
            raise ConnectorError(
                'Invalid code snippet: {}'.format(traceback_str[traceback_str.find('code_run') + len('code_run') + 3:]))
        finally:
            sys.stdout.flush()
            redirected_output.close()
    else:
        if 'restrict_imports' in config:
            try:
                exec(code_object, list_to_dict(import_list(config['restrict_imports'])))
                code_output = redirected_output.getvalue().replace('\n', '')
                return _parse(code_output, result)
            except (ParserError, YAMLError) as err:
                logger.error('A parser error has occurred: {}'.format(err))
                raise ConnectorError('A parser error has occurred: {}'.format(err))
            except Exception:
                traceback_str = str(traceback.format_exc())
                logger.error('Invalid code snippet: {}'.format(
                    traceback_str[traceback_str.find('code_run') + len('code_run') + 3:]))
                raise ConnectorError('Invalid code snippet: {}'.format(
                    traceback_str[traceback_str.find('code_run') + len('code_run') + 3:]))
            finally:
                sys.stdout.flush()
                redirected_output.close()
        else:
            logger.error('Error importing module {} (Module not available in env)'.format(config['restrict_imports']))
            raise ConnectorError(
                'Error importing module {} (Module not available in env)'.format(config['restrict_imports']))


def _parse(code_output, result):
    # parses list of dicts/nests differently
    if code_output.startswith('{') and code_output.endswith('}'):
        # we want regex to trigger only under certain cases
        check_for_dict = re.subn(r'(})({)', '},{', code_output)
        if check_for_dict[-1] > 0:
            result['code_output'] = list(ast.literal_eval(check_for_dict[0]))
        else:
            result['code_output'] = yaml.safe_load(json.dumps(code_output))
    else:
        result['code_output'] = yaml.safe_load(json.dumps(code_output))
    return result


def _regex_for_imports(code_string):
    """
    Case 1: import sys
    Case 2: import os.path
    Case 3: import json, sys, os...
    Case 4: from os import path
    Case 5: The format ['os', 'sys', 'json'] is used when allow_imports is set to false

    This function filters the string for all the cases listed above.

    :param code_string: The entire code input entered in the playbook step (type: str)
                        OR
                        list of libraries that were entered in connector config (type: list)
    :return: True/False based on if a match is found
    """
    restricted_libs = 'os|sys|subprocess'
    if not isinstance(code_string, list):
        # Case 1 and Case 2
        case_one_two_regex = re.compile(r'^import (?:{})(?:\.[a-zA-Z0-9_-]*)*\s*$'.format(restricted_libs), re.MULTILINE)
        match_one_two = case_one_two_regex.search(code_string)
        if match_one_two is not None:
            return True
        # Case 3
        case_three_regex = re.compile(r'^import [a-zA-Z0-9._-]*(?:,\s*[a-zA-Z0-9._-]*)+$', re.MULTILINE)
        match_three = case_three_regex.search(code_string)
        if match_three is not None:
            matched_libraries_list = match_three.group().replace('import ', '').replace(' ', '').split(',')
            for index, lib in enumerate(matched_libraries_list):
                if '.' in lib:
                    matched_libraries_list[index] = lib.split('.')[0]
            restricted_libs_list = restricted_libs.split('|')
            intersected_list = set(matched_libraries_list).intersection(set(restricted_libs_list))
            if len(intersected_list) > 0:
                return True
        # Case 4
        case_four_regex = re.compile(r'^from (?:{}) import .*'.format(restricted_libs), re.MULTILINE)
        match_four = case_four_regex.search(code_string)
        if match_four is not None:
            return True
    else:  # input is a list, meaning it's checking for restrict_imports input
        # Case 5
        case_five_regex = re.compile(r'(?:{})(?:\.[a-zA-Z0-9_-]*)*$'.format(restricted_libs))
        for lib in code_string:
            match_five = case_five_regex.search(lib)
            if match_five is not None:
                return True

    return False


def _check_health(config):
    allow_os_packages = settings.APPLICATION_CONFIG.getboolean('connector_configuration', 'allow_os_packages',
                                                               fallback=False)
    if config['allow_imports']:
        _import_modules(['requests'])
    else:
        list_to_import = import_list(config['restrict_imports'])
        if not allow_os_packages:
            if _regex_for_imports(list_to_import):
                raise ConnectorError('The connector configuration does not allow importing (os, subprocess, sys) '
                                     'packages. Remove these packages from universal imports and retry.')
        _import_modules(list_to_import)


operations = {
    'python_inline': python_inline,
    'python_inline_code_editor': python_inline
}
