import ast
from collections import ChainMap
from copy import deepcopy
from connectors.core.connector import get_logger, ConnectorError
from RestrictedPython import safe_builtins
from django.conf import settings
import importlib.util
import os
import sys
import inspect

logger = get_logger('code_snippet')

python_env_path = os.path.join(os.path.dirname(inspect.getfile(os)), 'site-packages')
allow_only_safe_builtins = settings.APPLICATION_CONFIG.getboolean('connector_configuration', 'allow_only_safe_builtins',
                                                               fallback=False)
custom_builtins_list = settings.APPLICATION_CONFIG.get('connector_configuration', 'custom_builtins',
                                                               fallback="[]")
logger.debug(f'Custom builtins list from config: {custom_builtins_list}')

custom_builtins = {
    'print': print,
    'list': list,
    'dict': dict,
    '__import__': __import__
}
try:
    for builtin_name in ast.literal_eval(custom_builtins_list):
        custom_builtins.update({
            builtin_name: __builtins__[builtin_name]
        })
except Exception as err:
    logger.error(err)
    pass
logger.debug(f'Custom builtins dict: {custom_builtins}')

allowed_builtins = dict(ChainMap(safe_builtins, custom_builtins)) if allow_only_safe_builtins else __builtins__
restricted_globals = dict(__builtins__=allowed_builtins)

def import_list(list_to_import):
    if isinstance(list_to_import, str):
        list_to_import = list_to_import.replace(' ', '').split(',')
    elif isinstance(list_to_import, tuple):
        list_to_import = list(list_to_import)
    else:
        logger.error('Incorrect input for the import list.')
        raise ConnectorError('Incorrect input for the import list.')

    return list_to_import


def _import_modules(list_to_import):
    for module_name in list_to_import:
        try:
            logger.info('Importing {}'.format(str(list_to_import)))
            t = importlib.util.find_spec(module_name, python_env_path)
            t.loader.load_module()
            return True
        except Exception as err:
            logger.error('Error importing module {}: {} (Module not available in env)'.format(module_name, err))
            raise ConnectorError('Error importing module {}: {} (Module not available in env)'.format(module_name, err))


def list_to_dict(list_to_import):
    local_parameter = deepcopy(restricted_globals)
    for module_name in list_to_import:
        try:
            if module_name not in sys.modules:
                t = importlib.util.find_spec(module_name, python_env_path)
                module_path = t.loader.load_module()
            else:
                module_path = sys.modules.get(module_name)
            local_parameter[module_name] = module_path
        except Exception as err:
            logger.error('Error importing module {}: {} (Module not available in env)'.format(module_name, err))
            raise ConnectorError('Error importing module {}: {} (Module not available in env)'.format(module_name, err))
    return local_parameter
