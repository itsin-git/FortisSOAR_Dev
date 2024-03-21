from connectors.core.connector import get_logger, ConnectorError
import importlib.util
import os
import sys
import inspect

logger = get_logger('code_snippet')

python_env_path = os.path.join(os.path.dirname(inspect.getfile(os)), 'site-packages')


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
    local_parameter = {}
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
