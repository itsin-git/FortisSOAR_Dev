from winrm.protocol import Protocol
from winrm.exceptions import InvalidCredentialsError
from connectors.core.connector import get_logger, ConnectorError
from requests import exceptions
import json

logger = get_logger('sccm')

IMPORT_CONFIG_MGR_CMD = 'powershell -command "Import-Module ($Env:SMS_ADMIN_UI_PATH.Substring(0,$Env:SMS_ADMIN_UI_PATH.Length-5) + \\"\ConfigurationManager.psd1\\");' \
                        '$PSD = Get-PSDrive -PSProvider CMSite;CD \\"$($PSD):\\"; '
GET_SOFTWARE_PATCHES_CMD = IMPORT_CONFIG_MGR_CMD + \
                           'Get-CMSoftwareUpdate -Fast | ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json;"'

GET_DEVICE_COLLECTIONS_CMD = IMPORT_CONFIG_MGR_CMD + \
                             'Get-CMDeviceCollection | ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json;"'

DEPLOY_SOFTWARE_PATCHES_CMD = IMPORT_CONFIG_MGR_CMD + 'New-CMSoftwareUpdateDeployment -SoftwareUpdateName \'{name}\' ' \
                              '-CollectionName \"{collection_name}\"{additional_params} |' \
                              ' ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json;"'

def _run_command(config, command):
    address = config['address'].strip().rstrip("/")
    username = config['user']
    password = config['password']
    protocol = config['protocol']
    port = config['port']
    verify_ssl = config['verify_ssl']
    if verify_ssl:
        verify_ssl_str = 'validate'
    else:
        verify_ssl_str = 'ignore'
    endpoint = '{0}://{1}:{2}/wsman'.format(protocol, address, port)
    logger.debug('endpoint is {}'.format(endpoint,))

    p = Protocol(
        endpoint=endpoint,
        transport='ntlm',
        username=username,
        password=password,
        server_cert_validation=verify_ssl_str)
    try:
        shell_id = p.open_shell()
    except InvalidCredentialsError:
        logger.exception('Invalid Credentials')
        raise ConnectorError('Invalid Credentials')
    except exceptions.SSLError:
        logger.exception('SSL Certificate Verification Failed')
        raise ConnectorError('SSL Certificate Verification Failed')
    except Exception as e:
        logger.exception('Error Connecting to SCCM Server')
        raise ConnectorError('Error Connecting to SCCM Server')

    try:
        logger.info('running command: {}'.format(command))
        command_id = p.run_command(shell_id, command)
        resp_output, resp_err, status_code = p.get_command_output(shell_id, command_id)
        logger.info('status_code: {}'.format(status_code,))
        logger.info('resp_err: {}'.format(resp_err,))
        logger.info('resp_output: {}'.format(resp_output,))
        p.cleanup_command(shell_id, command_id)
        p.close_shell(shell_id)
    except Exception:
        logger.exception('Error runinng powershell command on SCCM Server')
        raise ConnectorError('Error Runinng Powershell Command on SCCM Server')

    result = resp_output
    try:
        result = json.loads(resp_output.decode('utf-8'))
    except:
        # response not a json
        logger.info('response not a json: {}'.format(result))
    if status_code != 0 and (not config['do_not_fail']):
        raise ConnectorError(resp_err.decode('utf-8'))
    return {'op_status': status_code, 'op_result': result}


def check_health(config):
    _run_command(config, 'ipconfig')
    return True


def get_patches(config, params):
    return _run_command(config, GET_SOFTWARE_PATCHES_CMD)


def get_device_collections(config, params):
    return _run_command(config, GET_DEVICE_COLLECTIONS_CMD)


def deploy_patch(config, params):
    patch_name = params['patch_name']
    collection_name = params['collection_name']
    additional_params = params.get('additional_params', '').strip()
    if len(additional_params) > 0:
        additional_params = ' ' + additional_params.rstrip(';')
    return _run_command(config, DEPLOY_SOFTWARE_PATCHES_CMD.format(
        name=patch_name, collection_name=collection_name, additional_params=additional_params))


operations = {
    'get_patches': get_patches,
    'get_device_collections': get_device_collections,
    'deploy_patch': deploy_patch,
    'check_health': check_health
}
