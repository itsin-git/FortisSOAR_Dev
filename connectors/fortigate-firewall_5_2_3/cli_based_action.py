""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from io import StringIO
from os.path import join

import paramiko
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import download_file_from_cyops

from .utils import *
from .utils import _get_list_from_str_or_list

logger = get_logger('fortigate-firewall')


def read_file_data(params):
    try:
        file_meta = params.get('private_key')
        file_path = join('/tmp', download_file_from_cyops(file_meta.get('@id'))['cyops_file_path'])
        with open(file_path, 'rb') as attachment:
            file_content = attachment.read()
        return file_path, file_content
    except Exception as e:
        error_message = "Error While fetching {0} file data:\n{1}".format(params.get('private_key'), str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def _prepare_ssh_client(config, params):
    try:
        # extract host info
        host = config.get('address').strip('/')
        host = host.split('//')
        if len(host) == 2:
            host = host[1]
        else:
            host = host[0]
        port = params.get('port')
        username = params.get('username')
        password = params.get('password')

        rsa_key = None
        if params.get('private_key') and params.get('private_key').get('filename'):
            private_key_data = StringIO()
            file_path, file_data = read_file_data(params)
            private_key_data.write(str(file_data.decode('utf-8')))
            private_key_data.seek(0)
            rsa_key = paramiko.RSAKey.from_private_key(
                file_obj=private_key_data,
                password=password
            )
            logger.info('successfully created rsa key-pair')
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        client.load_system_host_keys()
        client.connect(host, port=port, username=username, password=password, pkey=rsa_key,
                       allow_agent=False, look_for_keys=False)
        return client
    except Exception as Err:
        raise ConnectorError(str(Err))


def execute_command(config, params):
    try:
        client = _prepare_ssh_client(config, params)
        cmd_list = _get_list_from_str_or_list(params, 'cmd_list')
        if not cmd_list:
            return []
        cmd_output = []
        for cmd in cmd_list:
            streams = client.exec_command(cmd, timeout=params.get('timeout') if params.get('timeout') else None, get_pty=True)
            stdin, stdout, stderr = streams
            error_str = stderr.read().decode('utf-8')
            if len(error_str) > 0 :
                logger.error("Failed command execution with error [{0}]. "
                             "Commands executed successfully [{1}]".format(error_str , str(cmd_output)))
                raise ConnectorError("Failed command execution with error [{0}]. Refer log file"
                                     " for more details".format(error_str))
            result = stdout.read().decode('utf-8').strip()
            cmd_output.append({"command": cmd, "output": result.split("\r\n")})
            if "Command fail." in result:
                logger.error("Command Fail to Execute {0}".format(str(cmd_output)))
                raise ConnectorError("Command Fail to Execute {0}".format(str(cmd_output)))
        client.close()
        return cmd_output
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))
