"""
Steps that use an ssh connection. Including sftp and remote code execution.
"""
from connectors.core.connector import get_logger, ConnectorError
from io import StringIO
from io import open
from integrations.crudhub import make_request

import paramiko
import time
import os
import sys
import base64

from voluptuous import (
    Required, All, Length, Range,
    Schema, Optional, Coerce
)

logger = get_logger('builtins.ssh')


def _prepare_ssh_client(config):

    if isinstance(config.get('private_key', {}), dict) and config.get('private_key', {}).get('@type') == "File":
        url = config.get('private_key', {}).get('@id')
        config["private_key"] = make_request(url, 'GET')
    else:
        config["private_key"] = ''

    allowed_keys = ['host', 'port', 'timeout', 'private_key', 'username', 'password', 'super_user_password', 'config_id', 'name', 'status']
    with open('./extkey.txt', 'w') as f:
        print('test', file=f)
        print(config.keys(), file=f)
    extra_keys = [key for key in config.keys() if key not in allowed_keys]
    for extra_key in extra_keys:
        config.pop(extra_key, None)

    config = HOST_CONFIG_SCHEMA(config)

    # extract host info
    host = config['host']
    port = config['port']
    username = config['username']
    password = config['password'] if config['password'] else None
    private_key = config['private_key']
    config_id = config['config_id']
    name = config['name']
    status = config['status']

    # prepare file like object with the private key
    rsa_key = None
    if private_key:
        private_key_data = StringIO()
        private_key_data.write(private_key)
        private_key_data.seek(0)
        rsa_key = paramiko.RSAKey.from_private_key(
            file_obj=private_key_data,
            password=password
        )

    client = paramiko.client.SSHClient()

    # FIXME: there should probably be some verification here instead of
    # blindly adding to known_hosts
    client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
    client.load_system_host_keys()

    client.connect(host, port=port, username=username, password=password,
                   # don't ever search for keys, just use the ones provided
                   pkey=rsa_key, allow_agent=False, look_for_keys=False)
    return client


HOST_CONFIG_SCHEMA = Schema({
    Required('host'): All(str, Length(min=1)),
    Optional('port', default=22): All(Coerce(int),
                                      Range(min=0, max=65535)),
    Optional('timeout', default=5): int,
    Optional('private_key'): str,
    Required('username'): str,
    Optional('private_key'): str,
    Optional('super_user_password', default=None): str,
    Optional('password', default=None): str,
    Optional('config_id', default=None): str,
    Optional('name', default=None): str,
    Optional('status', default=1): int,
})


def run_remote_command(config, params, *args, **kwargs):
    """
    Executes a command on a remote server. Assumes that keys have already been
    set up properly -- it does not allow for password based login, you must set
    up the public/private keys. RSA keys only for now. Host configuration for
    this object is of the following form::
    {
        'host': '<host string>',
        'port': <port number; 0-65535; default 22>,
        'timeout': '<ssh timeout in seconds; default 5',
        'private_key': '<text of a private key file>'
        'username': '<string>',
        'password': '<string; default None>'
    }

    Keys can be generated using ssh-keygen. If a password is provided in the
    hostconfig, it will be used to decrypt the private key.

    .. caution::
        There are currently no restrictions on the commands you can run, nor any
        plans to implement said restrictions. Notice, also, that you did not SEA
        a sign outside of sealab that said 'Configuration management'. The
        reason you did not see that sign, is that configuration management is
        not sealab's business. Any programs you want to use on your server, you
        must install yourself.

   :param dict config: describes how/where to connect to; see above
   :param str cmd: the command to be run on the remote server
   :param list allowed_exit: a list of non-standard exit codes to allow from
       remote commands. Default values are 0 (standard success exit code) and -1
       (meaning the remote command did not return any exit code)
   :return: the result of the run command
   :rtype: str
    """
    cmd = params['cmd']
    version = sys.version
    os.system('echo \'' + cmd + '\' > ./cmd.txt')
    with open('./cmdtype.txt','w') as o:
        print(type(cmd), file=o)

    os.system('echo \'' + version + '\' >> ./version.txt')
    #if params.get('is_super_user', False):
        #if config.get('super_user_password', None):
        #    cmd = 'echo ' + config.get('super_user_password') + ' | sudo ' + cmd
        #else:
        #    logger.error('Cannot run command as super user, password for super user not provided')
        #    raise ConnectorError('Cannot run command as super user, password for super user not provided')
    allowed_exit = params.get('allowed_exit', '')
    if isinstance(allowed_exit, int):
        allowed_exit = [allowed_exit]
    logger.info('run_remote_command starts')
    if not allowed_exit:
        allowed_exit = [-1, 0]
    #allowed_exit = [-1, 0]
    #if not isinstance(allowed_exit, list):
    #    raise ConnectorError("Invalid data type for allowed exit codes")
    config = HOST_CONFIG_SCHEMA(config)

    # extract host info
    host = config['host']
    port = config['port']
    username = config['username']
    password = config['password'] if config['password'] else None
    private_key = config['private_key']

    with _prepare_ssh_client(config) as client:
        # actual command execution right here
        #streams = client.exec_command(cmd, timeout=config['timeout'],
                                      # get pty so that when the ssh connection
                                      # ends, the remote command will be killed
                                      # as well
        #                              get_pty=True)
        #stdin, stdout, stderr = streams
        #logger.error(stderr.read().decode('utf-8'))
        #result = stdout.read().decode('utf-8').strip()
        #exit_code = stdout.channel.recv_exit_status()
        
        channel = client.invoke_shell()

        out = channel.recv(9999)

        while True:
            if "Username" in out.decode("utf-8"):
                channel.send(username)
                channel.send("\n")  
                while not channel.recv_ready():
                    time.sleep(3)
                
                out = channel.recv(9999)
                time.sleep(1)
                
            elif "Password" in out.decode("utf-8"):
                channel.send(password)  
                channel.send("\n")  
                while not channel.recv_ready():
                    time.sleep(3)
                    
                out = channel.recv(9999)
                time.sleep(1)
        
            else:
                break
        
        #cmd = 'ping 58.226.22.109 count 5\n'
        
        f = open('./cmds.txt', 'w', encoding='utf8')

        
        time.sleep(1)
        cmd_result = ''

        cmds = cmd.split('[CR]')

        cmdtype=type(cmd)
        cmdstype=type(cmds)
        print(cmdtype, file=f)
        print(cmdstype, file=f)
        print(cmd, file=f)
        print(cmds, file=f)

        for c in cmds:
            channel.send(c)
            channel.send('\n')
            f.write(c)
            f.write('fuck\n')

        while not channel.recv_ready():
            time.sleep(3)

        out=channel.recv(9999).decode('utf-8')
        f.close()
        
        try:
            while out:
                if out != "":
                    os.system('ping 1.1.1.1 -c 2')
                    out = ''
                    time.sleep(2)
                    if channel.recv_ready():
                        out = channel.recv(9999).decode('utf-8')
                        cmd_result = cmd_result + out
            
                if out == "":
                    os.system('ping 2.2.2.1 -c 2')
                    break
        
        except Exception as e:
            os.system('echo \'' + str(e) + '\' >> ./axgate_Error_Log.txt')
            print("Except:" + str(e))

        
        result = cmd_result

        os.system('echo \'' + cmd + username + password + '\' >> ./cmd2.txt')
          
        channel.close()
        client.close()

    exit_code = channel.recv_exit_status()

    if exit_code not in allowed_exit:
        try:
            logger.error(
                'Command failed with exit code: {0}'.format(exit_code)
            )
            raise paramiko.SSHException(
                'Command failed with exit code: {0}'.format(exit_code)
            )
        except Exception as exp:
            raise ConnectorError(str(exp))
    return result


def run_remote_python(config, params, version=2, *args, **kwargs):
    logger.info('run_remote_python starts')
    if version not in [2, 3]:
        raise ConnectorError('Unknown python version')
    script = params.get('script', '')
    script = script.replace('"', '\\"')
    cmd = 'python{0} -c "{1}"'.format(version, script)
    return run_remote_command(config, {'cmd': cmd}, *args, **kwargs)


def run_sftp_copy(config, iri, *args, **kwargs):
    logger.info('run_sftp_copy starts')

    file_obj = StringIO()
    file_obj.seek(0)

    with _prepare_ssh_client(config) as client:
        sftp = client.open_sftp()
        remote_path = '/home/{username}/scripts/'.format(
            username=config['username']
        )
        try:
            sftp.mkdir(remote_path, mode=511)
        except OSError:
            logger.error('')
            # either this path exists, or there's not a lot we can do
            pass
        import uuid
        sftp.putfo(file_obj, remote_path + uuid.uuid4())
    return

run_sftp_copy.__str__ = lambda: 'Remote file copy'
