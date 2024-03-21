import socket
import subprocess
import OpenSSL

from .constants import LOGGER_NAME
from connectors.core.connector import get_logger, Connector, ConnectorError

logger = get_logger(LOGGER_NAME)

DEFAULT_PORT = 8443


def _check_health(config):
    try:
        port = config.get('port', DEFAULT_PORT)
        if port < 1024:
            logger.error("raising an exception")
            raise ConnectorError("Cannot start listener on a system port. Port must be 1024 or higher.")
        if not check_associate_cert_with_private_key(config.get('ssl_cert'), config.get('ssl_key')):
            raise ConnectorError("Given certificate and key are invalid")
        if _is_port_used(port):
            raise ConnectorError(f"Given port: {port} is already in use")
        system_hostname = socket.gethostname()
        if config.get('hostname') != system_hostname:
            logger.warning("Hostname given does not match with system hostname you might not be able to access the web")
        return True
    except Exception as e:
        raise Exception(e)


def _is_port_used(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s_process = subprocess.Popen(['/usr/sbin/lsof', '-titcp:{}'.format(port)])
            pid, error = s_process.communicate()
            logger.info(error)
            if not pid:
                return False
            pid = pid[: -1]
            logger.info(pid)
            # ps -p <pid> -o command --no-heading
            service_details_pid = subprocess.check_output(
                ['/usr/bin/ps', '-p', '{}'.format(str(pid, 'UTF-8')), '-o', 'command', '--no-heading'])
            logger.info(service_details_pid)
            if str(service_details_pid, 'UTF-8').__contains__('/webserver/rest_controller.py'):
                return False
            return True
        except Exception as e:
            logger.exception(str(e))
            return True


def check_associate_cert_with_private_key(cert, private_key):
    """
    :type cert: str
    :type private_key: str
    :rtype: bool
    """
    if '-----BEGIN PRIVATE KEY-----' not in private_key:
        logger.error("Invalid keys, use PKCS#8 format, currently PKCS#1 detected")
        logger.error("Key should begin with -----BEGIN PRIVATE KEY-----")
        raise ConnectorError("Invalid keys, use PKCS#8 format, currently PKCS#1 detected")
    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    except OpenSSL.crypto.Error:
        logger.error('private key is not correct: %s' % private_key)
        raise ConnectorError("Key provided is not correct")
    try:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        logger.error('certificate is not correct: %s' % cert)
        raise ConnectorError("Certificate provided is invalid")
    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key_obj)
    context.use_certificate(cert_obj)
    try:
        context.check_privatekey()
        return True
    except OpenSSL.SSL.Error:
        return False
