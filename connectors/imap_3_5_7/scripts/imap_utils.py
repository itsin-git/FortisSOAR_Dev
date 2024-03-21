import logging
import ssl as ssl_lib
from imapclient import IMAPClient
from imapclient.exceptions import LoginError
import sys
import os
from os import path
sys.path.append(path.abspath('/opt/cyops-integrations/integrations'))
from connectors.imap.errors.error_constants import *

LOG_DIR_PATH = '/var/log/cyops/cyops-integrations/imap/'
LOG_FILE_PATH = path.join(LOG_DIR_PATH, 'listener.log')
os.makedirs(LOG_DIR_PATH, exist_ok=True)

logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(module)s %(funcName)s(): %(message)s')

logger = logging.getLogger(__name__)

def _select_folder(client, folder):
    """
    Selects a folder on the IMAP server

   :param IMAPClient client: The client object containing connection info
   :param str folder: The folder to select

   :return: a dict containing information about the folder
   :rtype: dict
    """
    return client.select_folder(folder)


def _make_imap_client(host, port, username, password, ssl, verify=True):
    """
    Creates the IMAP client that contains connection information.

   :param str host: imap host
   :param str port: imap port
   :param str username: username for email account
   :param str password: password for email account

   :return: The IMAP client with an active connection into the IMAP server
   :rtype: IMAPClient
    """
    imap_client_args = {
        'host': host,
        'port': port,
        'ssl': ssl,
        'use_uid': True,
        'timeout': 5,
    }

    try:
        if ssl and not verify:
            context = ssl_lib.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_lib.CERT_NONE
            imap_client_args["ssl_context"] = context
        client = IMAPClient(**imap_client_args)
        client.login(username, password)
    except LoginError as e:
        logger.exception("{0} ERROR :: {1}".format(cs_imap_14, str(e)))
        raise Exception("%s" % cs_imap_14)
    except Exception as e2:
        logger.exception("{0} ERROR :: {1}".format(cs_imap_19,str(e2)).format(username))
        raise Exception(cs_imap_19.format(username))
    return client

def logout_client (client):
    try:
        client.logout()
    except Exception as e:
        logger.warn(cs_imap_18.format(str(e)))
    return