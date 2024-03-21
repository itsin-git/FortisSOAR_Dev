import email
import json
import ssl as ssl_lib
from django.conf import settings
from .errors.error_constants import *
from imapclient import IMAPClient
from imapclient.exceptions import LoginError
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import explode_email

logger = get_logger("builtins.imap")


try:
    extract_email_metadata_legacy = settings.APPLICATION_CONFIG.getboolean('connector_configuration',
                                                                       'extract_email_metadata_legacy', fallback=False)
except:
    extract_email_metadata_legacy = False

# py 3.6 when
DISPLAY_SIZE_LIMIT = 20000


def _make_imap_client(host, port, username, password, ssl, verify):
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
        raise ConnectorError("%s" % cs_imap_14)
    except Exception as e2:
        logger.exception("{0} ERROR :: {1}".format(cs_imap_19, str(e2)).format(username))
        raise ConnectorError(cs_imap_19.format(username))
    return client


def _fetch_email(client, source, destination, limit_count=30, optimize=False, parse_inline_image=False, **kwargs):
    """
    Fetches emails from the source and moves them to the destination

   :param IMAPClient client: The client object containing connection info
   :param str source: The name of the folder/label to fetch from
   :param str destination: The name of the folder/label to move emails to

   :return: The list of emails that were processed
   :rtype: list
    """

    # get a list of unread emails from the source folder
    _select_folder(client, source)
    unread_emails, unread_mails_count = _fetch_unread(client, limit_count)

    # make sure both folders exist
    # this func will create the folder if it doesn't exist
    if not _check_folder_exists(client, source):
        logger.info('Creating new folder {0}'.format(source))
    if not _check_folder_exists(client, destination):
        logger.info('Creating new folder {0}'.format(destination))

    emails = []
    for msgid, data in unread_emails.items():
        # take out desired email part
        # this also marks the email as read
        if 'new' in kwargs:
            raw_msg = data[b'RFC822']
            email_data = explode_email(raw_msg, optimize=optimize, parse_inline_image=parse_inline_image, **kwargs)
            if optimize and extract_email_metadata_legacy:
                _set_email_header_value(email_data)
        else:
            email_data = _parse_email_old(client, data)
        # move the email to another folder
        _move_email(client, msgid, source, destination)
        # build up list of emails
        email_data['total_unread_emails'] = unread_mails_count
        emails.append(email_data)

    # end the imap session

    return emails


def logout_client(client):
    try:
        client.logout()
    except Exception as e:
        logger.exception("Message: IMAP client logout unsuccessfull %s", str(e))
    return


def _select_folder(client, folder):
    """
    Selects a folder on the IMAP server

   :param IMAPClient client: The client object containing connection info
   :param str folder: The folder to select

   :return: a dict containing information about the folder
   :rtype: dict
    """
    return client.select_folder(folder)


def _fetch_unread(client, limit_count):
    """
    Queries for all unread emails and fetches their bodies

   :param IMAPClient client: The client object containing connection info

   :return: a dict containing info about each message, indexed by message
      number
   :rtype: defaultdict
    """
    # find list of unread emails
    uids = client.search(['UNSEEN'])
    unread_mails_count = len(uids)
    uids = uids[:int(limit_count)]
    # if there are no unread emails, do nothing
    if not len(uids):
        return {}, 0

    # fetch the body of those messages
    return client.fetch(uids, ['RFC822']), unread_mails_count


def _check_folder_exists(client, folder):
    """
    Creates a folder if it doesn't already exist

   :param IMAPClient client: The client object containing connection info
   :param str folder: The folder to create if it doesn't exist

   :return: True if the folder existed, false if it had to be created
   :rtype: bool
    """
    if client.folder_exists(folder):
        return True
    else:
        try:
            client.create_folder(folder).decode('utf-8')
            return False
        except Exception as e:
            message = 'Error creating the {0} folder. It could be that a folder with the same name already exists with restricted permission.'.format(
                folder)
            logger.error('{0} Error: {1}'.format(message, str(e)))
            raise Exception(message)


def _set_email_header_value(email_data):
    header_template = {
        "from": "",
        "to": [],
        "cc": [],
        "bcc": [],
        "subject": "",
        "message-id": [],
        "date": "",
        "received": [],
        "return-path": ""
    }
    headers = email_data['headers']
    optimized_headers = {}
    for key, value in headers.items():
        key = key.lower()
        if key in header_template:
            if not type(header_template[key]) == type(value):
                if isinstance(header_template[key], list) and isinstance(value, str):
                    value = value.split(',')
            optimized_headers[key] = value
        else:
            if not 'metadata' in optimized_headers:
                optimized_headers['metadata'] = {}
            else:
                optimized_headers['metadata'][key] = value
    email_data['headers'] = optimized_headers


def _parse_email_old(client, email_data, *args, **kwargs):
    return {
        'attachments': _extract_attachments(client, email_data),
        'body': _extract_body(client, email_data),
        'headers': _extract_headers(email_data),
    }


def __extract(data, extract):
    """
    Massages the email information in data to a more usable format

   :param dict data: Contains information describing the email message
   :param Callable[str] extract: Function to extract / massage email data

   :return: list of massaged email data
   :rtype: list
    """
    # first, make an email.message out of the raw dict
    raw_msg = data[b'RFC822']
    message = email.message_from_bytes(raw_msg)
    # walk through each part, separated by MIME boundary
    if message.is_multipart():
        # for every segment of the email, apply the extract function
        extracted = [extract(part) for part in message.walk()]
        # filter out any null values
        return [t for t in extracted if t]
    else:
        # otherwise, just apply extract to the whole email
        payload = extract(message)
        # but still return a list
        return [payload] if payload else []


def _extract_headers(data):
    """
    Massages headers into a more workable dict

   :param dict data: Contains the headers in an unruly bytes format

   :return: dict of the headers
   :rtype: dict
    """
    raw_msg = data[b'RFC822']
    message = email.message_from_bytes(raw_msg)
    return dict(message.items())


def _extract_body(client, data):
    """
    Test the content of an email for being plain text

   :param IMAPClient client: The client object containing connection info
   :param dict data: Contains information describing the email message

   :return: list of the extracted body parts of the email
   :rtype: list
    """

    def _body(email_part):
        if (email_part.get('Content-Disposition') is None and
                    email_part.get_content_type() == 'text/plain'):

            # try to find the content type for decoding bytes, otherwise just
            # guess its utf-8 :\
            content_type = email_part.get_content_charset()
            content_type = content_type if content_type else 'utf-8'

            # decode takes care of converting quoted-printable
            body = email_part.get_payload(decode=True).decode(
                content_type
            ).rstrip()

            # attempt to convert plain text body to json
            try:
                body = json.loads(body, strict=False)
            except ValueError:
                logger.error(
                    'Value error while converting plain text body into json.')
            return body
        else:
            return None

    return __extract(data, _body)


def _extract_attachments(client, data):
    """
    Test the content of an email, and pull out attachments

   :param IMAPClient client: The client object containing connection info
   :param dict data: Contains information describing the email message

   :return: list of the extracted attachments for the email
   :rtype: list
    """

    def _attachment(email_part):
        # TODO other types? application/octet-stream perhaps?
        acceptable_content_type = [
            'application/json',
            'text/plain',
            'text/html',
        ]
        # check if this part is an attachment
        if email_part.get('Content-Disposition') is not None:
            # TODO: better validation of this
            # check its content_type
            content_type = email_part.get_content_type()
            if content_type in acceptable_content_type:
                # decode raw base64 encoded bytes to a string
                attachment = (email_part.get_payload(decode=True)
                              .decode('utf-8'))
                # try to convert any json automatically
                if content_type.lower() == 'application/json':
                    try:
                        attachment = json.loads(attachment, strict=False)
                    except ValueError:
                        logger.error('Error while converting json.')
                return attachment
        else:
            return None

    return __extract(data, _attachment)


def _move_email(client, uid, src_folder, dest_folder):
    """
    Moves an email from src to dest folder

   :param IMAPClient client: The client object containing connection info
   :param int uid: identifier for the email
   :param str src_folder: name of the source folder
   :param str dest_folder: name of the dest folder
    """
    client.select_folder(src_folder)
    client.copy(uid, dest_folder)
    client.delete_messages(uid)
