import os
import json
import base64
import random
import string
from email import policy
from mimetypes import guess_extension
from django.conf import settings
from connectors.core.connector import get_logger, ConnectorError
from .errors.error_constants import *
from .builtins import FileMetadata, save_file_in_env, calculate_hashes
from collections import OrderedDict
from extract_msg import Message
from extract_msg import Attachment as MsgAttachment
from imapclient.imapclient import decode_utf7
from email.message import Message as emlMessage
from .extract_email_utility import _create_file, _create_email, _email_headers_to_dict, _extract_body_parts, \
    my_iter_attachments, is_eml_msg_file, \
    get_content_disposition

logger = get_logger("cyops_utilities.email_extract")

try:
    DISPLAY_SIZE_LIMIT = int(
        settings.APPLICATION_CONFIG.get('connector_configuration', 'email_character_count_max', fallback=100000))
except:
    DISPLAY_SIZE_LIMIT = 100000


# Extracting the EML file's attachment in depricated output format
def find_attachments(message, attachments, level_count, *args, **kwargs):
    env = kwargs.get('env', {})
    for message in message.walk():
        filename = message.get_filename()
        is_eml_file = False
        if not filename:
            continue
        filename = ' '.join(filename.split())
        try:
            filepath = os.path.join(settings.TMP_FILE_ROOT, filename)
            decode_type = message.get('Content-Transfer-Encoding', False)
            bytes_payload = b''
            if message.is_multipart():
                tmp_payload = message.get_payload()[0]
                payload_content_type = tmp_payload.get_content_type()

                if payload_content_type == 'multipart/alternative' or payload_content_type == 'multipart/related' or payload_content_type == 'multipart/mixed' or payload_content_type == 'multipart/report':
                    bytes_payload = tmp_payload
                else:
                    bytes_payload = tmp_payload.get_payload()
                    content_type = tmp_payload.get_content_type()

                try:
                    if isinstance(bytes_payload, emlMessage):
                        is_eml_file = True
                    bytes_payload = bytes_payload.as_bytes(policy=policy.compat32)
                except AttributeError:
                    logger.error('Attribute error.')
            else:
                bytes_payload = message.get_payload(decode=True)

            if decode_type and decode_type.lower() == 'base64':
                try:
                    if isinstance(bytes_payload, str):
                        bytes_payload = base64.b64decode(bytes_payload)
                except Exception as e:
                    logger.error("Error occurred in decoding the email attachted {0}".format(str(e)))

            filename = _create_file(bytes_payload, filename=filename)
            save_file_in_env(env=env, filename=filename)
            file_name, filetype = os.path.splitext(filename)
            filetype = filetype.strip('.')
            if filetype == 'eml' or filetype == 'msg':
                inter_extracted_email = extract_email(filepath=filename, filetype=filetype,
                                                      level_count=level_count, *args, **kwargs)
                for attachment in attachments:
                    if attachment.get('filename', '') == filename:
                        attachment['parsed_attachment_data'] = inter_extracted_email
                        break

            elif is_eml_file:
                inter_extracted_email = extract_email(filepath=filename, filetype='eml',
                                                      level_count=level_count, *args, **kwargs)
                for attachment in attachments:
                    if attachment.get('filename', '') == filename:
                        attachment['parsed_attachment_data'] = inter_extracted_email
                        break


        except Exception as e:
            logger.error("Error occurred while extracting the attachment {0} ERROR :: {1}".format(filepath, str(e)))


# for the new format of extracting eml/msg file
def extract_email(filepath, filetype, level_count=0, optimize=False, *args, **kwargs):
    if not bool(filetype):
        filename, filetype = os.path.splitext(filepath)
        filetype = filetype.strip('.')

    if not os.path.exists(filepath):
        filepath = os.path.join(settings.TMP_FILE_ROOT, filepath)
        if not os.path.exists(filepath):
            raise ConnectorError('%s' % cs_connector_utility_3.format(filepath))

    if filetype == 'msg':
        return extract_from_msg_file(filepath, level_count, *args, **kwargs)
    elif filetype == 'eml':
        extracted_eml_file = extract_eml_file(filepath, level_count, optimize, *args, **kwargs)
        return extracted_eml_file
    else:
        raise ConnectorError("Invalid input :: Invalid or no File Type provided.")


def extract_eml_file(filepath, level_count, optimize, *args, **kwargs):
    with open(filepath, 'rb') as fhdl:
        raw_email = fhdl.read()
        level_count += 1
        return explode_email(raw_email, level_count, optimize, *args, **kwargs)


# for extracting eml file in new format. Also used by IMAP
def explode_email(email, level_count=0, optimize=False, parse_inline_image=False, *args, **kwargs):
    """
    Breaks apart the various sections of an email. Returns a dictionary with
    parts of the email as keys::

        {
            'file': <reference to the attachment file stored on disk>,
            'headers': <a dictionary containing headers>
            'preamble': "<extraneous data between headers and body>"
            'body': {
                'text': "<the plain text of the email, if any>"
                'html': "<html content of the email, if any>",
                'json': <dictionary containing the plain text, as json>
            },
            'attachment_files': [<a list of attachment references>]
            'attachments': [<list of data for found attachments>]
            'epilogue': "<extraneous data at the end of the email>"
        }

    Some of the above values may be truncated if they are too large. Also, the
    headers field may store multiple values at the same key. If the same header
    is specified multiple times in an email, each value will be put into a list.
    The headers dictionary will return that list when accessed with said key.

    Attachment data in turn has its own structure::

        {
            'file': <a file reference>
            'text': "<a string if the content type was plain text>"
            'json': "<a dictionary if the text could be parsed as json>"
            'metadata': FileMetadata(filename, content-length, content-type,
            md5, sha1, sha256)
        }

    If the attachment contains plain text or json, and it is not too large, the
    `text` and `json` fields will be populated with their respective content.
    Otherwise, the attachment can be referenced by its handle. This handle can
    be found in either `attachments` or `attachment_files` in the above email
    parts. The handle also gets stored in the env, so that other file handling
    steps can use it.

   :param email: An email message to parse and break up
   :return: email parts as a dictionary
   :rtype: dict
    """
    env = kwargs.get('env', {})

    if type(email) == str or type(email) == bytes:
        email = _create_email(email)

    # extract headers
    headers = _email_headers_to_dict(email.items())

    # extract body parts
    body = _extract_body_parts(email, parse_inline_image)

    # extract attachments
    if level_count < 5:
        attachment_list, uuids, parsed_attachment_data = _extract_attachment_parts(email, optimize, level_count,
                                                                                   parse_inline_image,
                                                                                   **kwargs)

    # create email file
    for charset in ['UTF-8', 'iso-8859-1']:
        try:
            email_filename = _create_file(email.as_bytes(policy=policy.compat32).decode(encoding=charset))
            break
        except UnicodeDecodeError:
            continue
    else:
        email_filename = _create_file(email.as_bytes(policy=policy.compat32))
    save_file_in_env(env, email_filename)
    return OrderedDict({
        'file': email_filename,
        'headers': headers,
        'preamble': email.preamble or '',
        'body': body,
        'attachments': attachment_list,
        'attachment_files': uuids,
        'parsed_attachment_data': parsed_attachment_data,
        'epilogue': email.epilogue
    })


def _extract_attachment_parts(eml, optimize=False, level_count=0, parse_inline_image=False, *args, **kwargs):
    env = kwargs.get('env', {})
    attachments_uuids = []
    attachments_list = []
    parsed_attachment_data = []

    # env, and eml get closed over here
    def _extract_attachment(email_message):
        # get some metadata about the attachment
        content_type = email_message.get_content_type()
        charset = email_message.get_content_charset()
        file_name = email_message.get_filename()
        file_extension = ""
        extract_attachment = {}

        if file_name:
            filename, file_extension = os.path.splitext(file_name)
        decode_type = email_message.get('Content-Transfer-Encoding', False)

        # decode the payload
        bytes_payload = b''
        if email_message.is_multipart():
            # if we already determined this was an attachment (which we did
            # since we are in this function), we won't descend any further into
            # the multipart payload, but instead return it as a single
            # attachment. This avoids a problem where e.g. the `message/rfc822`
            # content type counts as multipart, even though we wish to treat the
            # whole attachment as one file.
            tmp_payload = email_message.get_payload()[0]
            payload_content_type = tmp_payload.get_content_type()

            if payload_content_type == 'multipart/alternative' or payload_content_type == 'multipart/related' or payload_content_type == 'multipart/mixed' or payload_content_type == 'multipart/report':
                bytes_payload = tmp_payload
            else:
                bytes_payload = tmp_payload.get_content()
                content_type = tmp_payload.get_content_type()

            try:
                bytes_payload = bytes_payload.as_bytes(policy=policy.compat32)
            except AttributeError:
                logger.error('Attribute error.')
        else:
            # decode=True will take care of quote-printable and base64 encoded
            # payloads. It should always return bytes (or None, for multipart
            # messages, but we handled that above)
            bytes_payload = email_message.get_payload(decode=True)

        # make a file out of the decoded payload
        if decode_type and decode_type.lower() == 'base64':
            try:
                if isinstance(bytes_payload, str):
                    bytes_payload = base64.b64decode(bytes_payload)
            except Exception as e:
                logger.error("Error occurred in decoding the email attachted {0}".format(str(e)))

        content_disposition = get_content_disposition(email_message)
        if content_disposition != 'inline' or not parse_inline_image:
            file_voucher = _create_file(bytes_payload, file_extension)
            content_length = len(bytes_payload)

            # prepare payload for use in env
            if content_length > DISPLAY_SIZE_LIMIT:
                bytes_payload = b'Attachment too large to display'

            # format metadata for FileMetadata

            # only show the charset part if we actually have a charset, otherwise
            # just show the Content-Type
            content_charset = ('; charset="' + charset + '"') if charset else ''
            full_content_type = content_type + content_charset

            # pick out the filename from the email, or create something 'sensible'
            fallback_filename = 'attachment_{num}{ext}'.format(
                num=len(attachments_list) + 1,
                # FUN: this is non deterministic https://bugs.python.org/issue4963
                ext=guess_extension(content_type, strict=False) or '.¯\_(ツ)_/¯'
            )
            filename = email_message.get_filename(failobj=fallback_filename)
            file_hashes = calculate_hashes(os.path.join(settings.TMP_FILE_ROOT,
                                                        file_voucher))
            metadata = FileMetadata(filename, content_length, full_content_type,
                                    file_hashes['md5'], file_hashes['sha1'],
                                    file_hashes['sha256'])

            if filename and not bool(file_extension):
                filename, file_extension = os.path.splitext(filename)
            is_eml_msg_file_result = is_eml_msg_file(file_extension, filename)
            if is_eml_msg_file_result.get('result', False):
                try:
                    kwargs['optimize'] = optimize
                    extract_attachment = extract_email(file_voucher,
                                                       is_eml_msg_file_result.get('filetype'),
                                                       level_count=level_count,
                                                       *args, **kwargs)
                    parsed_attachment_data.append(extract_attachment)
                except Exception as e:
                    logger.error("Error occurred while extracting email file attached ERROR :: {0}".format(str(e)))

            # add attachment to our ongoing list and dict
            attachment = {
                'file': file_voucher,
                'file_type': file_extension.strip('.'),
                'metadata': dict(metadata._asdict())
            }

            attachments_uuids.append(file_voucher)
            attachments_list.append(attachment)

            # also save this file in the env so other file handling steps can
            # use it
            save_file_in_env(env, file_voucher, metadata)

    list(map(_extract_attachment, my_iter_attachments(eml, level_count)))

    return attachments_list, attachments_uuids, parsed_attachment_data


# Parsing for MSG file

def extract_from_msg_file(filepath, level_count, *args, **kwargs):
    env = kwargs.get('env', {})
    m = MyMessage(path=filepath, attachmentClass=Attachment)
    extracted_mail = m.save(customPath=settings.TMP_FILE_ROOT, env=env, level_count=level_count)
    res = json.loads(json.dumps(extracted_mail).replace('\\u0000', ''))
    return res


class MyMessage(Message):
    def save(self, toJson=False, useFileName=False, raw=False, ContentId=False, customPath=None, customFilename=None,
             env={}, level_count=0):
        attachmentsData = []
        parsed_attachment = []
        attachment_files = []
        # Save the attachments
        level_count = level_count + 1
        for attachment in self.attachments:
            attachment_data, attachment_file, parsed_attachment_data = attachment.save(ContentId, toJson,
                                                                                       customPath=customPath,
                                                                                       env=env,
                                                                                       level_count=level_count)
            attachmentsData.append(attachment_data)
            if parsed_attachment_data:
                parsed_attachment.append(parsed_attachment_data)
            attachment_files.append(attachment_file)
        header = dict(self.header) if self.header else {}
        header_required_keys = ['to', 'cc', 'from', 'date', 'subject', 'message-id']
        new_header = {}
        for k, v in header.items():
            key = k.lower()
            if key in header_required_keys:
                new_header[key] = v
                header_required_keys.remove(key)
            else:
                new_header[k] = v
        for header_key in header_required_keys:
            if hasattr(self, header_key):
                header_value = getattr(self, header_key)
                new_header[header_key] = header_value

        body = {}

        try:
            body['html'] = self.htmlBody.decode("utf-8") if self.htmlBody else None
        except Exception as e:
            body['html'] = decode_utf7(self.htmlBody)

        body['text'] = decode_utf7(self.body)
        body['json'] = None
        emailObj = {
            'body': body,
            'headers': new_header,
            'attachments': attachmentsData,
            'attachment_files': attachment_files,
            'parsed_attachment_data': parsed_attachment
        }
        return emailObj


class Attachment(MsgAttachment):
    def save(self, contentId=False, json=False, useFileName=False, raw=False, customPath=None, customFilename=None,
             env={}, level_count=0):
        # Check if the user has specified a custom filename
        filename = None
        attachment = {}
        parsed_attachment_data = {}
        if customFilename:
            filename = customFilename
        else:
            # If not...
            # Check if user wants to save the file under the Content-id
            if contentId:
                filename = self.cid
            # If filename is None at this point, use long filename as first preference
            if filename is None:
                filename = self.longFilename
            # Otherwise use the short filename
            if filename is None:
                filename = self.shortFilename
            # Otherwise just make something up!
            if filename is None:
                filename = 'UnknownFilename ' + \
                           ''.join(random.choice(string.ascii_uppercase + string.digits)
                                   for _ in range(5)) + '.bin'
                self.name = filename
        temp_filetype = ''
        filetype = self.type
        if hasattr(filetype, 'name'):
            filetype = filetype.name.lower()
        if not filetype in filename and filetype != 'data':
            filename = filename + '.' + filetype
        elif filetype == 'data':
            temp_filename, temp_filetype = os.path.splitext(filename)
            is_eml_msg_file_result = is_eml_msg_file(temp_filetype, temp_filename)
            if is_eml_msg_file_result.get('result', False):
                filetype = temp_filetype = is_eml_msg_file_result.get('filetype')

        if customPath:
            filepath = os.path.join(customPath, filename)

        if filetype == "data" or filetype == "eml" or temp_filetype == 'msg':
            with open(filepath, 'wb') as f:
                f.write(self.__data)
            save_file_in_env(env=env, filename=filename)
            if filetype == 'eml' or filetype == 'msg':
                if level_count < 5:
                    extracted_email = extract_email(filepath=filename, filetype=filetype,
                                                                 level_count=level_count, env=env)
                    parsed_attachment_data = extracted_email
        else:
            # For no filetype and file content is not a data i.e not a image, document, textfile, musicfile etc
            extracted_email = self.saveEmbededMessage(contentId, json, useFileName, raw, customPath, customFilename,
                                                      level_count)
            parsed_attachment_data = extracted_email

        try:
            metadata = {}
            file_hashes = calculate_hashes(os.path.join(settings.TMP_FILE_ROOT,
                                                        filename))
            metadata = FileMetadata(filename, None, filetype,
                                    file_hashes['md5'], file_hashes['sha1'],
                                    file_hashes['sha256'])
        except Exception as e:
            logger.warn('Error while calculating hash values for file {0} ERROR: {1}'.format(filename, str(e)))

        attachment['file'] = filename
        attachment['metadata'] = dict(metadata._asdict())
        attachment['file_type'] = filetype
        return attachment, filename, parsed_attachment_data

    def saveEmbededMessage(self, contentId=False, json=False, useFileName=False, raw=False, customPath=None,
                           customFilename=None, level_count=0):
        """
        Seperate function from save to allow it to
        easily be overridden by a subclass.
        """
        extracted_email = {}
        if level_count < 5:
            try:
                extracted_email = self.data.save(json, useFileName, raw, contentId, customPath, customFilename)
            except Exception as e:
                logger.error('Error while extracting the attachment {0} ERROR: {1}'.format(self.name, str(e)))
        return extracted_email
