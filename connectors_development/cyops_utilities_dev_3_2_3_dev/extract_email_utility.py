import email
import uuid
import os
import json
import base64
import datetime
from email import policy
from django.conf import settings
from connectors.core.connector import get_logger, ConnectorError
from .files import calculate_hashes
from .errors.error_constants import *
from collections import OrderedDict
from .builtins import extract_artifacts
from email.message import EmailMessage

try:
    extract_email_metadata_legacy = settings.APPLICATION_CONFIG.getboolean('connector_configuration',
                                                                       'extract_email_metadata_legacy', fallback=False)
except:
    extract_email_metadata_legacy = False

logger = get_logger("cyops_utilities.email_extract")

try:
    DISPLAY_SIZE_LIMIT = int(settings.APPLICATION_CONFIG.get('connector_configuration', 'email_character_count_max', fallback=100000))
except:
    DISPLAY_SIZE_LIMIT = 100000


def _create_file(data, file_extension='', filename=''):
    if not filename:
        filename = uuid.uuid4().hex + file_extension

    file_path = os.path.join(settings.TMP_FILE_ROOT, filename)

    mode = 'w{}'.format('b' if type(data) is bytes else '')
    try:
        with open(file_path, mode) as fp:
            fp.write(data)
    except Exception as e:
        logger.info('file operation error %s' % e)

    return filename


def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial


def _create_email(email_data):
    try:
        file_voucher = uuid.UUID(email_data).hex
        email_data = _fetch_email_from_disk(file_voucher)
    except Exception:
        pass

    if not type(email_data) == str and not type(email_data) == bytes:
        logger.error('Email data must be string or bytes')
        raise ConnectorError('Email data must be string or bytes')

    if type(email_data) == str:
        # this can help when trying to parse an email that was extracted as an
        # attachment from another email.
        try:
            email_data = email_data.encode('utf-8').decode('unicode_escape')
        except Exception:
            pass

    # create an Email object from the str data
    try:
        eml = email.message_from_string(email_data,
                                        _class=email.message.EmailMessage,
                                        policy=policy.SMTP)
    except TypeError:
        eml = email.message_from_bytes(email_data,
                                       _class=email.message.EmailMessage,
                                       policy=policy.SMTP)
    if eml.defects:
        logger.warn('email defects found when parsing: ')
        logger.warn(str(eml.defects))
    # from email.iterators import _structure
    # logger.debug('Email structure: ')
    # logger.debug(_structure(eml))
    return eml


def _fetch_email_from_disk(file_voucher):
    with open(os.path.join(settings.TMP_FILE_ROOT, file_voucher), 'rb') as fp:
        msg = fp.read()
    return msg


def _email_headers_to_dict(email_headers):
    """
    Turns the headers into a json serializable form that allows for duplicate
    keys. The value of said keys is turned into a list if a duplicate is
    found. This allows the headers to be json serialized, while still
    maintaining the same information as the python header data structure.
    See:
      https://docs.python.org/3.4/library/email.message.html\
              #email.message.Message.__len__

    in the stdlib
    """
    headers = {}
    for k, v in email_headers:
        key = k.lower()
        if key in headers and type(headers[key]) is list:
            headers[key].append(v)
        elif key in headers:
            headers[key] = [headers[key], v]
        else:
            headers[key] = v
    return headers


def _extract_body_parts(eml, parse_inline_image=False):
    def _extract(part_type):
        part = eml.get_body(preferencelist=(part_type,))

        if not part:
            return ''
        else:
            payload = _maybe_decode(
                part.get_payload(decode=True), part.get_content_charset()
            )[:DISPLAY_SIZE_LIMIT]
            return payload

    inline_images = []
    if parse_inline_image:
        inline_images = extract_inline_images(eml, inline_images)

    plain = _extract('plain')
    try:
        json_body = json.loads(plain, strict=False)
    except Exception:
        json_body = None

    html = _extract('html')

    for images in inline_images:
        html = html.replace('\"{}\"'.format(images.get('cid')), images.get('img_data'))

    return {
        'text': plain,
        'html': html,
        'json': json_body,
    }


def _maybe_decode(data, charset=None):
    if type(data) != bytes:
        return data

    charsets = [charset, 'utf-8', 'ascii', 'latin-1']
    for cs in charsets:
        try:
            return data.decode(cs)
        except Exception:
            continue
    return data


def my_iter_attachments(eml, level_count):
    """
    "iter_attachments():

    skip the first occurrence of each of text/plain, text/html,
    multipart/related, or multipart/alternative (unless they are explicitly
    marked as attachments via Content-Disposition: attachment), and return all
    remaining parts."

    t. python docs

    also 3.4.5 when
    """

    def is_attachment(part):
        c_d = part.get('content-disposition')
        if c_d is None:
            return False
        return c_d.content_disposition == 'attachment'

    maintype, subtype = eml.get_content_type().split('/')
    if maintype != 'multipart' or subtype == 'alternative':
        return
    parts = eml.get_payload()
    if maintype == 'multipart' and subtype == 'related':
        start = eml.get_param('start')
        if start:
            found = False
            attachments = []
            for part in parts:
                if part.get('content-id') == start:
                    found = True
                else:
                    attachments.append(part)
            if found:
                yield from attachments
                return
        parts.pop(0)
        yield from parts
        return
    seen = []
    for part in parts:
        maintype, subtype = part.get_content_type().split('/')
        if ((maintype, subtype) in eml._body_types and
                not is_attachment(part) and subtype not in seen):
            seen.append(subtype)
            continue
        yield part


def optimize_output(data):
    if isinstance(data.get('body', None), list):
        for body_key, body_value in enumerate(data['body']):
            data['body'][body_key] = {'content': body_value.get('content', '')}
    if isinstance(data.get('body', ''), str):
        body = [{'content': data.get('body', '')}]
        data['body'] = body
    attachments = data.pop('attachment', [])
    if attachments:
        for attachment in attachments:
            filename = attachment.pop('filename', None)
            if filename:
                attachment['file'] = filename
            generated_hash = attachment.get('hash', None)
            if generated_hash:
                attachment['metadata'] = attachment.pop('hash', None)
                attachment['metadata']['filename'] = filename
            elif filename:
                filepath = os.path.join(settings.TMP_FILE_ROOT, filename)
                attachment['metadata'] = calculate_hashes(filepath)
                attachment['metadata']['filename'] = filename
            if attachment.get('parsed_attachment_data', None):
                body = attachment.get('parsed_attachment_data').get('body', '')
                if isinstance(body, list):
                    for body_key, body_value in enumerate(body):
                        body[body_key] = {'content': body_value.get('content', '')}
                    attachment['parsed_attachment_data']['body'] = body
                if isinstance(body, str):
                    attachment['parsed_attachment_data']['body'] = [{'content': body}]
    data['attachments'] = attachments
    if not data.get('headers', None):
        data['headers'] = data.pop('header', None)


def getExplodedEmailFile(extract_attachment, attachment_type, optimize):
    if attachment_type == 'eml':
        body, bodyMetadata = get_eml_body(extract_attachment.get('body', []), optimize)
        header, headerMetadata = get_eml_header(extract_attachment.get('headers', {}))
    elif attachment_type == 'msg':
        body, bodyMetadata = get_msg_body(extract_attachment.get('body', []), optimize)
        header, headerMetadata = get_msg_header(extract_attachment.get('headers', []))
    attachment = extract_attachment.pop('attachments', None)
    extract_attachment['body'] = bodyMetadata
    extract_attachment['headers'] = headerMetadata
    return OrderedDict({"body": body, "headers": header, "attachments": attachment, "metadata": extract_attachment})


def get_eml_body(body, optimize):
    extract_body = []
    if optimize:
        return body, []
    for key, bobyObject in enumerate(body):
        if bobyObject["content_type"] != 'text/html':
            # just check for html
            extracted_content = bobyObject.get('content', "")
            try:
                extracted_indicator = extract_artifacts(extracted_content).get('unified_result', {})
                extract_body.append({"content": extracted_content, "indicators": extracted_indicator})
            except Exception as e:
                logger.error("Error occurred while extracting the indicators from body ERROR :: {0} ".format(str(e)))
            del body[key]
    return extract_body, body


def get_eml_header(header):
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

    if not extract_email_metadata_legacy:
        header_template['to'] = ""
        header_template['message-id'] = ""

    outer_header_keys = {
        "to",
        "cc",
        "bcc"
    }
    extract_header = {}

    headerObject = header.get('header', {})

    if headerObject:
        for header_key, header_value in header_template.items():
            if header_key in outer_header_keys:
                extract_header_value = header.get(header_key, header_value)
                header.pop(header_key, None)
            else:
                extract_header_value = headerObject.get(header_key, header_value)
            if not type(header_value) == type(extract_header_value):
                if isinstance(header_value, str) and isinstance(extract_header_value, list):
                    temp_string = ','
                    extract_header_value = temp_string.join(extract_header_value)
                elif isinstance(header_value, list) and isinstance(extract_header_value, str):
                    extract_header_value = extract_header_value.split(',')
            extract_header[header_key] = extract_header_value
            headerObject.pop(header_key, None)
        header['header'] = headerObject
    return extract_header, header


def get_msg_body(body, optimize):
    extract_body = {}
    extracted_content = body
    if optimize:
        return body, []
    try:
        extracted_indicator = extract_artifacts(extracted_content).get('unified_result', {})
        extract_body = {"content": extracted_content, "indicators": extracted_indicator}
    except Exception as e:
        logger.error("Error occurred while extracting the indicators from body ERROR :: {0} ".format(str(e)))
    return extract_body, []


def get_msg_header(header):
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
    header_mapping = {
        "received": "Received",
        "subject": "Subject",
        "message-id": "Message-ID",
        "return-path": "Return-Path"
    }
    extract_header = {}
    for header_key, header_value in header_template.items():
        get_header_key = header_key
        if header_key in header_mapping:
            get_header_key = header_mapping.get(header_key)
        extract_header_value = header.get(get_header_key, header_value)
        if not type(header_value) == type(extract_header_value):
            if isinstance(header_value, str) and isinstance(extract_header_value, list):
                if len(extract_header_value) == 1:
                    extract_header_value = extract_header_value[0]
                else:
                    temp_string = ''
                    extract_header_value = temp_string.join(extract_header_value)
            elif isinstance(header_value, list) and isinstance(extract_header_value, str):
                extract_header_value = extract_header_value.split(',')
        extract_header[header_key] = extract_header_value
        header.pop(get_header_key, None)
    return extract_header, header


def is_eml_msg_file(file_extension, filename=""):
    if file_extension.strip('.') == 'eml' or '.eml' in file_extension or '.eml' in filename:
        return {'result':True, 'filetype':'eml'}
    elif file_extension.strip('.') == 'msg' or '.msg' in file_extension or '.msg' in filename:
        return {'result': True, 'filetype': 'msg'}
    else:
        return {'result': False, 'filetype': file_extension}


def extract_inline_images(email, inline_images):
    images = {}
    if email.is_multipart():
        list_payload = email.get_payload()
        for payload in list_payload:
            if isinstance(payload, EmailMessage):
                payload_content_type = payload.get_content_type()
                if 'multipart/' in payload_content_type or 'text/' in payload_content_type:
                    extract_inline_images(payload, inline_images)
                content_disposition = payload.get('Content-Disposition')
                if content_disposition is not None:
                    disposition_type = get_content_disposition(payload)
                    if disposition_type == 'inline':
                        content_id = 'cid:' + str(payload.get('Content-ID')).strip('>').strip('<')
                        content_type = str(payload.get_content_type())
                        try:
                            img_data = 'data:{};base64,'.format(content_type) + base64.b64encode(
                                payload.get_content()).decode('utf-8')
                        except TypeError:
                            img_data = 'data:{};base64,'.format(content_type) + base64.b64encode(
                                payload.get_content().encode()).decode('utf-8')
                        images.update({'cid': content_id, 'img_data': img_data})
                        inline_images.append(images)
                        images = {}
    return inline_images

def _splitparam(param):
    a, sep, b = str(param).partition(';')
    if not sep:
        return a.strip(), None
    return a.strip(), b.strip()


def get_content_disposition(email):
    value = email.get('content-disposition')
    if value is None:
        return None
    c_d = _splitparam(value)[0].lower()
    return c_d