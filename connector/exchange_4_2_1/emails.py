""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import base64, email, json, os, uuid
from email import policy
from email.message import EmailMessage
from mimetypes import guess_extension
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import FileMetadata, save_file_in_env, calculate_hashes, \
    extract_email_metadata, extract_email_metadata_new
from .exchange_const import EML_TYPE, MSG_TYPE, TMP_FILE_ROOT
from .exchange_const import ext_lst
from .msg_to_eml import load
import re

logger = get_logger('exchange')


def _email_headers_to_dict(email_headers, updated_headers=False):
    try:
        headers = {}
        for k, v in email_headers:
            if k in headers and type(headers[k]) is list:
                headers[k.lower() if updated_headers else k].append(v)
            elif k in headers:
                headers[k.lower() if updated_headers else k] = [headers[k], v]
            else:
                headers[k.lower() if updated_headers else k] = v
        return headers
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


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


def _extract_body_parts(eml, parse_inline):
    def _extract(part_type):
        try:
            part = eml.get_body(preferencelist=(part_type))
            if not part:
                return ''
            else:
                payload = _maybe_decode(
                    part.get_payload(decode=True), part.get_content_charset()
                )
                return payload
        except Exception as err:
            logger.exception('An exception occurred {}'.format(str(err)))
            raise ConnectorError('An exception occurred {}'.format(str(err)))

    inline_images = []
    if parse_inline:
        inline_images = extract_inline_images(eml, inline_images)
    plain = _extract('plain')

    try:
        json_body = json.loads(plain, strict=False)
    except Exception:
        json_body = None

    html = _extract('html')
    if parse_inline:
        for images in inline_images:
            html = html.replace('\"{}\"'.format(images.get('cid')), images.get('img_data'))
    try:
        html = html.encode('utf-8')
    except Exception:
        logger.warn('Could not encode html as utf-8')
        pass

    try:
        plain = plain.encode('utf-8')
    except Exception:
        logger.warn('Could not encode plain as utf-8')
        pass

    try:
        json_body = json_body.encode('utf-8')
    except Exception:
        logger.warn('Could not encode json_body as utf-8')
        pass
    return {
        'text': plain,
        'html': html,
        'json': json_body
    }


def _maybe_decode(data, charset=None):
    try:
        if type(data) != bytes:
            return data

        charsets = [charset, 'utf-8', 'ascii', 'latin-1']
        for cs in charsets:
            try:
                logger.debug('decodeing data in {} format'.format(str(cs)))
                return data.decode(cs)
            except Exception:
                logger.debug('faild decode data in {} format'.format(str(cs)))
                continue
        return data
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def clean_up_file(env, filename, metadata={}):
    try:
        save_file_in_env(env, filename, metadata)
    except Exception as e:
        logger.exception("error in clean up files from tmp: {}".format(e))


def extract_eml_msg_attachment_metadata(file_voucher, file_extension, updated_headers, **kwargs):
    try:
        env = kwargs.get('env', {})
        if file_extension[1:] == MSG_TYPE:
            res1 = load(TMP_FILE_ROOT + file_voucher)
            file_voucher = _create_file(str(res1))
            if updated_headers:
                res = extract_email_metadata_new(TMP_FILE_ROOT + file_voucher, EML_TYPE, **kwargs)
            else:
                res = extract_email_metadata(TMP_FILE_ROOT + file_voucher, EML_TYPE, **kwargs)
            clean_up_file(env, file_voucher)
        else:
            if updated_headers:
                res = extract_email_metadata_new(TMP_FILE_ROOT + file_voucher, file_extension[1:], **kwargs)
            else:
                res = extract_email_metadata(TMP_FILE_ROOT + file_voucher, file_extension[1:], **kwargs)
        return res
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def _extract_attachment_parts(eml, extract_attach_data, updated_headers, **kwargs):
    env = kwargs.get('env', {})
    parsed_attachment_data = []
    attachments_uuids = []
    attachments_list = []

    # env, and eml get closed over here
    def _extract_attachment(email_message):
        # get some metadata about the attachment
        content_type = email_message.get_content_type()
        charset = email_message.get_content_charset()

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

            if 'multipart/' in payload_content_type or 'text/' in payload_content_type:
                bytes_payload = tmp_payload
                try:
                    bytes_payload = bytes_payload.as_bytes(policy=policy.compat32)
                except AttributeError as err:
                    logger.exception(str(err))
            else:
                bytes_payload = email_message.as_string().encode('utf-8')
                content_type = tmp_payload.get_content_type()

        else:
            # decode=True will take care of quote-printable and base64 encoded
            # payloads. It should always return bytes (or None, for multipart
            # messages, but we handled that above)
            bytes_payload = email_message.get_payload(decode=True)

        content_disposition = get_content_disposition(email_message)
        if content_disposition == 'attachment':
            file_voucher = _create_file(bytes_payload)
            clean_up_file(env, file_voucher)
            content_length = len(bytes_payload)
            # text/* attachments
            if email_message.get_content_maintype() != 'text':
                text_payload = '<data expunged>'
            else:
                text_payload = _maybe_decode(bytes_payload, charset=charset)

            # json attachments
            json_payload = None
            if content_type == 'application/json':
                try:
                    text = _maybe_decode(bytes_payload, charset=charset)
                    json_payload = json.loads(text, strict=False)
                except Exception:
                    pass

            # format metadata for FileMetadata

            # only show the charset part if we actually have a charset, otherwise
            # just show the Content-Type
            content_charset = ('; charset="' + charset + '"') if charset else ''
            full_content_type = content_type + content_charset

            # pick out the filename from the email, or create something 'sensible'
            ext = guess_extension(content_type, strict=False) or '.¯\_(ツ)_/¯'
            if ext not in ext_lst:
                ext = '.eml'
            fallback_filename = 'attachment_{num}{ext}'.format(
                num=len(attachments_list) + 1,
                # FUN: this is non deterministic https://bugs.python.org/issue4963
                ext=ext
            )
            filename = email_message.get_filename(failobj=fallback_filename)
            filename, file_extension = os.path.splitext(filename)
            filename = filename.rstrip()
            file_extension = re.sub("[^A-Za-z0-9.\-]", "", file_extension)
            file_hashes = calculate_hashes(os.path.join(TMP_FILE_ROOT,
                                                        file_voucher))
            metadata = FileMetadata(filename+file_extension, content_length, full_content_type,
                                    file_hashes['md5'], file_hashes['sha1'],
                                    file_hashes['sha256'])
            try:
                if extract_attach_data:
                    if file_extension.strip('.') == EML_TYPE or file_extension.strip('.') == MSG_TYPE:
                        parsed_attachment_data.append(
                            extract_eml_msg_attachment_metadata(file_voucher,
                                                                file_extension, updated_headers, **kwargs))
            except Exception as e:
                logger.exception("error in extract_eml_msg_attachment_metadata: {}".format(e))
            try:
                text_payload = text_payload.encode('utf-8')
                json_payload = json_payload.encode('utf-8')
            except Exception:
                pass
            attachment = {
                'file': file_voucher,
                'text': text_payload,
                'json': json_payload,
                'metadata': dict(metadata._asdict())
            }
            attachments_uuids.append(file_voucher)
            attachments_list.append(attachment)
            # also save this file in the env so other file handling steps can use it
            clean_up_file(env, file_voucher, metadata)

    list(map(_extract_attachment, my_iter_attachments(eml)))

    return attachments_list, attachments_uuids, parsed_attachment_data


def _fetch_email_from_disk(file_voucher):
    try:
        with open(os.path.join(TMP_FILE_ROOT, file_voucher), 'rb') as fp:
            msg = fp.read()
        return msg
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def _create_email(email_data):
    try:
        file_voucher = uuid.UUID(email_data).hex
        email_data = _fetch_email_from_disk(file_voucher)
    except Exception:
        pass

    if not type(email_data) == str and not type(email_data) == bytes:
        logger.error('Email data must be string or bytes')
        raise ConnectorError('Email data must be string or bytes')

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
    return eml


def my_iter_attachments(eml):
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


def explode_email(email, parse_inline, extract_attach_data=False, updated_headers=False, **kwargs):
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
    try:
        parsed_attachment_data = []
        if type(email) == str or type(email) == bytes:
            email = _create_email(email)

        # extract headers
        headers = _email_headers_to_dict(email.items(), updated_headers)

        # extract body parts
        body = _extract_body_parts(email, parse_inline)

        # extract attachments
        try:
            attachment_list, uuids, parsed_attachment_data = _extract_attachment_parts(email, extract_attach_data,
                                                                                       updated_headers, **kwargs)
        except Exception as e:
            logger.exception("error in attachment extraction: {}".format(e))
            attachment_list = []
            uuids = []
            pass
        resp = {
            'raw': email.as_string(policy=policy.compat32),
            'headers': headers,
            'preamble': email.preamble or '',
            'body': body,
            'attachments': attachment_list,
            'attachment_files': uuids,
            "parsed_attachment_data": parsed_attachment_data,
            'epilogue': email.epilogue
        }
        if extract_attach_data:
            resp.update({'extract_attach_data': extract_attach_data})
        return resp
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


explode_email.__str__ = lambda: 'Dismantle Email'


def _create_file(data):
    try:
        filename = uuid.uuid4().hex
        file_path = os.path.join(TMP_FILE_ROOT, filename)

        mode = 'w{}'.format('b' if type(data) is bytes else '')

        with open(file_path, mode) as fp:
            fp.write(data)

        return filename
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def _parse_email_old(client, email_data, *args, **kwargs):
    try:
        return {
            'attachments': _extract_attachments(client, email_data),
            'body': _extract_body(client, email_data),
            'headers': _extract_headers(email_data),
        }
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def __extract(data, extract):
    """
    Massages the email information in data to a more usable format
   :param dict data: Contains information describing the email message
   :param Callable[str] extract: Function to extract / massage email data
   :return: list of massaged email data
   :rtype: list
    """
    # first, make an email.message out of the raw dict
    try:
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
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def _extract_headers(data):
    """
    Massages headers into a more workable dict
   :param dict data: Contains the headers in an unruly bytes format
   :return: dict of the headers
   :rtype: dict
    """
    try:
        raw_msg = data[b'RFC822']
        message = email.message_from_bytes(raw_msg)
        return dict(message.items())
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


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
                logger.error('Value error while converting plain text body into json.')
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
        try:
            acceptable_content_type = [
                'application/json',
                'text/plain',
                'text/html',
            ]
            if email_part.get('Content-Disposition') is not None:
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
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
        return __extract(data, _attachment)


