import hashlib
import os
import shutil
import uuid
import json
from collections import namedtuple
from zipfile import ZipFile
from datetime import datetime
import pyminizip
import requests
from connectors.core.connector import get_logger, ConnectorError
from django.conf import settings
from django.http.multipartparser import parse_header
from integrations.crudhub import make_file_upload_request
from requests_toolbelt import MultipartEncoder
from requests_toolbelt.downloadutils import stream
from integrations.crudhub import make_request
from .crudhub import make_cyops_request, urlparse
from .errors.error_constants import *
from .utils import maybe_json_or_raise, cyops_version
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from os.path import join

logger = get_logger('cyops_utilities.builtins.files')

# File handling
FileMetadata = namedtuple('FileMetadata', ['filename',
                                           'content_length',
                                           'content_type',
                                           'md5',
                                           'sha1',
                                           'sha256'])


def download_file_from_url(url, username=None, password=None,
                           request_headers=None, *args, **kwargs):
    """
    Downloads a file from a url. Optionally takes username/password arguments
    for use in basic authentication schemes. Otherwise, if a file is public,
    these arguments are not required (obviously).
    :param str url: Absolute path to the file as an URL
    :param str username: username for basic auth
    :param str password: password for basic auth
    :param dict request_headers: A dictionary of headers to add to the requests
        call
    :return: filename
    :rtype: str
    """
    logger.info('download_file_from_url with url %s', url)
    if username or password:
        auth = (username, password)
    else:
        auth = None
    env = kwargs.get('env', {})
    headers = request_headers or {}
    logger.info("Download file from URL %s", url)
    filename, metadata = download_file(url, auth=auth, headers=headers,
                                       *args, **kwargs)
    save_file_in_env(env, filename, metadata=metadata)
    res = dict(metadata._asdict())
    res.update({'cyops_file_path': filename})
    return res


def download_file(iri, auth=None, headers=None, *args, **kwargs):
    """
    Downloads a file from an arbitrary iri over http.
    :param str iri: Absolute path to the file as an IRI
    :param Callable auth: something that implements requests' auth requirements
    :param Callable response_reader: this should be a function that drains\
            response.content and returns a filename.
    :param Callable file_hash_calculator: this should be a function that
            calculates file hashes like md5, sha1, sha256
    :return: filename and file metadata
    :rtype: tuple
    """
    logger.info('download_file from arbitrary iri over http IRI: %s', iri)
    if headers is None:
        headers = {}

    request_args = {
        'stream': True,
        'verify': False,
        'headers': headers,
    }
    # see body-content-workflow at
    # http://docs.python-requests.org/en/master/user/advanced/
    if kwargs.get('is_crudhub_endpoint'):
        request_args['method'] = 'GET'
        request_args['iri'] = iri
        request_args['validate_response'] = False
        response = make_cyops_request(**request_args)
    else:
        request_args['url'] = iri
        request_args['auth'] = auth
        response = requests.get(**request_args)
    # error handling first
    if not response.ok:
        result = {
            'status_code': response.status_code,
            'message': response.content,
        }
        raise ConnectorError(result)

    # consume the response
    file_path = read_response_to_file(response)

    # get filename from the absolute file path
    filename = os.path.basename(file_path)

    content_disposition = response.headers.get('content-disposition', '')
    try:
        # parse_headers expects a latin-1 header byte string
        content_disposition = content_disposition.encode('iso-8859-1')
    except AttributeError:
        logger.error(cs_connector_utility_8)

    # e.g. ('conntent-disposition: attachment', {'filename': b'\xad'})
    key, filename_dict = parse_header(content_disposition)

    # get and convert filename from the filename dict
    cd_filename = filename_dict.get('filename', None)
    try:
        content_disposition_filename = cd_filename.decode('utf-8')
    except AttributeError:
        content_disposition_filename = cd_filename

    # if that didn't work, guess the filename from the url
    if not content_disposition_filename:
        content_disposition_filename = response.url.split('/')[-1]

    # if *that* didn't work, use the generated uuid
    content_disposition_filename = content_disposition_filename or filename

    # extract other header metadata, if available
    file_size = response.headers.get('content-length', 'unknown')
    content_type = response.headers.get('content-type', 'unknown')
    file_hashes = calculate_hashes(file_path)
    # construct full file metadata tuple
    metadata = FileMetadata(content_disposition_filename,
                            file_size, content_type, file_hashes['md5'],
                            file_hashes['sha1'], file_hashes['sha256'])

    return filename, metadata


def create_file_from_string(contents, filename=None, *args, **kwargs):
    """
    Creates a (temporary) file filled with `contents`. The content-type of this
    file will be 'text/plain'
    :param str contents: The text contents of the file
    :return: filename
    :rtype: str
    """
    mode = 'w'
    if isinstance(contents, (dict, list)):
        copy_contents = json.dumps(contents)
        try:
            json.loads(copy_contents)
            contents = copy_contents
        except Exception as e:
            contents = str(contents)

    elif isinstance(contents, bytes):
        mode = 'wb'

    if not filename:
        filename = uuid.uuid4().hex
    path = os.path.join(settings.TMP_FILE_ROOT, filename)

    with open(path, mode=mode) as fp:
        fp.write(contents)

    file_hashes = calculate_hashes(path)
    metadata = FileMetadata(filename, os.path.getsize(path), 'text/plain',
                            file_hashes['md5'], file_hashes['sha1'],
                            file_hashes['sha256'])
    save_file_in_env(kwargs.get('env', {}), filename, metadata)

    return dict(metadata._asdict())


def read_response_to_file(response):
    # find the place we want to store files, and make sure it exists
    logger.info('Finding the place we want to store files')
    file_dir = settings.TMP_FILE_ROOT
    os.makedirs(file_dir, exist_ok=True)

    # random filename
    filename = uuid.uuid4().hex
    path = file_dir + filename

    # drains response.content and returns the name of the file it created
    filename = stream.stream_response_to_file(response, path=path)
    return filename


def upload_file_to_url(filename=None, url='', username=None, password=None,
                       request_headers=None, multipart_headers=None,
                       extra_multipart_fields=None, download_auth=None,
                       download_url=None, type=None, iri=None, *args, **kwargs):
    """
    Uploads a file, specified by a file handle uuid. Basic auth to
    the external endpoint is avaliable with the username and password fields.
    Customization of the multipart body is also avaliable the same as
    :class:`upload_file`.
    .. hint::
        There are also ~~super secret~~ kwargs (download_auth and download_url)
        that allow for downloading a file first. Don't rely on these sticking
        around though.
    :param str file: Name of file on the filesystem
    :param str url: The location to send the file to
    :param str username: username to use in basic auth of external system
    :param str password: password to use in basic auth of external system
    :param dict extra_multipart_fields: extra form data to put into the body
    :param dict request_headers: Headers added to the http request
    :param dict multipart_headers: Headers to add to the multipart body
    :param dict download_auth: Auth info for downloading file to upload
    :param str download_url: URL to download a file to upload.
    :return: Request response content
    :rtype: Any
    """
    auth = None
    env = kwargs.get('env', {})
    metadata = None

    if username or password:
        auth = (username, password)

    if not filename and download_url:
        filename, metadata = download_file(download_url, auth=download_auth,
                                           *args, **kwargs)
        save_file_in_env(env, filename, metadata)
        metadata = collect_file_metadata(filename, env)
    if not filename and iri:
        metadata = download_file_from_cyops(iri, None, *args, **kwargs)
        filename = metadata.get('cyops_file_path')

    if not filename:
        logger.error('%s' % cs_connector_utility_1.format("filename"))
        raise ConnectorError("%s" % cs_connector_utility_1.format("filename"))

    check_file_traversal(filename)
    metadata = metadata or collect_file_metadata(filename, env)

    file_path = os.path.join(settings.TMP_FILE_ROOT, filename)

    if not os.path.exists(file_path):
        raise ConnectorError(cs_connector_utility_3.format(file_path))

    return upload_file(open(file_path, 'rb'), url,
                       metadata=metadata, auth=auth,
                       request_headers=request_headers, multipart_headers=None,
                       extra_fields=extra_multipart_fields, *args, **kwargs)


def zip_and_protect_file(filename, target_filename, password=None, compress_level=0, *args, **kwargs):
    try:
        if 'api/3/' in filename:
            metadata = download_file_from_cyops(filename, None, *args, **kwargs)
            filename = metadata.get('cyops_file_path', None)

        check_file_traversal(filename)
        source_filepath = os.path.join(settings.TMP_FILE_ROOT, filename)
        target_filepath = os.path.join(settings.TMP_FILE_ROOT, target_filename)

        if not os.path.exists(source_filepath):
            logger.error(cs_connector_utility_3.format(source_filepath))
            raise ConnectorError(cs_connector_utility_3.format(source_filepath))
        if os.path.exists(target_filepath):
            logger.error(cs_connector_utility_19.format(target_filepath))
            raise ConnectorError(cs_connector_utility_19.format(target_filepath))
        if password:
            password = str(password)
        pyminizip.compress(
            source_filepath,
            None,
            target_filepath,
            password,
            int(compress_level))
        check_file_traversal(target_filepath)
        env = kwargs.get('env', {})
        save_file_in_env(env, target_filename)
        save_file_in_env(env, filename)
        return {"zip_filename": target_filename}
    except ConnectorError as e:
        raise ConnectorError(e)
    except Exception as e:
        logger.error(cs_connector_utility_20.format('zipping', str(e)))
        raise ConnectorError(cs_connector_utility_20.format('zipping', str(e)))


def unzip_protected_file(password=None, file_iri=None, file_name=None, *args, **kwargs):
    try:

        if file_name:
            pass
        elif file_iri:
            metadata = download_file_from_cyops(file_iri, None, *args, **kwargs)
            file_name = metadata.get('cyops_file_path', None)
        else:
            raise ConnectorError(cs_connector_utility_1.format('Filename or IRI'))

        source_filepath = os.path.join(settings.TMP_FILE_ROOT, file_name)
        target_filepath = os.path.join(settings.TMP_FILE_ROOT, datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f'))

        if not os.path.exists(source_filepath):
            logger.error(cs_connector_utility_3.format(source_filepath))
            raise ConnectorError(cs_connector_utility_3.format(source_filepath))
        if os.path.exists(target_filepath):
            logger.warn(cs_connector_utility_19.format(target_filepath))
            shutil.rmtree(target_filepath)
        with ZipFile(source_filepath) as zf:
            if password:
                password = str(password).encode()
            zipinfo = zf.infolist()
            for info in zipinfo:
                # upper limit is 138 characters for some reason, it's seemingly enforced by zipfile
                # 32 of these characters come from target_filepath
                if len(info.filename) > 106:
                    extension = info.filename.split('.')[-1]
                    # we'll give some allowance for long file extensions and truncate filename at 80 characters
                    info.filename = '{}{}{}'.format(info.filename[0:80], '--truncated.', extension)
                zf.extract(member=info, path=target_filepath, pwd=password)
        check_file_traversal(target_filepath)
        env = kwargs.get('env', {})
        listOfFiles = list()
        for (dirpath, dirnames, filenames) in os.walk(target_filepath):
            listOfFiles += [os.path.join(dirpath, file) for file in filenames]
        save_file_in_env(env, target_filepath)
        save_file_in_env(env, file_name)
        return {"filenames": listOfFiles}

    except ConnectorError as e:
        raise ConnectorError(e)
    except Exception as e:
        logger.error(cs_connector_utility_20.format('unzipping', str(e)))
        raise ConnectorError(cs_connector_utility_20.format('unzipping', str(e)))


def check_file_traversal(filename):
    """
    Check for file traversal.
    http://stackoverflow.com/questions/6803505/does-my-code-prevent
    Users don't control filenames for now, but better safe than sorry
    """
    working_directory = os.path.abspath(settings.TMP_FILE_ROOT)
    file_path = os.path.join(settings.TMP_FILE_ROOT, filename)
    requested_path = os.path.relpath(file_path, start=working_directory)
    requested_path = os.path.normpath(os.path.join(working_directory,
                                                   requested_path))
    common_prefix = os.path.commonprefix([requested_path, working_directory])
    if common_prefix is not working_directory:
        logger.error(cs_connector_utility_9.format(filename))
        raise ConnectorError(cs_connector_utility_9.format(filename))


def collect_file_metadata(filename, *args, **kwargs):
    # try to find the metadata in the env
    env = kwargs.get('env', {})
    files_metadata = env.get('files', {})
    metadata = files_metadata.get(filename, {})

    # create some new metadata
    metadata = metadata or {
        'filename': filename,
        'content_type': 'application/octet-stream',
    }
    return metadata


def upload_file(file_obj, url, metadata=None, auth=None,
                request_headers=None, multipart_headers=None,
                extra_fields=None, *args, **kwargs):
    """
    Uploads a file from a file-like object. Allows for a lot of customization of
    the actual multipart body. You can add multiple fields as well as additional
    headers to said body. You can also update the http request headers for
    additional authentication or other needs. The file will be streamed from
    disk; since it does not have to be loaded info memory all at the same time,
    this should allow for uploading of arbitrarily large files -- usually the
    limit is imposed by the receiving HTTP server.
    :param str filename: Name of file on the filesystem
    :param str metadata: Extra info about the file
    :param str url: The location to upload the file to
    :param dict auth: Requests auth object
    :param dict extra_fields: extra form data to put into the body
    :param dict request_headers: Headers added to the http request
    :param dict multipart_headers: Headers to add to the multipart body
    :return: Request response content
    :rtype: Any
    :raises Exception: if there are problems parsing the request
    """
    # defaults for object args
    multipart_headers = multipart_headers or {}
    request_headers = request_headers or {}
    extra_fields = extra_fields or {}
    metadata = metadata or {}

    # collect metadata
    real_filename = metadata.get('filename', 'download')
    content_type = metadata.get('content_type', 'application/octet-stream')

    # http://docs.python-requests.org/en/master/user/advanced/#streaming-uploads
    if hasattr(file_obj, 'mode'):
        assert file_obj.mode == 'rb', file_obj.mode

    # construct multipart payload
    boundary = uuid.uuid4().hex

    fields = {
        'file': (real_filename,
                 file_obj,
                 content_type,
                 multipart_headers)
    }
    # don't want to overwrite the actual file param
    extra_fields.pop('file', None)
    fields.update(extra_fields)

    encoder = MultipartEncoder(fields, boundary=boundary)

    request_headers.update({
        'Content-Type': encoder.content_type
    })

    # actual request
    logger.info('Starting request: POST %s', url)
    response = requests.post(url, headers=request_headers,
                             verify=False, data=encoder, auth=auth)
    return maybe_json_or_raise(response)


def save_file_in_env(env, filename, metadata={}):
    logger.info('Save file in environment Filename: %s', filename)
    if metadata:
        if 'agent_id' not in metadata:
            assert type(metadata) is FileMetadata
            metadata = dict(metadata._asdict())

    file_dict = env.get('files', {})
    file_dict[filename] = metadata
    env['files'] = file_dict


def calculate_hashes(file_path):
    """
    Creates a md5, SHA1, SHA2 hashes to file objects.
    :param str file_path: Path of the file required to generate hashes.
    :return: dict of hashes like md5, sha1, sha256
    :rtype: dict dictionary
    """
    file_hashes = {'md5': '', 'sha1': '', 'sha256': ''}
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as file_object:
            for chunk in iter(lambda: file_object.read(4096), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        file_hashes['md5'] = md5.hexdigest()
        file_hashes['sha1'] = sha1.hexdigest()
        file_hashes['sha256'] = sha256.hexdigest()
    except IOError as e:
        logger.warn('Could not open file:{} :: {}'.format(file_path, str(e)))
    return file_hashes


def upload_file_to_cyops(file_path, filename=None, create_attachment=False, name='', description='',
                         *args, **kwargs):
    check_file_traversal(file_path)

    file_path = os.path.join(settings.TMP_FILE_ROOT, file_path)

    if not os.path.exists(file_path):
        logger.error(cs_connector_utility_3.format(file_path))
        raise ConnectorError(cs_connector_utility_3.format(file_path))

    try:
        file_type = filename.replace(' ', '').split('.')[-1]
    except:
        file_type = 'txt'

    result = make_file_upload_request(filename, open(file_path, 'rb'), file_type, 'files', *args, **kwargs)
    file_hashes = calculate_hashes(file_path)
    result['metadata'] = file_hashes

    if create_attachment:
        # init optional args
        attachment_info = {
            'name': name, 'description': description
        }

        # CH collections
        attachment_collection_iri = '/api/3/attachments'

        # now create an attachment with this file
        file_iri = result.get('@id', '')
        attachment_info['file'] = file_iri
        return make_cyops_request(attachment_collection_iri, 'POST', attachment_info, *args, **kwargs)
    else:
        return result


def download_file_from_cyops(iri, headers=None, *args, **kwargs):
    """
    Downloads a file and the corresponding metadata from Crudhub. This will do
    HMAC authentication. The iri can be either a file or an attachment.
    :param str iri: Absolute path to the file as an IRI
    :return: filename
    :rtype: str
    """
    logger.info('download_file_from_crudhub IRI: %s', iri)

    if not int(cyops_version.replace('.', '')) < 643:
        from integrations.crudhub import download_file_from_cyops as download_file_from_cyops_new
        return download_file_from_cyops_new(iri, headers=headers, *args, **kwargs)

    # account for relative iri
    if not bool(urlparse(iri).netloc):
        iri = settings.CRUD_HUB_URL + str(iri)

    # get the @id and type (with or without a trailing slash)
    split = iri.split('/')
    obj_id = split[-1]
    if not obj_id:
        obj_id = split[-2]
        obj_type = split[-3]
    else:
        obj_type = split[-2]

    # retrieve the file info from the attachment
    if obj_type != 'files':
        collection = '/api/3/{obj_type}/{obj_id}'.format(obj_type=obj_type,
                                                         obj_id=obj_id)
        logger.info('Download file from crudhub %s', collection)
        res = make_cyops_request(collection, 'GET', None, *args, **kwargs)
        file_iri = res['file']

        if type(file_iri) is not str:
            file_iri = file_iri.get('@id', '')
        return download_file_from_cyops(file_iri, *args, **kwargs)

    # download the file metadata
    collection = '/api/3/files?id={}'.format(obj_id)
    logger.info('Download file metadata %s', collection)
    metadata = make_cyops_request(collection, 'GET', None, *args, **kwargs)
    ch_metadata = metadata['hydra:member'][0]
    mime_type = ch_metadata.get('mimeType', 'application/octet-stream')
    if not headers:
        headers = {}
    headers.update({'Accept': 'application/octet-stream'})
    # download the file
    filename, meta = download_file(iri, is_crudhub_endpoint=True, headers=headers, *args, **kwargs)
    try:
        metadata = FileMetadata(ch_metadata.get('filename', filename),
                                ch_metadata.get('size', 0),
                                ch_metadata.get('mimeType', ''),
                                ch_metadata.get('md5', meta.md5),
                                ch_metadata.get('sha1', meta.sha1),
                                ch_metadata.get('sha256', meta.sha256))
    except Exception as e:
        logger.error(str(e))
        metadata = FileMetadata(filename, 0, '', '', '', '')
        # save in env
        save_file_in_env(kwargs.get('env', {}), filename, metadata)
    # return the voucher
    res = metadata._asdict()
    res.update({'cyops_file_path': filename})
    save_file_in_env(kwargs.get('env', {}), filename, metadata)
    return res


def create_cyops_attachment(filename, name='', description='',
                            request_headers=None, multipart_headers=None,
                            extra_multipart_fields=None, *args, **kwargs):
    """
    Uploads a file to Crudhub, then associates the file with an attachment.
    :param str filename: Name of file on the filesystem
    :param str name: User provided name for the attachment
    :param str description: User provided description for the attachment
    :param dict extra_fields: extra form data to put into the body
    :param dict request_headers: Headers added to the http request
    :param dict multipart_headers: Headers to add to the multipart body
    :return: CH result
    :rtype: dict
    """
    logger.info('Uploads a file to Crudhub, then associates the file with an attachment.')
    env = kwargs.get('env', {})
    check_file_traversal(filename)

    # init optional args
    attachment_info = {
        'name': name, 'description': description
    }
    request_headers = request_headers or {}

    # collect metadata
    metadata = collect_file_metadata(filename, env)

    # first upload the file and get the @id back
    abs_filename = os.path.join(settings.TMP_FILE_ROOT, filename)
    return upload_file_to_cyops(file_path=abs_filename, filename=metadata.get('filename', 'download'),
                                request_headers=None, multipart_headers=None, extra_multipart_fields=None,
                                create_attachment=True, **attachment_info)


def get_attachment_types(*args, **kwargs):
    attachment_types = []
    picklist_iri = ''

    response = make_cyops_request('/api/3/picklist_names?$limit=1000', 'GET')['hydra:member']

    for picklist in response:
        if picklist['name'] == 'AttachmentsType':
            picklist_iri = picklist['@id']

    response2 = make_cyops_request(picklist_iri + '?$relationships=true', 'GET')['picklists']

    for attachment_type in response2:
        attachment_types.append(attachment_type['itemValue'])

    return attachment_types


def get_key(key_to_decrypt):
    if key_to_decrypt.startswith('0x') or key_to_decrypt.startswith('0X'):
        key_to_decrypt = int(key_to_decrypt, 16)
    else:
        key_to_decrypt = ord(key_to_decrypt)
    return key_to_decrypt


def get_fileiri_data(cyops_file_iri):
    file_data = make_request(cyops_file_iri, 'GET')
    if not isinstance(file_data, bytes):
        file_data = file_data.encode('utf-8')
    return file_data


def xor_byte_file_decryption(input_file, output_file, key_to_decrypt, file_path='', file_iri=None, *args, **kwargs):
    try:
        if file_path:
            if not file_path.startswith('/tmp/'):
                file_path = '/tmp/' + file_path
            with open(file_path, 'rb') as fo:
                file_data = fo.read()
        else:
            cyops_file_iri = file_iri
            file_data = get_fileiri_data(cyops_file_iri)

        key_to_decrypt = get_key(key_to_decrypt)
        temp_target_filename = os.path.join("/tmp/", output_file)
        file = open(temp_target_filename, "w")
        for ch in file_data:
            xored = ch ^ key_to_decrypt
            file.write(chr(xored))
        file.close()
        env = kwargs.get('env', {})
        save_file_in_env(env, temp_target_filename)
        return {"output_file": temp_target_filename}
    except Exception as e:
        logger.error(str(e))
        raise ConnectorError(e)


def pem_certificate_serializer(obj):
    result = {}
    fields_mapping = {
        'Country' : 'COUNTRY_NAME',
        'State' : 'STATE_OR_PROVINCE_NAME',
        'Locality' : 'LOCALITY_NAME',
        'Organization' : 'ORGANIZATION_NAME',
        'Organization Unit' : 'ORGANIZATIONAL_UNIT_NAME',
        'Common Name' : 'COMMON_NAME'
    }
    for field_key, field_value in fields_mapping.items():
        value = obj.get_attributes_for_oid(getattr(NameOID, field_value))
        if value : result[field_key] = value[0].value
    return result


def read_pem_certificate(file_iri_or_path, *args, **kwargs):
    try:
        if file_iri_or_path.startswith('/api/3/'):
            res = download_file_from_cyops(file_iri_or_path)
            file_path = join('/tmp', res['cyops_file_path'])
        else:
            file_path = os.path.join('/tmp', file_iri_or_path)
            check_file_traversal(file_path)
        with open(file_path, 'rb') as pem_file:
            pem_data = pem_file.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        cert_subject = pem_certificate_serializer(cert.subject)
        cert_issuer = pem_certificate_serializer(cert.issuer)
        cert_version = cert.version.name
        return {'subject': cert_subject,
                'serial_number': cert.serial_number,
                'issuer': cert_issuer,
                'version': cert_version}
    except Exception as err:
        logger.error(err)
        raise ConnectorError(err)
