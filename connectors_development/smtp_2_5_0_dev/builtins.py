import re
import json
import bleach
import uuid
import copy
import base64
from bs4 import BeautifulSoup
from email.mime.image import MIMEImage
from django.core.mail import EmailMultiAlternatives
from django.core.mail.backends.smtp import EmailBackend
from connectors.core.connector import get_logger
from integrations.crudhub import make_request
from connectors.cyops_utilities.builtins import download_file_from_cyops
from connectors.environment import expand
from os.path import basename, join, abspath, relpath, normpath, commonprefix
from connectors.core.connector import ConnectorError
from django.conf import settings
try:
    from bleach.css_sanitizer import CSSSanitizer
    clean_css_args = {"css_sanitizer": CSSSanitizer(allowed_css_properties=[])}
except Exception as e:
    # For python 3.6 compatible version of bleach lib is <=4.1.0
    # In bleach 4.1.0 there is no arg css_sanitizer
    clean_css_args = {"styles": []}

logger = get_logger("builtins.smtp")


def validate_send_mail_inputs(params):
    if not params.get('to') or not params.get('subject') or not params.get('content'):
        error_message = 'Required params (To, Subject, Body) missing'
        logger.error(error_message)
        raise Exception(error_message)

def update_new_params(params):
    formatted_params = {
        'to': params.get('to_recipients') or params.get('to'),
        'cc': params.get('cc_recipients') or params.get('cc'),
        'bcc': params.get('bcc_recipients') or params.get('bcc'),
        'content': params.get('body') or params.get('content'),
        'body_type': params.get('body_type') or 'Rich Text',
    }
    params.update(formatted_params)


def send_email(config, params):
    """
    A task for sending email.
    """
    if params.get('to_recipients') or params.get('cc_recipients') or params.get('body'):
        update_new_params(params)
        validate_send_mail_inputs(params)
        return send_email_new(config, params)
    validate_send_mail_inputs(params)
    to = params.get('to', '').split(";")
    # Fix for approval step containing an invalid email address in the recipient list
    if len(to) == 1 and ',' in to[0]:
        to = to[0].split(',')
    cc = params.get('cc', '').split(";")
    if len(cc) == 1 and ',' in cc[0]:
        cc = cc[0].split(',')
    bcc = params.get('bcc', '').split(";")
    if len(bcc) == 1 and ',' in bcc[0]:
        bcc = bcc[0].split(',')
    from_str = params.get('from')
    fpath = params.get('file_path')
    f_name = params.get('file_name')
    attachment_iris = params.get('iri_list')
    content = params.get('content')
    subject = params.get('subject', '')
    content_type = params.get('content_type', 'text/plain')
    env = params.get('env', {})

    if not from_str:
        from_str = config['default_from']
    backend = EmailBackend(host=config['host'], port=config['port'],
                           username=config.get('username', ''),
                           password=config.get('password', ''),
                           use_tls=config['useTLS'],
                           timeout=config.get('timeout', 10))
    if not isinstance(content, str):
        try:
            content = json.dumps(content)
        except:
            logger.warn('Json conversion failed.')

    content, inline_images = parse_and_replace_image(content)

    text_content = bleach.clean(content,
                                # these are whitelists, so we allow nothing
                                tags=[], attributes={},
                                # remove, don't just escape
                                strip=True, **clean_css_args)

    email_msg = EmailMultiAlternatives(connection=backend,
                                       subject=subject,
                                       body=text_content,
                                       from_email=from_str,
                                       to=to,
                                       cc=cc,
                                       bcc=bcc
                                       )
    if content_type in ['html', 'text/html']:
        email_msg.attach_alternative(content, 'text/html')
    if fpath:
        fpath = fpath.strip()
        if fpath.startswith(settings.TMP_FILE_ROOT):
            # trim '/tmp/' for backward compatibility
            fpath = fpath[5:]
        _check_file_traversal(fpath)
        fpath_complete = join(settings.TMP_FILE_ROOT, fpath)
        if not f_name:
            f_name = basename(fpath_complete)
        with open(fpath_complete, 'rb') as attachment:
            email_msg.attach(f_name, attachment.read())
    if attachment_iris:
        for iri in attachment_iris:
            file_path, file_name = _download_file(iri, env)
            with open(file_path, 'rb') as attachment:
                email_msg.attach(file_name, attachment.read())
        logger.info('All attachments added to email')
    if inline_images:
        for inline_image in inline_images:
            image = MIMEImage(inline_image.get('content'))
            image.add_header('Content-ID', '<' + inline_image.get('content_id') + '>')
            email_msg.attach(image)
    try:
        email_msg.send()
    except Exception as e:
        logger.exception('Error sending email')
        raise ConnectorError('Error sending email: {0}'.format(str(e)))


def send_richtext_email(config, params):
    params['content_type'] = 'text/html'
    return send_email(config, params)


def _download_file(iri, env):
    try:
        if iri.startswith('/api/3/attachments/'):
            attachment_data = make_request(iri, 'GET')
            file_iri = attachment_data['file']['@id']
        else:
            file_iri = iri
        file_download_response = download_file_from_cyops(file_iri, env=env)
        file_path = file_download_response['cyops_file_path']
        file_name = file_download_response['filename']
        logger.info('file id = %s, file_name = %s' % (file_iri, file_name))
        return join(settings.TMP_FILE_ROOT, file_path), file_name
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError('could not find attachment with id {}'.format(str(iri)))


def _check_file_traversal(filename):
    """
    Check for file traversal.
    http://stackoverflow.com/questions/6803505/does-my-code-prevent

    Users don't control filenames for now, but better safe than sorry
    """
    working_directory = abspath(settings.TMP_FILE_ROOT)
    file_path = join(settings.TMP_FILE_ROOT, filename)
    requested_path = relpath(file_path, start=working_directory)
    requested_path = normpath(join(working_directory, requested_path))
    common_prefix = commonprefix([requested_path, working_directory])
    if common_prefix is not working_directory:
        logger.error('File traversal attempted')
        raise ConnectorError('File traversal attempted')


def send_email_new(config, params):
    """
    A task for sending email starting 4.12.1.
    """
    to, cc, bcc = _recipient_handler(config, params)
    from_str = params.get('from')
    fpath = params.get('file_path')
    f_name = params.get('file_name')
    attachment_iris = params.get('iri_list')
    if attachment_iris and isinstance(attachment_iris, str):
        attachment_iris = ''.join(attachment_iris.split()).split(',')

    if params.get('body_type') == 'Plain Text':
        params['content_type'] = 'text/plain'
    elif params.get('body_type') == 'Rich Text':
        params['content_type'] = 'text/html'
    elif params.get('body_type') == 'Email Template':
        params['content_type'] = 'text/html'
        params['subject'], params['content'] = _email_template_handler(config, params)
    env = params.get('env', {})

    content = params.get('content')

    subject = params.get('subject', '')
    content_type = params.get('content_type', 'text/plain')

    default_from = ""

    if not config['default_from']:
        config['default_from'] = default_from
    if not from_str or not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", from_str):
        from_str = config['default_from']

    timeout = config.get('timeout', None)
    if not timeout:
        timeout = 10
    backend = EmailBackend(host=config['host'], port=config['port'],
                           username=config.get('username', ''),
                           password=config.get('password', ''),
                           use_tls=config['useTLS'],
                           timeout=timeout)
    if not isinstance(content, str):
        try:
            content = json.dumps(content)
        except:
            logger.warn('Json conversion failed.')

    content, inline_images = parse_and_replace_image(content)

    text_content = bleach.clean(content,
                                # these are whitelists, so we allow nothing
                                tags=[], attributes={},
                                # remove, don't just escape
                                strip=True, **clean_css_args)

    email_msg = EmailMultiAlternatives(connection=backend,
                                       subject=subject,
                                       body=text_content,
                                       from_email=from_str,
                                       to=to,
                                       cc=cc,
                                       bcc=bcc)
    if content_type in ['html', 'text/html']:
        email_msg.attach_alternative(content, 'text/html')
    if fpath:
        fpath = fpath.strip()
        if fpath.startswith(settings.TMP_FILE_ROOT):
            # trim '/tmp/' for backward compatibility
            fpath = fpath[5:]
        _check_file_traversal(fpath)
        fpath_complete = join(settings.TMP_FILE_ROOT, fpath)
        if not f_name:
            f_name = basename(fpath_complete)
        with open(fpath_complete, 'rb') as attachment:
            email_msg.attach(f_name, attachment.read())
    if attachment_iris:
        for iri in attachment_iris:
            file_path, file_name = _download_file(iri, env)
            with open(file_path, 'rb') as attachment:
                email_msg.attach(file_name, attachment.read())
        logger.info('All attachments added to email')
    if inline_images:
        for inline_image in inline_images:
            image_content = inline_image.get('content')
            image_content_id = inline_image.get('content_id')
            if image_content and image_content_id:
                image = MIMEImage(image_content)
                image.add_header('Content-ID', '<' + image_content_id + '>')
                image.add_header('content-disposition', 'inline', filename=image_content_id)
                email_msg.attach(image)
            else:
                logger.warn('Error occurred while uploading inline image, Invalid image content or content_id')

    try:
        email_msg.send()
    except Exception as e:
        logger.exception('Error sending email')
        raise ConnectorError('Error sending email: {0}'.format(str(e)))


def get_users(config, params):
    user_list = []
    response = make_request('/api/3/people?$limit=1000', 'GET')['hydra:member']
    for user in response:
        user_list.append('{} {} {}'.format(user['firstname'], user['lastname'], user['email']))

    return user_list


def get_teams(config, params):
    team_list = []
    response = make_request('/api/3/teams?$limit=1000', 'GET')['hydra:member']
    for team in response:
        team_list.append(team['name'])

    return team_list


def get_email_templates(config, params):
    email_template_names = []
    response = make_request('/api/3/email_templates', 'GET')['hydra:member']
    for email_template in response:
        email_template_names.append(email_template['name'])

    return email_template_names


def _recipient_handler(config, params):
    recipient_type = params.get('type')
    if recipient_type == 'User':
        to = params.get('to', [])
        cc = params.get('cc', [])
        bcc = params.get('bcc', [])
        to_list = []
        cc_list = []
        bcc_list = []
        for user in to:
            to_list.append(user.split()[-1])
        for user in cc:
            cc_list.append(user.split()[-1])
        for user in bcc:
            bcc_list.append(user.split()[-1])
        to = to_list
        cc = cc_list
        bcc = bcc_list

    elif recipient_type == 'Team':
        to = params.get('to', [])
        cc = params.get('cc', [])
        bcc = params.get('bcc', [])
        team_dict = {}
        response = make_request('/api/3/teams?$relationships=true', 'GET')['hydra:member']
        for team in response:
            people_dict = {'logic': 'OR', 'filters': []}
            emails = set()
            for actor in team.get('actors', []):
                if isinstance(actor, str):
                    people_dict['filters'].append({'field': 'uuid', 'operator': 'eq', 'value': actor.rsplit('/', 1)[-1]})
                else:
                    emails.add(actor.get('email'))
            if people_dict['filters']:
                actors = make_request('/api/query/people', 'POST', body=people_dict)['hydra:member']
                for actor in actors:
                    emails.add(actor['email'])
            team_dict[team['name']] = list(emails)

        to_list = []
        cc_list = []
        bcc_list = []
        for team_name, user_emails in team_dict.items():
            if team_name in to:
                to_list.extend(user_emails)
            if team_name in cc:
                cc_list.extend(user_emails)
            if team_name in bcc:
                bcc_list.extend(user_emails)

        to = to_list
        cc = cc_list
        bcc = bcc_list
    else:  # Manual Input
        to_iri = _to_list(params.get('to', []))
        cc_iri = _to_list(params.get('cc', []))
        bcc_iri = _to_list(params.get('bcc', []))

        to = _build_payload_dict(to_iri) if to_iri else []
        cc = _build_payload_dict(cc_iri) if cc_iri else []
        bcc = _build_payload_dict(bcc_iri) if bcc_iri else []
    return to, cc, bcc

def _to_list(iri):
    if isinstance(iri, str):
        iri = ''.join(iri.split()).split(',')
        if len(iri) == 1 and ';' in iri[0]:
            iri = iri[0].split(';')       
    return iri

def _build_payload_dict(iri_email_input):
    output_list = []

    iri_dict_people = {'logic': 'OR', 'filters': []}
    iri_dict_team = {'logic': 'OR', 'filters': []}
    for iri in iri_email_input:
        if '/api/3/people' in iri:  # user IRI
            iri_dict_people['filters'].append({'field': 'uuid', 'operator': 'eq', 'value': iri.rsplit('/', 1)[-1]})
        if '/api/3/teams' in iri:  # team IRI
            iri_dict_team['filters'].append({'field': 'uuid', 'operator': 'eq', 'value': iri.rsplit('/', 1)[-1]})
        if re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", iri):  # email address
            output_list.append(iri)

    if iri_dict_people['filters']:  # query API for user IRI
        response_to_people = make_request('/api/query/people', 'POST', body=iri_dict_people)['hydra:member']
        for user in response_to_people:
            output_list.append(user['email'])
    if iri_dict_team['filters']:  # query API for team IRI
        response_to_team = make_request('/api/query/teams?$relationships=true',
                                              'POST', body=iri_dict_team)['hydra:member']

        people_dict = {'logic': 'OR', 'filters': []}
        for team in response_to_team:
            for actor in team.get('actors', []):
                if isinstance(actor, str):
                    people_dict['filters'].append({'field': 'uuid', 'operator': 'eq', 'value': actor.rsplit('/', 1)[-1]})
                else:
                    output_list.append(actor['email'])
        if people_dict['filters']:
            actors = make_request('/api/query/people', 'POST', body=people_dict)['hydra:member']
            for actor in actors:
                output_list.append(actor['email'])

    return list(set(output_list))


def _email_template_handler(config, params):
    env = params.get('env', {})

    email_template = params.get('email_templates')
    request_body = {'logic': 'OR', 'filters':[{'field': 'name', 'operator': 'eq', 'value': email_template}]}
    response = make_request('/api/query/email_templates', 'POST', body=request_body)['hydra:member']
    subject = ''
    content = ''
    if response:
        subject = response[0]['subject']
        content = response[0]['content']
        try:
            subject = expand(env, subject)
            content = expand(env, content)
        except Exception as err:
            raise ConnectorError(err)

    return subject, content


def parse_and_replace_image(email_body):
    soup = BeautifulSoup(email_body, 'html.parser')
    inline_images = []
    for img in soup.findAll('img'):
        encoded_image = img.get('src', '')
        if 'data:image' in encoded_image:
            file_name = uuid.uuid4().hex
            body_content = encoded_image.split(' ')[0]
            body_content_copy = copy.deepcopy(body_content)
            body_content = re.sub("data:image/.*;base64,", "", body_content)
            inline_images.append({
                'content_id': file_name,
                'content': base64.b64decode(body_content)
            })
            email_body = email_body.replace(body_content_copy, "cid:" + file_name).replace("\n", "")

    return email_body, inline_images
