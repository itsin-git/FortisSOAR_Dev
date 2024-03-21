""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import ssl
import certifi

import requests
from connectors.cyops_utilities.builtins import download_file_from_cyops
from integrations.crudhub import make_request
from os.path import join
from connectors.core.connector import get_logger, ConnectorError
import time
from slack_sdk import WebClient

from .utils.fsr_slack_converter import convert_input

logger = get_logger('slack')


def get_client_object(config):
    if config:
        server_url = config.get('server_url').strip('/')
        logger.debug(
            'get_config health check server_url: {0}'.format(str(server_url)))
        bot_token = config.get('slack_token')
        verify_ssl = config.get('verify_ssl', 'False')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = 'https://' + server_url
        server_url = '{}/api/'.format(server_url)
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.verify_mode = ssl.CERT_NONE if verify_ssl == False else ssl.CERT_REQUIRED
        client = WebClient(
            token=bot_token, base_url=server_url, ssl=ssl_context)
        return client


def validate_app_token(config):
    url = "https://slack.com/api/apps.connections.open"
    payload = {}
    headers = {
        'Content-type': 'application/x-www-form-urlencoded',
        'Authorization': 'Bearer ' + str(config.get('app_token'))
    }
    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        if response and response.json().get('ok'):
            return True
    except Exception as e:
        logger.error(f"Exception occurred while reaching slack API, {str(e)}")
    raise ConnectorError('Invalid App token provided')


def check_health_ex(config):
    try:
        if config.get('enable_slack_bot'):
            validate_app_token(config)
        client = get_client_object(config)
        result = client.api_call("api.test")
        if result['ok'] is True:
            return True
        else:
            handle_error_resp(result)
    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


def handle_error_resp(data):
    skip_error = ['user_not_found', 'user_not_visible']
    if not data.get('ok') and data.get('error') not in skip_error:
        logger.error('Failure due to {0}'. format(data))
        raise ConnectorError('Failure due to {0}'. format(
            {'error': data.get('error'), 'detail': data.get('detail')}))


def list_channels(config, params):
    try:
        client = get_client_object(config)
        types_list = {
            "Public Channel": "public_channel",
            "Private Channel": "private_channel",
            "Group messaging": "mpim",
            "Direct Messages": "im"
        }
        types = params.get('types')
        temp_lst = []
        if type(types) == list:
            for item in types:
                temp_lst.append(types_list.get(item))
        temp_lst_str = ','.join(map(str, temp_lst))
        if len(temp_lst_str) == 0:
            temp_lst_str = "public_channel"
        resp = client.conversations_list(
            limit=params.get('limit') if params.get('limit') else 100,
            cursor=params.get('cursor'),
            exclude_archived=str(params.get('exclude_archived')),
            types=temp_lst_str
        )
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


def get_channel_info(config, params):
    try:
        client = get_client_object(config)
        resp = client.conversations_info(
            channel=params.get('channel'),
            include_locale=str(params.get('include_locale')),
            include_num_members=str(params.get('include_num_members'))
        )
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


def search_channel(config, params):
    try:
        client = get_client_object(config)
        search_name = params.get('search_name')
        search_type = params.get('search_type')
        result = list()
        resp = client.api_call("conversations.list")
        handle_error_resp(resp)
        if resp['ok'] and resp['channels'].__len__():
            channels = resp.get('channels')
            for channel in channels:
                if search_type == "Exact" and channel['name'] == search_name:
                    result.append(channel)
                    break
                if search_type == "Starts With":
                    ch_name = channel['name']
                    if ch_name.startswith(search_name):
                        result.append(channel)
                if search_type == "Ends With":
                    ch_name = channel['name']
                    if ch_name.endswith(search_name):
                        result.append(channel)
                if search_type == "Contains" and search_name in channel['name']:
                    result.append(channel)

        result_dict = dict()
        result_dict['status'] = 'Success' if result.__len__() else 'Failed'
        result_dict['message'] = 'Found channel' if result.__len__() else 'No channel found'
        result_dict['data'] = result
        return result_dict

    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


def list_users(config, params):
    try:
        client = get_client_object(config)
        limit = params.get('limit', 50)
        cursor = params.get('cursor', '')

        resp = client.users_list(
            cursor=cursor,
            limit=limit
        )
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


def get_user(config, params):
    try:
        client = get_client_object(config)
        search_by = params.get('search_by')
        search_type = params.get('search_type')
        search_value = params.get('value')
        locale = bool(params.get('include_locale'))
        result = dict()

        if search_by == "Email":
            resp = client.users_lookupByEmail(email=search_value)
            handle_error_resp(resp)
            if resp['ok']:
                user = resp['user']
            else:
                user = dict()
            return user

        if search_by == "User ID":
            resp = client.users_info(
                user=search_value,
                include_locale=locale)

            handle_error_resp(resp)
            if resp['ok']:
                user = resp['user']
            else:
                user = dict()
            result['status'] = 'Success' if user.__len__() else 'Failed'
            result['message'] = 'Found users' if user.__len__() else 'No users found'
            result['data'] = [user] if user.__len__() else []
            return result
        if search_by == "Alias" or search_by == "Username":
            result = list()
            resp = client.api_call("users.list")
            handle_error_resp(resp)
            if resp['ok'] and resp['members'].__len__():
                users = resp.get('members')
                for user in users:
                    user_info = user
                    if search_by == 'Username':
                        user = user['profile']
                    if search_type == "Exact" and user['name' if search_by == "Alias" else 'real_name'] == search_value:
                        result.append(user_info)
                        break
                    if search_type == "Starts With":
                        ch_name = user['name' if search_by == "Alias" else 'real_name']
                        if ch_name.startswith(search_value):
                            result.append(user_info)
                    if search_type == "Ends With":
                        ch_name = user['name' if search_by == "Alias" else 'real_name']
                        if ch_name.endswith(search_value):
                            result.append(user_info)
                    if search_type == "Contains" and search_value in user['name' if search_by == "Alias" else 'real_name']:
                        result.append(user_info)

            result_dict = dict()
            result_dict['status'] = 'Success' if result.__len__() else 'Failed'
            result_dict['message'] = 'Found users' if result.__len__() else 'No users found'
            result_dict['data'] = result
            return result_dict
    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


def send_message(config, params):
    try:
        client = get_client_object(config)
        channel_id = params.get('channel')
        message = params.get('message')
        blocks = params.get('blocks')
        email_id = params.get('email_id')
        if not channel_id and  not email_id :
            raise ConnectorError(str("Empty channel/Email address provided."))
        if not channel_id and  email_id :
            get_user_payload = {'search_by': 'Email', 'value': email_id}
            recipient_user = get_user(config, get_user_payload)
            channel_id = recipient_user.get('id')
        # If the blocks variable is empty string, need to mark it None explicitly
        if not blocks:
            blocks = []
        # If thread_ts not given in str format, it is not honored
        thread_ts = str(params.get('thread_ts'))
        attachments = params.get('attachments')
        resp = client.chat_postMessage(
            channel=channel_id,
            text=message,
            as_user=True,
            attachments=attachments,
            blocks=blocks,
            thread_ts=thread_ts)
        logger.info(resp)
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


def upload_file(config, params):
    try:
        client = get_client_object(config)
        file_iri = handle_params(params.get('path'), str(params.get('value')))
        file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
        logger.info(file_path)
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()

        resp = client.files_upload(
            channels=params.get('channel'),
            file=file_data,
            filename=params.get('file_name'),
            filetype=params.get('file_type'),
            title=params.get('title'),
            initial_comment=params.get('comment')
        )
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


def create_channel(config, params):
    try:
        client = get_client_object(config)
        resp = client.conversations_create(
            name=params.get('name'),
            is_member=True,
            is_private=params.get('is_private') if params.get('is_private') else False
        )
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def rename_channel(config, params):
    try:
        client = get_client_object(config)
        resp = client.conversations_rename(
            channel=params.get('channel'),
            name=params.get('name')
        )
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def list_to_str(input):
    if type(input) == list:
        return ','.join(map(str, input))
    else:
        return input


def invite_user_to_channel(config, params):
    try:
        client = get_client_object(config)
        resp = client.conversations_invite(
            channel=params.get('channel'),
            users=list_to_str(params.get('users'))
        )
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def close_channel(config, params):
    try:
        client = get_client_object(config)
        resp = client.conversations_close( channel=params.get('channel'))
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def convert_to_epoc(date_to_convert):
    try:
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        return int(time.mktime(time.strptime(date_to_convert, pattern)))
    except Exception as err:
        logger.error(str(err))
        return ''


def get_message_history(config, params):
    try:
        client = get_client_object(config)
        params.pop('cursor')
        resp = client.conversations_history(
            channel=params.get('channel'),
            cursor=params.get('cursor', ''),
            inclusive=str(params.get('inclusive')),
            oldest=convert_to_epoc(params.get('oldest')) if params.get('oldest') else '',
            latest=convert_to_epoc(params.get('latest')) if params.get('latest') else '',
            limit=str(params.get('limit')) if params.get('limit') else '100'
        )
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def handle_params(input_type, value):
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)

            attachment_data = make_request(value, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))

            return file_iri
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                return value
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
    except Exception as err:
        logger.info('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                             (input_type, value.replace('/api/3/attachments/', '')))


def send_input(config, params):
    try:
        ts_id = ""
        client = get_client_object(config)
        # input is a FSR Manual Input object
        input_data = params.get('input')
        recipient_email = input_data['owner_details']['externalRecipients'].split(',')[0]
        if not recipient_email:
            raise ConnectorError(str("Invalid recipient email address/user id provided."))
        if "@" in recipient_email and "." in recipient_email:
            get_user_payload = {'search_by': 'Email', 'value': recipient_email}
            recipient_user = get_user(config, get_user_payload)
            recipient_user_id = recipient_user.get('id')
        else:
            recipient_user_id = recipient_email
        input_id = input_data['id']
        step_id = input_data['step_id']
        workflow_id = input_data['workflow']
        manual_input_context = f"fsr_{workflow_id}_{input_id}_{step_id}"
        blocks = convert_input(input_data['input']['schema'],
                               input_data['response_mapping']['options'], manual_input_context)
        logger.info(blocks)

        bot_context = input_data.get('input').get('bot_context')
        if bot_context and not bot_context.get('ts'):
            resp = client.chat_postEphemeral(
                channel=bot_context['channel_id'], text="Default Message", blocks=blocks, user=bot_context['user_id'])
            logger.debug(resp)
            handle_error_resp(resp)
            return resp.data
        if bot_context:
            recipient_user_id = bot_context.get('channel_id')
            ts_id = str(bot_context.get('ts',""))
        resp = client.chat_postMessage(
            channel=recipient_user_id,
            text='Default Message',
            blocks=blocks,thread_ts=ts_id)
        logger.info(resp)
        handle_error_resp(resp)
        return resp.data
    except Exception as err:
        logger.error("An Exception occurred for {0}".format(str(err)))
        raise ConnectorError(str(err))


operations = {
    'create_channel': create_channel,
    'get_channel_info': get_channel_info,
    'rename_channel': rename_channel,
    'invite_user_to_channel': invite_user_to_channel,
    'close_channel': close_channel,
    'list_channels': list_channels,
    'search_channel': search_channel,
    'list_users': list_users,
    'get_user': get_user,
    'send_message': send_message,
    'upload_file': upload_file,
    'get_message_history': get_message_history,
    'send_input': send_input
}
