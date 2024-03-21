import requests
from consts import (HELP_MESSAGE, PLAYBOOK_TRIGGER_MESSAGE, PLAYBOOK_ERROR_MESSAGE, 
        WF_RESUME_ERROR_MESSAGE, PLAYBOOK_INVALID_MESSAGE, ACK_MESSAGE, STATIC_DOT)
from log_helper import logger
import re
import sys
from os.path import abspath
sys.path.append(abspath('/opt/cyops-integrations/integrations'))
from integrations.crudhub import make_request

finished_status = ['failed','finished','skipped','finished_with_error','terminated']
error_status = ['failed','skipped','terminated']

def make_rest_call(method, url, payload=None):
    try:
        return make_request(url, method, body=payload, __async=True, verify=False)
    except requests.exceptions.Timeout:
        logger.error("Request to url {} timed out".format(url))
    except requests.exceptions.RequestException as e:
        logger.exception(e)
    return {"totalItems": 0}

def identify_playbook_containing_required_tags(workflows, tags=[], command=None):
    if not command:
        all_tags = []
        for workflow in workflows:
            for tag in workflow.get('recordTags'):
                if tag == "bot_enabled":
                    pass
                else:
                    all_tags.append(tag)
        return list(set(all_tags))
    for workflow in workflows:
        if all(tag in workflow.get('recordTags') for tag in tags):
            return workflow


def find_candidate_playbook(command=None):
    tags_list = ['bot_enabled']
    if command:
        tags_list = ['bot_enabled', command]
    payload = {
        "logic": "AND",
        "filters": [
            {
                "type": "primitive",
                "field": "recordTags",
                "value": tags_list,
                "operator": "in"
            },
            {
                "type": "primitive",
                "field": "isActive",
                "value": "true",
                "operator": "eq"
            }
        ],
        "sort": [
            {
                "field": "id",
                "direction": "DESC"
            }
        ]
    }
    url = "/api/query/workflows"
    response = make_rest_call('POST', url, payload)
    if not response.get('hydra:member', None):
        return None
    return identify_playbook_containing_required_tags(response['hydra:member'], tags_list, command)


def trigger_playbook(playbook, command_inputs, context):
    url = f"/api/triggers/1/notrigger/{playbook['uuid']}"
    payload = {
        "_eval_input_params_from_env": True,
        'env':  dict(zip(playbook['parameters'], command_inputs)),
        "runtime_tags": ["bot_command"]
    }
    payload['env']['bot_context'] = context
    logger.debug(f"Payload sent while triggering playbook\n{payload}")

    response = make_rest_call('POST', url, payload)
    return response['task_id']


def trigger_playbook_with_command(playbook, command_inputs="", command=None):
    url = f"/api/triggers/1/notrigger/{playbook['uuid']}"
    if command_inputs and isinstance(command_inputs,str):
        command_inputs = command_inputs.split(' ')
    payload = {
        "_eval_input_params_from_env": True,
        'env':  dict(zip(playbook['parameters'], command_inputs)),
        "runtime_tags": ["bot_command"]
    }
    payload['env']['bot_context'] = command
    logger.debug(f"Payload sent while triggering playbook\n{payload}")

    response = make_rest_call('POST', url, payload)
    return response['task_id']


def parse_command(command_text):
    command_text = re.sub("<(.*?)>", "", command_text).strip()
    command_details = command_text.split(' ')
    logger.debug(f"Commands identified\n{command_details}")
    return command_details[0], command_details[1:]


def process_mentioned(event, context, client, event_orignal):
    try:
        command_name, command_inputs = parse_command(event.get('text'))
        if not command_name or (isinstance(command_name, str) and command_name.lower() == 'help'):
            return help_text(client=client, event_orignal=event_orignal)
        elif isinstance(command_name, str) and command_name.lower() == 'playbookinfobytag':
            return playbook_info_text(command_inputs, client=client, event_orignal=event_orignal)
        elif isinstance(command_name, str) and command_name.lower() == 'availablecommands':
            playbook_tags = find_candidate_playbook()
            reply_text = " "
            reply_text = reply_text.join(playbook_tags)
            block_message = "All Available Commands:\n" + STATIC_DOT + ("\n" + STATIC_DOT).join(playbook_tags)
            block_text = [{"type": "section", "text": {"type": "mrkdwn", "text": block_message}}]
            return available_command_text(client=client, event_orignal=event_orignal, reply_text=reply_text,
                                          block_text=block_text)
        elif isinstance(command_name, str) and command_name.lower() == 'invokeplaybook':
            command_name = command_inputs[0]
            command_inputs = command_inputs[1:]
        client.chat_postMessage(
            channel=event_orignal['channel'],
            thread_ts=event_orignal['ts'],
            text=ACK_MESSAGE)
        playbook = find_candidate_playbook(command_name)
        if not playbook:
            logger.error(f"No playbook identified for the event {event.text}")
            return
        logger.debug(f"Triggering the playbook \"{playbook['name']}\"")
        task_id = trigger_playbook(playbook, command_inputs, context)
        logger.debug(
            f"Playbook \"{playbook['name']}\" triggered with task_id {task_id}")
        return True
    except Exception as error:
        logger.error(error)
        client.chat_postMessage(
            channel=event_orignal['channel'],
            text=PLAYBOOK_ERROR_MESSAGE
        )


def get_values_for_inputs(input_payload):
    input_dict = {}
    for random_key, value_dict in input_payload['state']['values'].items():
        for manual_input_var, dict1 in value_dict.items():
            input_type = dict1['type']
            value = ""
            if input_type == 'checkboxes':
                value = False
                if dict1.get("selected_options", None):
                    value = True
            elif input_type == 'multi_static_select' or input_type == 'static_select':
                value = []
                for item in dict1.get("selected_options", []):
                    value.append(item['value'])
            elif input_type == 'plain_text_input' or input_type == 'url_text_input' or input_type == 'number_input':
                value = dict1['value']
            elif input_type == 'datetimepicker':
                value = dict1['selected_date_time']
            else:
                value = dict1
            input_dict[manual_input_var] = value
    return input_dict


def get_action_details(payload):
    if payload['actions']:
        context = payload['actions'][0]['action_id'].replace("fsr_", "")
        step_iri = payload['actions'][0]['value']
        action_button_text = payload['actions'][0]['text']['text']
        return context, step_iri, action_button_text
    logger.error("Invalid payload recieved")


def resume_playbook(action_payload,respond):
    input_dict = get_values_for_inputs(action_payload)
    context, step_iri, action_button_text = get_action_details(action_payload)
    [workflow_id, input_id, step_id] = context.split('_')
    resume_payload = {
        "input": input_dict,
        "step_id": step_id,
        "manual_input_id": input_id,
        "step_iri": step_iri
    }
    logger.debug(f"Playbook resume payload:\n{resume_payload}")
    url = f"/api/wf/api/workflows/{workflow_id}/wfinput_resume/"
    response = make_rest_call('POST', url, resume_payload)
    logger.debug(response)
    if response.get('totalItems') == 0:
        return respond(text=WF_RESUME_ERROR_MESSAGE,
                          response_type="in_channel", replace_original=True)
    return respond(text="Input submitted sucessfully",
                          response_type="in_channel", replace_original=True)


def help_text(respond=None, client=None, event_orignal=None):
    if client:
        return client.chat_postMessage(
            channel=event_orignal['channel'],
            thread_ts=event_orignal['ts'],
            text="Help Text",
            blocks=HELP_MESSAGE
        )
    else:
        return respond(text="playbook result",blocks=HELP_MESSAGE, response_type="in_channel")


def available_command_text(respond=None, client=None, event_orignal=None, reply_text=None, block_text=None):
    reply_text = "All available commands: "+reply_text
    if client:
        return client.chat_postMessage(
            channel=event_orignal['channel'],
            thread_ts=event_orignal['ts'],
            text=reply_text,
            blocks=block_text
        )
    else:
        return respond(text=reply_text, blocks=block_text, response_type="in_channel")


def playbook_info_text(command_inputs, respond=None, client=None, event_orignal=None,):
    playbook = find_candidate_playbook(command_inputs[0])
    reply_text = "Playbook name :" + \
        playbook['name'] + " Playbook description :" + playbook['description']
    if client:
        return client.chat_postMessage(
            channel=event_orignal['channel'],
            thread_ts=event_orignal['ts'],
            text=reply_text
        )
    else:
        return respond(text=reply_text, response_type="in_channel")

def process_shortcut(respond, command_name, command_text, context, shortcut, client):
    try:
        shortcut['user_id']=  shortcut['user']['id']
        if not context.get('channel_id'):
            message_ack = client.chat_postMessage(
                channel=context['user_id'], text=ACK_MESSAGE)
            shortcut['channel_id']=message_ack.data['channel']
            shortcut['ts']=message_ack.data['ts']
        else:
            shortcut['ts']=  shortcut['message']['ts']
            shortcut['channel_id']= context.get('channel_id')
            message_ack = client.chat_postMessage(
                channel=context.get('channel_id'), text=ACK_MESSAGE,response_type="in_channel",thread_ts=shortcut['ts'])
        playbook = find_candidate_playbook(command_name)
        if not playbook:
            logger.error(
                f"{PLAYBOOK_INVALID_MESSAGE} + ' ' + {command_text}")
            return respond(text=f"{PLAYBOOK_INVALID_MESSAGE} {command_text}", response_type="in_channel")
        logger.debug(f"Triggering the playbook \"{playbook['name']}\"")
        task_id = trigger_playbook_with_command(
            playbook, command_text, shortcut)
        logger.debug(
            f"Playbook \"{playbook['name']}\" triggered with task_id {task_id}")

    except Exception as error:
        logger.exception(error)
        respond(PLAYBOOK_TRIGGER_MESSAGE, response_type="in_channel")


def process_command(respond, client, command, say, context):
    try:
        logger.debug(command)
        command_name, command_inputs = parse_command(command['text'])
        if not command_name or (isinstance(command_name, str) and command_name.lower() == 'help'):
            return help_text(respond)
        elif isinstance(command_name, str) and command_name.lower() == 'playbookinfobytag':
            return playbook_info_text(command_inputs, respond)
        elif isinstance(command_name, str) and command_name.lower() == 'availablecommands':
            playbook_tags = find_candidate_playbook()
            reply_text = " "
            reply_text = reply_text.join(playbook_tags)
            block_message = "All Available Commands:\n" + STATIC_DOT + ("\n" + STATIC_DOT).join(playbook_tags)
            block_text = [{"type": "section", "text": {"type": "mrkdwn", "text": block_message}}]
            return available_command_text(respond, None, None, reply_text=reply_text, block_text=block_text)
        elif isinstance(command_name, str) and command_name.lower() == 'invokeplaybook':
            command_name = command_inputs[0]
            command_inputs = command_inputs[1:]
        message_ack = respond(ACK_MESSAGE, response_type="in_channel")
        reply_url = message_ack.api_url
        playbook = find_candidate_playbook(command_name)
        if not playbook:
            logger.error(
                f"{PLAYBOOK_INVALID_MESSAGE} + ' ' + {command['text']}")
            respond.response_url = reply_url
            return respond(text=f"{PLAYBOOK_INVALID_MESSAGE} {command['text']}", response_type="in_channel")
        logger.debug(f"Triggering the playbook \"{playbook['name']}\"")
        task_id = trigger_playbook_with_command(
            playbook, command_inputs, command)
        logger.debug(
            f"Playbook \"{playbook['name']}\" triggered with task_id {task_id}")

    except Exception as error:
        logger.exception(error)
        respond(text=f"{PLAYBOOK_ERROR_MESSAGE}", response_type="in_channel")


def handle_event(event, context, client=None, event_orignal=None):
    process_mentioned(event, context, client, event_orignal)


def handle_command(respond, client, command, say, context):
    process_command(respond, client, command, say, context)
