import argparse
import json
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from event_handler import handle_command, handle_event, resume_playbook, process_shortcut
from log_helper import logger
from util import create_event_and_context_object_from_slack_event, decrypt
from consts import HELP_MESSAGE, PLAYBOOK_INVALID_MESSAGE

import re
pattern = re.compile("fsr_[0-9_]+[0-9]$")
shortcut_pattern = re.compile("fsr_[a-zA-Z]*$")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Slack Websocket Listener')
    parser.add_argument('--config_id', help='Configuration Id for the listener', required=True)
    parser.add_argument('--payload', help='Slack Authentication Data', required=True)
    args = parser.parse_args()
    payload = decrypt(args.payload, args.config_id)
    payload_json = json.loads(payload)
    bot_token = payload_json["bot_token"]
    app_token = payload_json["app_token"]
    if not bot_token or not app_token:
        raise Exception("Missing Slack Authentication Credentials")
    slack_app = App(token=bot_token)

    @slack_app.event("app_home_opened")
    def handle_home_opened(client,event, say):
        if event.get('tab') == 'home' and not event.get('view'):
            client.views_publish(
                user_id=event["user"],
                view={
                    "type": "home",
                    "blocks": HELP_MESSAGE
                }
            )


    @slack_app.event("app_mention")
    def handle_app_mentions(client, ack, event, say):
        try:
            event_orignal = event
            logger.debug(f"App mention event received with payload:\n{event}")
            event, context = create_event_and_context_object_from_slack_event(
                event)
            handle_event(event, context, client, event_orignal)
            # say(f"Your request is acknowledged. FSR will be processing it soon")
        except Exception as error:
            logger.exception(error)

    @slack_app.shortcut(constraints=shortcut_pattern)
    def handle_shortcut(ack, respond, command, shortcut, say, context, client):
        ack()
        command_name = shortcut['callback_id'][4:]
        command_text = shortcut.get('message', {}).get('text', "")
        if not command_name:
            respond(PLAYBOOK_INVALID_MESSAGE, response_type="in_channel")
        process_shortcut(
            respond, command_name, command_text, context, shortcut, client)

    @slack_app.action(constraints={"action_id": pattern})
    def handle_app_mentions(ack, event, say, body, respond, context):
        ack()
        logger.info(event)
        resume_playbook(body,respond)


    @slack_app.command("/fortisoar")
    def handle_some_command(ack, client, respond, command, say, logger, context):
        ack()
        handle_command(respond, client, command, say, context)

    SocketModeHandler(slack_app, app_token, logger).start()
