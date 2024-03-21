from integrations.crudhub import make_request
from connectors.core.connector import get_logger
from .constants import LOGGER_NAME
from .webserver.scheme import validate_token

logger = get_logger(LOGGER_NAME)


def resume_playbook(config, params):
    record_id = params.get('web_data', {}).get('manual_input_id')
    token = params.get('token')
    if not validate_token(token, record_id, logger):
        logger.error("Invalid token provided")
        return {"status": "failure", "message": "Invalid token provided"}
    endpoint = "/api/wf/api/workflows/" + str(
        params.get('web_data', {}).get('workflow_id')) + "/wfinput_resume/?format=json"
    logger.info(endpoint)
    method = "POST"
    body = params.get('web_data')
    logger.info(endpoint)
    response = make_request(endpoint, method, body)
    return response
