from integrations.crudhub import make_request
from .webserver.scheme import validate_token
from .constants import LOGGER_NAME
from connectors.core.connector import get_logger

logger = get_logger(LOGGER_NAME)


def fetch_maunal_input_details(config, params):
    record_id = params.get('manual_input_id')
    token = params.get('token')
    if not validate_token(token, record_id, logger):
        logger.error("Invalid token provided")
        return {"status": "failure", "message": "Invalid token provided"}
    endpoint = "/api/wf/api/manual-wf-input/" + str(record_id) + "/?format=json"
    method = "GET"
    response = make_request(endpoint, method)
    return response
