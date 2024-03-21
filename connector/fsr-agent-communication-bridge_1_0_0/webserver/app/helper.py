from .log import get_logger

logger = get_logger("fsr-agent-communication-bridge")


def connector_body(conn_name, conn_operation, params, config=''):
    return {
        "connector": conn_name,
        "operation": conn_operation,
        "config": config,
        "params": {
            "manual_input_id": params.get('input_id'),
            "token": params.get('token')
        }
    }


def connector_body_execute(conn_name, conn_operation, params, config=''):
    return {
        "connector": conn_name,
        "operation": conn_operation,
        "config": config,
        "params": {
            "web_data": params.get('web_data'),
            "token": params.get('token')
        }
    }
