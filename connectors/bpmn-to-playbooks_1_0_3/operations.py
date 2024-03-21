from connectors.core.connector import get_logger, ConnectorError
from .flowable import toCybersponsePlaybookFlowable
from .camunda import toCybersponsePlaybookCamunda
from .utils import xmlToJson
import json, re

logger = get_logger('bpmntoplaybooks')


def bpmntoplaybooks(config, params, **kwargs):
    if params.get('bpmnTool').lower() == "flowable":
        if params.get('bpmnFormat').lower() == "json":
            if isinstance(params.get('bpmnOutput'), dict):
                return toCybersponsePlaybookFlowable(params.get('bpmnOutput'))
            else:
                logger.exception("BPMN JSON format is incorrect")
                raise ConnectorError("BPMN JSON format is incorrect")
        elif params.get('bpmnFormat').lower() == "xml":
            xmljson = xmlToJson(params.get('bpmnOutput'))
            if isinstance(xmljson, dict):
                return toCybersponsePlaybookFlowable(xmljson)
            else:
                logger.exception("Unable to convert BPMN XML to JSON Format")
                raise ConnectorError("Unable to convert BPMN XML to JSON Format")

    elif params.get('bpmnTool').lower() == "camunda":
        if params.get('bpmnFormat').lower() == "json":
            if isinstance(params.get('bpmnOutput'), dict):
                return toCybersponsePlaybookCamunda(params.get('bpmnOutput'))
            else:
                logger.exception("BPMN JSON format is incorrect")
                raise ConnectorError("BPMN JSON format is incorrect")
        elif params.get('bpmnFormat').lower() == "xml":
            xmljson = xmlToJson(params.get('bpmnOutput'))
            if isinstance(xmljson, dict):
                return toCybersponsePlaybookCamunda(xmljson)
            else:
                logger.exception("Unable to convert BPMN XML to JSON Format")
                raise ConnectorError("Unable to convert BPMN XML to JSON Format")

operations = {
    'bpmntoplaybooks': bpmntoplaybooks
}
