from .config import cybersponseModules, configData, playbook, workflowData
from connectors.core.connector import get_logger, ConnectorError
from .crud_api import make_cyops_request
from .error_constants import *
import uuid, json, urllib

logger = get_logger('bpmntoplaybooks')


class CybersponseStep:

    def __init__(self):
        self.step = {
            "@type": "WorkflowStep",
            "status": "",
            "description": "",
            "uuid": str(uuid.uuid4())
        }

    def cyopsStep(self, key, bpmnDetail, bpmnShape):

        self.step['name'] = bpmnDetail['bpmnName']

        # Retrieve x, y co-ordinates from BPMN Diagram
        coordinate = coordinates(key, bpmnShape, bpmnDetail['bpmnID'])
       
        self.step['left'] = coordinate['left']
        self.step['top'] = coordinate['top']

        # Retrive CyberSponse Step Type IRI and Set Arguments

        try:
            for item in configData:
                if key in item['bpmnStepType']:
                    if item['bpmnFieldType']:
                        if bpmnDetail.get('bpmnFieldType', '') == item['bpmnFieldType']:
                            self.step['stepType'] = item['cyopsStepTypeIRI']
                            self.step['arguments'] = item['cyopsStepArguments']
                            self.step['arguments']['resource']['name'] = bpmnDetail['bpmnName'] 

                            # Arguments required for Create/Update Record
                            if bpmnDetail['bpmnFieldType'] == 'Create':
                                self.step['arguments'].update(
                                    collection='/api/3/{}'.format(bpmnDetail['bpmnModuleName'].lower()),
                                    _showJson=False,
                                    step_variables=[])

                            elif bpmnDetail['bpmnFieldType'] == 'Update':
                                self.step['arguments'].update(
                                    collectionType='/api/3/{}'.format(bpmnDetail['bpmnModuleName'].lower()),
                                    _showJson=False, step_variables=[], collection='placeholder')

                    elif "bpmnFieldType" not in bpmnDetail:

                        self.step['stepType'] = item['cyopsStepTypeIRI']
                        self.step['arguments'] = item.get('cyopsStepArguments', '')

                        if "userTask" in item['bpmnStepType']:
                            self.step['arguments']['resource']['name'] = bpmnDetail['bpmnName']

                        elif key == "scriptTask":
                            self.step['arguments'] = {'params': {}}
                            self.step['arguments'].update(name=bpmnDetail['bpmnName'],
                                                          params=bpmnDetail['connectorParams'],
                                                          version=bpmnDetail['connectorVersion'],
                                                          operation=bpmnDetail['connectorAction'],
                                                          connector=bpmnDetail['connectorName'].lower(),
                                                          operationTitle=bpmnDetail['connectorActionName'])

                        elif key == "mail":
                            self.step['arguments']['params']['from'] = bpmnDetail['from']
                            self.step['arguments']['params'].update(cc=bpmnDetail['cc'], to=bpmnDetail['to'],
                                                                    bcc=bpmnDetail['bcc'], type='Manual Input',
                                                                    content=bpmnDetail['text'],
                                                                    subject=bpmnDetail['subject'],
                                                                    body_type='Plain Text')

                            self.step['arguments'].update(version='2.2.0',
                                                          operation=bpmnDetail.get('operation', 'send_email_new'),
                                                          connector='smtp', operationTitle=bpmnDetail['bpmnName'])

                        elif key == "http":
                            self.step['arguments'].pop('resource', None)
                            self.step['arguments'] = {'params': {}}
                            self.step['arguments']['params'].update(url=bpmnDetail['requestUrl'],
                                                                    body=bpmnDetail['requestBody'],
                                                                    method=bpmnDetail['requestMethod'], params='',
                                                                    verify=bpmnDetail['ignoreException'],
                                                                    headers=bpmnDetail['requestHeaders'])

                            self.step['arguments'].update(version='2.2.0',
                                                          operation=bpmnDetail.get('operation', 'api_call'),
                                                          connector='cyops_utilities',
                                                          operationTitle=bpmnDetail['bpmnName'])
                        # Set route in trigger step
                        if key == "startEvent":
                            self.step['arguments']['route'] = str(uuid.uuid4())
        except Exception as err:
            logger.exception(err_msg_5.format(key, bpmnDetail, item, str(err)))
            raise ConnectorError(err_msg_5.format(key, bpmnDetail, item, str(err)))


def toCybersponsePlaybookCamunda(data):
    try:
        workflows = []
        stepMappingID = {}
        stepMappingName = {}
        steps = []
        routes = []

        # Build Steps

        supportedBPMNSteps = ["exclusiveGateway", "startEvent", "endEvent", "userTask", "serviceTask", "scriptTask"]
        ignoreBPMNSteps = ["@attributes", "#text", "sequenceFlow", "documentation", "dataObject", "extensionElements"]

        for key in data['definitions']['process']:
            if key in supportedBPMNSteps:
                if isinstance(data['definitions']['process'][key], list):
                    for item in data['definitions']['process'][key]:
                        stepTmp = CybersponseStep()

                        # Get Connector Details
                        if key == "scriptTask":
                            connectorAction = item['@attributes']['scriptFormat'] if item['@attributes']['scriptFormat'] else None
                            connectorData = getConnectorData(item['@attributes']['name'], connectorAction)
                        else:
                            connectorData = None

                        # Get BPMN ID and Name
                        bpmnDetail = bpmnDetails(item, connectorData)

                        # To Identify Create/Update, Http, Mail Step
                        if 'bpmnFlowableType' in bpmnDetail:
                            key = bpmnDetail['bpmnFlowableType']

                        stepTmp.cyopsStep(key, bpmnDetail,
                                          data['definitions']['bpmndi:BPMNDiagram']['bpmndi:BPMNPlane'][
                                              'bpmndi:BPMNShape'])

                        stepMappingID[bpmnDetail['bpmnID']] = stepTmp.step['uuid']
                        stepMappingName[bpmnDetail['bpmnID']] = bpmnDetail['bpmnName']

                        steps.append(stepTmp.step)
                else:
                    stepTmp = CybersponseStep()

                    # Get Connector Details
                    if key == "scriptTask":
                        connectorAction = data['definitions']['process'][key]['@attributes']['scriptFormat'] if 'scriptFormat' in data['definitions']['process'][key]['@attributes'].keys() else None
                        connectorData = getConnectorData(data['definitions']['process'][key]['@attributes']['name'], connectorAction)
                    else:
                        connectorData = None

                    # Get BPMN ID and Name
                    bpmnDetail = bpmnDetails(data['definitions']['process'][key], connectorData)

                    # To Identify Create/Update, Http, Mail Step
                    if 'bpmnFlowableType' in bpmnDetail:
                        key = bpmnDetail['bpmnFlowableType']

                    stepTmp.cyopsStep(key, bpmnDetail,
                                      data['definitions']['bpmndi:BPMNDiagram']['bpmndi:BPMNPlane']['bpmndi:BPMNShape'])

                    stepMappingID[bpmnDetail['bpmnID']] = stepTmp.step['uuid']
                    stepMappingName[bpmnDetail['bpmnID']] = bpmnDetail['bpmnName']

                    steps.append(stepTmp.step)
            elif key not in ignoreBPMNSteps:
                logger.exception(err_msg_1.format(key))
                raise ConnectorError(err_msg_1.format(key))

        # Build Route
        for item in data['definitions']['process']['sequenceFlow']:
            tmp = {}

            tmp['@type'] = 'WorkflowRoute'
            tmp['uuid'] = str(uuid.uuid4())
            tmp['name'] = stepMappingName[item['@attributes']['sourceRef']] + ' -> ' + stepMappingName[
                item['@attributes']['targetRef']]
            tmp['label'] = ""
            tmp['isExecuted'] = False
            tmp['sourceStep'] = '/api/3/workflow_steps/{}'.format(stepMappingID[item['@attributes']['sourceRef']])
            tmp['targetStep'] = '/api/3/workflow_steps/{}'.format(stepMappingID[item['@attributes']['targetRef']])

            routes.append(tmp)

        # Update Condition in Steps
        for item in data['definitions']['process']['sequenceFlow']:
            if 'conditionExpression' in item:

                tmpCondition = {}
                tmpCondition['step_iri'] = '/api/3/workflow_steps/{}'.format(
                    stepMappingID[item['@attributes']['targetRef']])

                if 'name' in item['@attributes']:
                    tmpCondition['condition'] = item['@attributes']['name']

                cyberSponseStepID = stepMappingID[item['@attributes']['sourceRef']]

                for item in steps:
                    if (item['uuid'] == cyberSponseStepID):
                        item['arguments']['conditions'].append(tmpCondition)

        # Build Workflows
        # Get the trigger step id from steps
        for item in steps:
            if (item['stepType'] == '/api/3/workflow_step_types/f414d039-bb0d-4e59-9c39-a8f1e880b18a'):
                triggerStepID = item['uuid']
                workflowData['triggerStep'] = '/api/3/workflow_steps/{}'.format(triggerStepID)

        workflowData['name'] = data['definitions']['process']['@attributes']['name']
        workflowData['steps'] = steps
        workflowData['routes'] = routes
        workflowData['uuid'] = str(uuid.uuid4())

        workflows.append(workflowData)

        # Build Playbook
        playbook['data'][0]['workflows'] = workflows

        return playbook

    except Exception as e:
        logger.exception(err_msg_3.format(str(e)))
        raise ConnectorError(err_msg_3.format(str(e)))


def coordinates(key, data, bpmnID):
    coordinates = {}

    for item in data:
        if item['@attributes']['id'] == 'BPMNShape_' + bpmnID or item['@attributes']['bpmnElement'] == bpmnID:
            left = item['omgdc:Bounds']['@attributes']['x']
            top = item['omgdc:Bounds']['@attributes']['y']
            if key == 'startEvent':
                coordinates['left'] = 20
                coordinates['top'] = 20
            elif key == 'endEvent':
                coordinates['left'] = 200 + (float(left) * 1.7)
                coordinates['top'] = float(top) * 1.7
            else:
                coordinates['left'] = float(left) * 1.7
                coordinates['top'] = float(top) * 1.7
    if coordinates:
        return coordinates
    else:
        logger.exception(err_msg_4.format(bpmnID, str('Unable to retreive co-ordinates')))
        raise ConnectorError(err_msg_4.format(bpmnID, str('Unable to retreive co-ordinates')))


def bpmnDetails(data, connectorData=None):
    bpmnDetail = {}

    try:
        if '@attributes' in data:

            bpmnDetail['bpmnID'] = data['@attributes']['id']
            bpmnDetail['bpmnName'] = data['@attributes']['name']
            if 'flowable:class' in data['@attributes']:
                if data['@attributes']['flowable:class'] in cybersponseModules:
                    bpmnDetail['bpmnModuleName'] = data['@attributes']['flowable:class']
                    bpmnDetail['bpmnFieldType'] = data['extensionElements']['flowable:field']['@attributes']['name']

            if 'flowable:type' in data['@attributes']:

                bpmnDetail['bpmnFlowableType'] = data['@attributes']['flowable:type']
                if (data['extensionElements'] and data['extensionElements']['flowable:field']):
                    for item in data['extensionElements']['flowable:field']:
                        if (item['@attributes'] and item['flowable:string']):
                            bpmnDetail[item['@attributes']['name']] = item['flowable:string']['#cdata-section']

            # For conenctor action name from scriptTask
            bpmnDetail['connectorActionName'] = data['@attributes']['scriptFormat'] if 'scriptFormat' in data['@attributes'].keys() else ""

        else:
            bpmnDetail['bpmnID'] = data['id']
            bpmnDetail['bpmnName'] = data['name']
            if ('flowable:class' in data):
                if (data['flowable:class'] in cybersponseModules):
                    bpmnDetail['bpmnModuleName'] = data['flowable:class']
                    bpmnDetail['bpmnFieldType'] = data['extensionElements']['flowable:field']['@attibute']['name']

            if ('flowable:type' in data):
                bpmnDetail['bpmnFlowableType'] = data['flowable:type']

            # For conenctor action name from scriptTask
            bpmnDetail['connectorActionName'] = data.get("scriptFormat", "")

    except Exception as err:
        logger.exception(err_msg_6.format(str(err), str(data)))
        raise ConnectorError(err_msg_6.format(str(err), str(data)))

    # For Script Task
    if isinstance(connectorData, (dict, str)):

        if not connectorData['connectorParams']:
            bpmnDetail['connectorName'] = ""
        else:
            bpmnDetail['connectorName'] = bpmnDetail['bpmnName']
        # Get Connectores latest version
        bpmnDetail['connectorAction'] = connectorData['connectorAction']
        bpmnDetail['connectorParams'] = connectorData['connectorParams']
        bpmnDetail['connectorVersion'] = connectorData['connectorVersion']

    return bpmnDetail


def cyopsStepType(key, bpmnFieldType=None):
    for item in configData:
        if item['bpmnStepType']:
            if item['bpmnFieldType']:
                if key in item['bpmnStepType'] and bpmnFieldType == item['bpmnFieldType']:
                    return item['@id']
            elif key in item['bpmnStepType']:
                return item['@id']


def getConnectorData(name, action):
    connectorData = {}
    connectorVersion = getConnectorVersion(name)

    if connectorVersion:
        connectorData['connectorVersion'] = connectorVersion['version']
        connectorDetails = getConnectorParams(connectorVersion['name'], connectorData['connectorVersion'], action)
        connectorData['connectorAction'] = connectorDetails['connectorAction']
        connectorData['connectorParams'] = connectorDetails['connectorParams']
    else:
        connectorData['connectorVersion'] = ''
        connectorData['connectorAction'] = ''
        connectorData['connectorParams'] = ''
    return connectorData


def getConnectorVersion(connectorName):
    url = "/api/integration/connectors/?ordering=label&page_size=30&search={}".format(urllib.parse.quote(connectorName.lower()))

    # params = {"ordering": "label", "page_size": 30, "search": connectorName}
    try:
        req = make_cyops_request(url, 'GET')
        if len(req['data']) != 0:
            req['data'][0].pop('icon_small')
            return req['data'][0]
        else:
            logger.warning(err_msg_2.format(connectorName, str('Connector Not Installed')))
            return {}
    except Exception as err:     
        logger.exception(err_msg_2.format(connectorName, str(err)))
        raise ConnectorError(err_msg_2.format(connectorName, str(err)))

def getConnectorParams(connectorName, version, action):
    connectorParams = {}
    url = "/api/integration/connectors/{}/{}/".format(connectorName, version)
    params = {"format": "json"}

    try:
        req = make_cyops_request(url, 'GET', params=params)
        operationName = []
        
        for item in req['operations']:
            operationName.append(item['title'])

        for item in req['operations']:
            if item['title'] == action:
                connectorParams['connectorAction'] = item['operation']

                temp = {}
                for a in item['parameters']:
                    temp[a['name']] = 'Place Holder'

                connectorParams['connectorParams'] = temp
            elif action not in operationName:
                connectorParams['connectorAction'] = ""
                connectorParams['connectorParams'] = ""
        return connectorParams
    except Exception as err:
        logger.exception(err_msg_2.format(connectorName, str(err)))
        raise ConnectorError(err_msg_2.format(connectorName, str(err)))
