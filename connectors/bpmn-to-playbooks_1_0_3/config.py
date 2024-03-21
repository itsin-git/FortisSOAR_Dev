cybersponseModules = ['Alerts', 'Incidents', 'Indicators', 'Assets', 'Events', 'Scans', 'Vulnerabilities']

configData = [
    {
        'cyopsStepType': 'CyopsUtilites',
        'bpmnFieldType': '',
        'bpmnStepType': ['http', 'endEvent'],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/0109f35d-090b-4a2b-bd8a-94cbc3508562',
        'cyopsStepArguments': {
            'name': 'CyOPs Utilities',
            'params': [],
            'version': '2.2.0',
            'connector': 'cyops_utilities',
            'operation': 'no_op',
            'operationTitle': 'Utils: No Operation',
            'step_variables': []
        }
    },
    {
        'cyopsStepType': 'SetVariable',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/04d0cf46-b6a8-42c4-8683-60a7eaa69e8f'
    },
    {
        'cyopsStepType': 'Connectors',
        'bpmnFieldType': '',
        'bpmnStepType': ['scriptTask'],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/0bfed618-0316-11e7-93ae-92361f002671',
        'cyopsStepArguments': {}
    },
    {
        'cyopsStepType': 'cybersponse.pre_update',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/0d375573-1c17-47bb-9790-934cff200ec4'
    },
    {
        'cyopsStepType': 'Decision',
        'bpmnFieldType': '',
        'bpmnStepType': ['exclusiveGateway'],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/12254cf5-5db7-4b1a-8cb1-3af081924b28',
        'cyopsStepArguments': {'conditions': []}
    },
    {
        'cyopsStepType': 'InsertData',
        'bpmnFieldType': 'Create',
        'bpmnStepType': ['serviceTask'],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/2597053c-e718-44b4-8394-4d40fe26d357',
        'cyopsStepArguments': {
            'resource': {
                'name': ''
            }
        }
    },
    {
        'cyopsStepType': 'SendMail',
        'bpmnFieldType': '',
        'bpmnStepType': ['mail'],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/4c0019b2-055c-44d0-968c-678a0c2d762e',
        'cyopsStepArguments': {'params': {}}
    },
    {
        'cyopsStepType': 'Delay',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/6832e556-b9c7-497a-babe-feda3bd27dbf'
    },
    {
        'cyopsStepType': 'Approval',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/6832e556-b9c7-497a-babe-feda3bd27dcg'
    },
    {
        'cyopsStepType': 'WorkflowReference',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/74932bdc-b8b6-4d24-88c4-1a4dfbc524f3'
    },
    {
        'cyopsStepType': 'cybersponse.post_update',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/9300bf69-5063-486d-b3a6-47eb9da24872'
    },
    {
        'cyopsStepType': 'APICall',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/949779e9-c4c2-4652-9ad2-c1875be6be54'
    },
    {
        'cyopsStepType': 'SetPlaybookResult',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/9dcc4bf5-b6cf-4a5c-b545-1fac3b9e33e6'
    },
    {
        'cyopsStepType': 'cybersponse.pre_delete',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/a987479e-9c96-46b0-9598-7f0b35e16ad2'
    },
    {
        'cyopsStepType': 'cybersponse.pre_create',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/aed55d18-1974-4743-b061-7f5a4292e657'
    },
    {
        'cyopsStepType': 'SetAPIKeys',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b104e839-fc31-48b3-8c50-7e9433f33d79'
    },
    {
        'cyopsStepType': 'cybersponse.abstract_trigger',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b348f017-9a94-471f-87f8-ce88b6a7ad62'
    },
    {
        'cyopsStepType': 'UpdateRecord',
        'bpmnFieldType': 'Update',
        'bpmnStepType': ['serviceTask'],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928722',
        'cyopsStepArguments': {
            'resource': {
                'name': ''
            }
        }
    },
    {
        'cyopsStepType': 'DownloadFile',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928723'
    },
    {
        'cyopsStepType': 'FileStringAttachment',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928724'
    },
    {
        'cyopsStepType': 'FileSFTP',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928725'
    },
    {
        'cyopsStepType': 'RemoteCommand',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928726'
    },
    {
        'cyopsStepType': 'MapPlaybook',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928728'
    },
    {
        'cyopsStepType': 'DatabaseConnector',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928745'
    },
    {
        'cyopsStepType': 'FindRecords',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928770'
    },
    {
        'cyopsStepType': 'SendEmail',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928778'
    },
    {
        'cyopsStepType': 'FetchEmail',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928789'
    },
    {
        'cyopsStepType': 'FileAttachment',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928796'
    },
    {
        'cyopsStepType': 'DatabaseQuery',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928799'
    },
    {
        'cyopsStepType': 'ManualDecision',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/dc61b68b-4967-4e82-b4ed-a1315aa81998'
    },
    {
        'cyopsStepType': 'ManualTask',
        'bpmnFieldType': '',
        'bpmnStepType': ['serviceTask', 'userTask'],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/dc6ac63d-c5a5-472f-9eb4-6b18473a98b8',
        'cyopsStepArguments': {
            'resource': {
                'name': ''
            }
        }
    },
    {
        'cyopsStepType': 'cybersponse.api_call',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/df26c7a2-4166-4ca5-91e5-548e24c01b5f'
    },
    {
        'cyopsStepType': 'cybersponse.post_create',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/ea155646-3821-4542-9702-b246da430a8d'
    },
    {
        'cyopsStepType': 'RunScript',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/ee73e569-2188-43fe-a7f0-1964ba82a4de'
    },
    {
        'cyopsStepType': 'cybersponse.post_delete',
        'bpmnFieldType': '',
        'bpmnStepType': [],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/ef350fda-1771-477a-8f90-16f68cd7e5cb'
    },
    {
        'cyopsStepType': 'cybersponse.action',
        'bpmnFieldType': '',
        'bpmnStepType': ['startEvent'],
        'cyopsStepTypeIRI': '/api/3/workflow_step_types/f414d039-bb0d-4e59-9c39-a8f1e880b18a',
        'cyopsStepArguments': {
            'resources': [
                'alerts'
            ],
            'inputVariables': [],
            'step_variables': {
                'input': {
                    'records': '{{vars.request.data.records}}'
                }
            },
            'displayConditions': {
                'alerts': {
                    'sort': [],
                    'limit': 30,
                    'logic': 'AND',
                    'filters': []
                }
            },
            'executeButtonText': 'Execute',
            'noRecordExecution': True,
            'singleRecordExecution': False
        }
    }
]

playbook = {
    'type': 'workflow_collections',
    'data': [
        {
            '@context': '/api/3/contexts/WorkflowCollection',
            '@type': 'WorkflowCollection',
            'name': 'OpenC2',
            'description': '',
            'visible': True,
            'image': '',
            'id': 7807,
            'createUser': {
                'cyopsStepTypeIRI': '/api/3/people/3451141c-bac6-467c-8d72-85e0fab569ce',
                '@type': 'Person',
                'firstname': 'CS',
                'lastname': 'Admin',
                'title': 'Admin',
                'department': '',
                'email': 'soc@cybersponse.com',
                'description': '',
                'phoneFax': '',
                'phoneHome': '',
                'phoneMobile': '',
                'phoneWork': '646-275-9691',
                'companyId': '',
                'type': '',
                'userId': 'ce5a842b-fbbc-4c6e-8d35-a0438fcdf80c',
                'userType': '',
                'avatar': '',
                'createUser': '/api/3/people/3451141c-bac6-467c-8d72-85e0fab569ce',
                'createDate': 1546027976,
                'modifyUser': '/api/3/people/3451141c-bac6-467c-8d72-85e0fab569ce',
                'modifyDate': 1546555751,
                'id': 175,
                '@settings': '/api/3/user_settings/3451141c-bac6-467c-8d72-85e0fab569ce'
            },
            'createDate': 1548273945,
            'modifyUser': {
                'cyopsStepTypeIRI': '/api/3/people/3451141c-bac6-467c-8d72-85e0fab569ce',
                '@type': 'Person',
                'firstname': 'CS',
                'lastname': 'Admin',
                'title': 'Admin',
                'department': '',
                'email': 'soc@cybersponse.com',
                'description': '',
                'phoneFax': '',
                'phoneHome': '',
                'phoneMobile': '',
                'phoneWork': '646-275-9691',
                'companyId': '',
                'type': '',
                'userId': 'ce5a842b-fbbc-4c6e-8d35-a0438fcdf80c',
                'userType': '',
                'avatar': '',
                'createUser': '/api/3/people/3451141c-bac6-467c-8d72-85e0fab569ce',
                'createDate': 1546027976,
                'modifyUser': '/api/3/people/3451141c-bac6-467c-8d72-85e0fab569ce',
                'modifyDate': 1546555751,
                'id': 175,
                '@settings': '/api/3/user_settings/3451141c-bac6-467c-8d72-85e0fab569ce'
            },
            'modifyDate': 1548273945
        }
    ]
}

workflowData = {
    '@type': 'Workflow',
    '@triggerLimit': '',
    'description': '',
    'collection': '',
    'tag': '',
    'isActive': False,
    'singleRecordExecution': False,
    'remoteExecutableFlag': False,
    'parameters': [],
    'synchronus': False,
    'version': ''

}
