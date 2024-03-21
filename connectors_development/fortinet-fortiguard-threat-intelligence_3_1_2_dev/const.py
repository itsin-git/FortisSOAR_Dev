ERRORS = {
    400: 'The parameters are invalid.',
    401: 'Invalid credentials were provided or request not authorized',
    403: 'Access Denied',
    422: 'Parameters are missing in query/request body.',
    423: 'The parameters are invalid in path/query/request body.',
    500: 'Internal Server Error',
    503: 'Service Unavailable'
}

MAX_FEEDS_TO_PULL = 500
BATCH_SIZE = 1000
EXECUTION_PAUSE_COUNT = 20
EXECUTION_PAUSE_TIME = 10
MAX_RETRY = 5
SLEEP = 10

MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs", "URL_Enrichment_Playbooks_IRIs", "Domain_Enrichment_Playbooks_IRIs",
              "FileHash_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "fortinet-fortiguard-threat-intelligence"

SOURCE = {
    'Viruses': 'av',
    'Intrusion Prevention': 'ips',
    'Botnet': 'botnet',
    'Endpoint Vulnerabilities': 'fctvuln',
    'Mobile': 'mob',
    'Application': 'app',
    'Internet Services': 'isdb'
}

MESSAGE_404 = "Information not found"
