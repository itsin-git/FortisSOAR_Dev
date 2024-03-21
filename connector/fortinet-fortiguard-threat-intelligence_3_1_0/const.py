ERRORS = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Invalid credentials provided failed to authorize',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error',
}

MAX_FEEDS_TO_PULL = 500
BATCH_SIZE = 1000
EXECUTION_PAUSE_COUNT = 20
EXECUTION_PAUSE_TIME = 10

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
