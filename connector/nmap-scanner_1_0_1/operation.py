import json, nmap
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('nmap-scanner')


def scan_network(params):
    try:
        hostname = params.get('hostname')
        port_list = params.get('port')
        args = params.get('args')
        nm = nmap.PortScanner()
        scan_output = nm.scan(hosts=hostname, ports=str(port_list), arguments=args)
        return json.loads(json.dumps(scan_output))
    except Exception as err:
        logger.error('{}'.format(err))
        raise ConnectorError('{}'.format(err))


def _check_health():
    nm = nmap.PortScanner()
    scan_output = nm.scan(hosts='google.com', ports="1000-1024")
    nmap_data = scan_output.get('nmap')
    if nmap_data:
        logger.info('connector available')
        return True


operations = {'scan_network': scan_network}
