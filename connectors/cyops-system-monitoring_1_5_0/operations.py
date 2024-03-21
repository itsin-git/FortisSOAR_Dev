import subprocess
import psutil
import requests
from connectors.core.connector import get_logger, ConnectorError, SDK_VERSION
from integrations.crudhub import make_request
logger = get_logger('monitoring')


def disk_utilization(config, params, **kwargs):

    try:
        disk_part = psutil.disk_partitions()

        t = []
        for item in disk_part:
            sdiskpart = {"sdiskpart": dict(item._asdict())}

            disk_usage = psutil.disk_usage(sdiskpart['sdiskpart']['mountpoint'])
            disk_usages = {"sdiskusage": dict(disk_usage._asdict())}

            sdiskpart['sdiskpart']['disk_usage'] = disk_usages['sdiskusage']

            t.append(sdiskpart)

        return t
    except Exception as e:
        logger.exception(e)
        raise ConnectorError(e)

def virtual_memory(config, params, **kwargs):

    try:
        svem = psutil.virtual_memory()
        return {'svem': dict(svem._asdict())}
    except Exception as e:
        logger.exception(e)
        raise ConnectorError(e)

def cpu_percent(config, params, **kwargs):

    try:
        return psutil.cpu_percent()
    except Exception as e:
        logger.exception(e)
        raise ConnectorError(e)

def service_status(config, params, **kwargs):

    services = ["rabbitmq-server",
                "elasticsearch",
                "redis",
                "nginx",
                "php-fpm",
                "cyops-auth",
                "uwsgi",
                "celeryd",
                "celerybeatd",
                "cyops-tomcat",
                "cyops-search",
                "cyops-ha"
                ]

    cyops_version = SDK_VERSION.replace('.', '')
    if int(cyops_version) < 641:
        license_details = make_request(url='/api/auth/license/?param=license_details', method='GET')
        licenseType = license_details.get('details', {}).get('is_distributed', False)
        if licenseType:
            services.append("cyops-postman")
    else:
        services.append("cyops-postman")
        services.append("cyops-integrations-agent")
    if int(cyops_version) >= 700:
        services.remove('redis')
    if int(cyops_version) >= 730:
        services.append('postgresql-14')
    else: 
        services.append('postgresql-12')
    try:
        statuses = []
        for service in services:
            service_info = subprocess.check_output(["systemctl", "show", service], universal_newlines=True).split('\n')
            service_dict = {}
            for info in service_info:
                kv = info.split("=", 1)
                if len(kv) == 2:
                    service_dict[kv[0]] = kv[1]
            statuses.append({'service': service,
                             'ActiveState': service_dict['ActiveState'],
                             'SubState': service_dict['SubState']
                            })
        return statuses
    except Exception as e:
        logger.exception(e)
        raise ConnectorError(e)

def _check_health(config):
    try:
        count = psutil.cpu_count()
        logger.info("Health check successfully completed.")
        return True
    except Exception as e:
        logger.exception("Health check failed.")
        raise ConnectorError(e)

operations = {
    'disk_utilization': disk_utilization,
    'virtual_memory': virtual_memory,
    'cpu_percent': cpu_percent,
    'service_status': service_status
}
