from tower_cli import get_resource
from tower_cli.conf import settings
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('ansible-tower')


def list_users(config, params):
    try:
        settings.runtime_values(username=config.get('username'), password=config.get('password'), host=config.get('host'))
        user_resource = get_resource('user')
        user_list = user_resource.list(all_pages = True)
        return {"users": user_list}
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def list_job_templates(config, params):
    try:
        settings.runtime_values(username=config.get('username'), password=config.get('password'),
                                host=config.get('host'))
        jt_resource = get_resource('job_template')
        jt_list = jt_resource.list(all_pages = True)
        jt_resource.delete()
        return {"job_templates": jt_list}
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def search_job_templates(config, params):
    try:
        settings.runtime_values(username=config.get('username'), password=config.get('password'),
                                host=config.get('host'))
        jt_resource = get_resource('job_template')
        jt_list = jt_resource.list(all_pages = True, query = [("name",params.get('name') )])
        jt_resource.list()
        return {"job_templates": jt_list}
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def launch_job(config, params):
    try:
        settings.runtime_values(username=config.get('username'), password=config.get('password'),
                                host=config.get('host'))
        job_resource = get_resource('job')
        job = job_resource.launch(job_template=params.get('template_name'), detail=True)
        return {"job_status": job}
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def get_job_status(config, params):
    try:
        settings.runtime_values(username=config.get('username'), password=config.get('password'),
                                host=config.get('host'))
        job_resource = get_resource('job')
        job = job_resource.status(pk=params.get('pk'), detail=True)
        return {"job_details": job}
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def _check_health(config):
    try:
        template_list = list_job_templates(config,None)
        if template_list:
            return True
    except Exception as err:
        logger.error('{}'.format(err))
        raise ConnectorError('{}'.format(err))


operations = {
    'list_users': list_users,
    'list_job_templates': list_job_templates,
    'search_job_templates': search_job_templates,
    'launch_job': launch_job,
    'get_job_status': get_job_status
}
