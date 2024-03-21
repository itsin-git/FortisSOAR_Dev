""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import time, os
import base64
from base64 import b64encode
from integrations.crudhub import make_request, make_file_upload_request
from connectors.cyops_utilities.builtins import download_file_from_cyops
from connectors.core.connector import get_logger, ConnectorError
from .utils import QUERY_SCHEMA, FortiSandbox
from django.conf import settings

MACRO_LIST = ["URL_Enrichment_Playbooks_IRIs", "File_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "fortinet-fortisandbox"
logger = get_logger('fortisandbox')


def get_epoch(_date):
    try:
        pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        return int(time.mktime(time.strptime(_date, pattern)))
    except Exception as Err:
        logger.exception('get_epoch: Exception occurred [{0}]'.format(str(Err)))
        raise ConnectorError('get_epoch: Exception occurred [{0}]'.format(str(Err)))


def handle_params(params):
    try:
        if params.get('input_type') == 'Attachment ID':
            iri = params.get('attachment_iri')
            if not iri.startswith('/api/3/attachments/'):
                iri = '/api/3/attachments/{0}'.format(iri)
        elif params.get('input_type') == 'Indicator IRI':
            iri = params.get('indicator_iri')
            if not iri.startswith('/api/3/indicators/'):
                iri = '/api/3/indicators/{0}'.format(iri)
        response = make_request(iri, 'GET')
        return response['file']['@id'], response['file']['filename']

    except Exception as err:
        logger.exception('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError('Invalid attachment/indicator iri {0}'.format(iri))


def create_cyops_attachment(content, attachment_name, file_name):
    try:
        file_resp = make_file_upload_request(file_name, content, 'application/octet-stream')
        description = 'FortiSandbox: {0}'.format(file_name)
        payload = {'name': attachment_name, 'file': file_resp['@id'], 'description': description}
        return make_request('/api/3/attachments', 'POST', payload)
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)


def _check_health(config):
    try:
        response = get_system_status(config, {})
        if not response['result']['status']['message'] == 'OK':
            raise ConnectorError(response['result']['status']['message'])
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError('{0}'.format(err))


def submit_file(config, params):
    forti = FortiSandbox(config)
    try:
        file_iri, filename = handle_params(params)
        dw_file_md = download_file_from_cyops(file_iri)
        tmp_file_path = dw_file_md.get('cyops_file_path')
        file_name = dw_file_md.get('filename')
        if len(file_name) == 0 and len(tmp_file_path) > 0:
            new_name = tmp_file_path.split('/')
            if len(new_name) == 3:
                file_name = new_name[2]
            else:
                file_name = tmp_file_path
        file_path = os.path.join(settings.TMP_FILE_ROOT, tmp_file_path)
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()

        test_input = QUERY_SCHEMA.get('file_upload')
        test_input = forti._load_file_for_upload(file_data, test_input, filename)
        test_input['params'][0]['overwrite_vm_list'] = params['overwrite_vm_list']
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def submit_urlfile(config, params):
    forti = FortiSandbox(config)
    try:
        urls = params['url']
        if isinstance(urls, str):
            urls = urls.split(',')

        urls_value = '\n'.join(urls).replace(' ', '')

        test_input = QUERY_SCHEMA.get('file_upload_url')
        test_input = forti._load_file_for_upload(urls_value, test_input, 'auto_submitted_urls')
        test_input['params'][0]['overwrite_vm_list'] = params['overwrite_vm_list']
        test_input['params'][0]['timeout'] = '60' if params['timeout'] < 0 else str(params['timeout'])
        test_input['params'][0]['depth'] = '1' if params['depth'] else '0'
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_system_status(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get_status')
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_scan_stats(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get_scan_stats')
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_submission_job_list(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get-jobs-of-submission')
        test_input['params'][0]['sid'] = str(params['sid'])
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_scan_result_job(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get_job_verdict')
        test_input['params'][0]['jid'] = str(params['jid'])
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_file_rating(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get_file_rating')
        test_input['params'][0]['ctype'] = params['hash_type'].lower()
        test_input['params'][0]['checksum'] = params['file_hash']
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_url_rating(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get_url_rating')
        test_input['params'][0]['address'] = params['url'] if isinstance(params['url'], list) else [params['url']]
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_job_behaviour(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get-job-behavior')
        test_input['params'][0]['ctype'] = params['hash_type'].lower()
        test_input['params'][0]['checksum'] = params['file_hash']
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def cancel_submission(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('cancel-submission')
        test_input['params'][0]['sid'] = str(params['sid'])
        test_input['params'][0]['reason'] = params['reason']
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def handle_white_black_list(config, params):
    forti = FortiSandbox(config)
    try:
        indicator_value = params.get('indicator_value', '')

        indicator_type = params['indicator_type'].lower()
        if indicator_type == 'url regex':
            indicator_type = 'url_regex'

        if not indicator_value:
            indicator_value = ['test']

        indicator_value = indicator_value if isinstance(indicator_value, list) else [indicator_value]

        indicator_value = '\n'.join(indicator_value)

        test_input = QUERY_SCHEMA.get('white-black-list')
        test_input['params'][0]['list_type'] = params['list_type'].lower()
        test_input['params'][0]['checksum_type'] = indicator_type
        test_input['params'][0]['action'] = params['action'].lower()
        test_input['params'][0]['upload_file'] = b64encode(indicator_value.encode()).decode()
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        if params['action'].lower() == 'download':
            if not response['result']['status']['message'] == 'OK':
                return response
            download_file = response['result']['data']['download_file']
            if download_file:
                filename = '{0}_{1}.txt'.format(params['list_type'].lower(), params['indicator_type'].lower())
                attachment_name = 'FortiSandbox: Download {0} {1}'.format(params['list_type'], params['indicator_type'])
                return create_cyops_attachment(base64.b64decode(download_file.encode('utf-8')), attachment_name,
                                               filename)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def mark_sample_fp_fn(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('mark-sample-fp-fn')
        test_input['params'][0]['jid'] = str(params['jid'])
        test_input['params'][0]['comments'] = params['comments']
        test_input['params'][0]['cloud_submit'] = 0
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_avrescan(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get-avrescan')
        test_input['params'][0]['stime'] = get_epoch(params['stime'])
        test_input['params'][0]['etime'] = get_epoch(params['etime'])
        test_input['params'][0]['need_av_ver'] = 1 if params['need_av_ver'] else 0
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_file_verdict(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get-multiple-file-verdict')
        test_input['params'][0]['ctype'] = params['hash_type'].lower()
        test_input['params'][0]['checksum'] = params['file_hash'] if (isinstance(params['file_hash'], list)) else [
            params['file_hash']]
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_installed_vm(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get-all-installed-vm')
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def get_pdf_report(config, params):
    forti = FortiSandbox(config)
    try:
        test_input = QUERY_SCHEMA.get('get-pdf-report')
        test_input['params'][0]['qtype'] = params['qtype']
        test_input['params'][0]['qval'] = params['qval']
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        if not response['result']['status']['message'] == 'OK':
            return response
        report_details = response['result']['data']
        report_name, report_data = report_details.get('report_name'), report_details.get('report')
        attachment_name = 'FortiSandbox: Report'
        return create_cyops_attachment(base64.b64decode(report_data.encode('utf-8')), attachment_name, report_name)

    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


def download_hashes_url_from_mwpkg(config, params):
    forti = FortiSandbox(config)
    type_map = {'SHA256': 0, 'SHA1': 1, 'MD5': 2, 'URL': 3}
    test_input = QUERY_SCHEMA.get('download-malpkg')
    lazy = 1 if params['lazy'] else 0
    if lazy == 0:
        major, minor = params['major'], params['minor']
        test_input['params'][0]['major'] = major
        test_input['params'][0]['minor'] = minor

    try:
        test_input['params'][0]['lazy'] = lazy
        test_input['params'][0]['type'] = type_map[params['type']]
        test_input['session'] = forti.session_id
        response = forti._handle_post(test_input)
        if response['result']['status']['message'] == 'OK':
            file = response['result']['data']['download_file']
            response['result']['data']['download_file'] = base64.b64decode(file.encode('utf-8')).decode()[:-1]
        return response
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(e)
    finally:
        forti.logout()


operations = {
    'submit_file': submit_file,
    'submit_urlfile': submit_urlfile,
    'get_system_status': get_system_status,
    'get_scan_stats': get_scan_stats,
    'get_submission_job_list': get_submission_job_list,
    'get_scan_result_job': get_scan_result_job,
    'get_file_rating': get_file_rating,
    'get_url_rating': get_url_rating,
    'get_file_verdict': get_file_verdict,
    'get_job_behaviour': get_job_behaviour,
    'cancel_submission': cancel_submission,
    'handle_white_black_list': handle_white_black_list,
    'mark_sample_fp_fn': mark_sample_fp_fn,
    'get_avrescan': get_avrescan,
    'get_installed_vm': get_installed_vm,
    'get_pdf_report': get_pdf_report,
    'download_hashes_url_from_mwpkg': download_hashes_url_from_mwpkg
}
