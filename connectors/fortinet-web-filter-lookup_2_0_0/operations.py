""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
import requests
import requests.exceptions as req_exceptions

MACRO_LIST = ["URL_Enrichment_Playbooks_IRIs", "Domain_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "fortinet-web-filter-lookup"
logger = get_logger('fortinet-web-filter-lookup')


class FortiGuard(object):
    def __init__(self, config):
        self.base_url = config.get('base_url') + '/v1/rate'
        self.verify_ssl = config.get('verify_ssl')
        self.token = config.get("token")

    def get_response(self, sample_url):
        try:
            url = self.base_url
            use_ssl = self.verify_ssl
            params = {'url': sample_url, 'cate_ver': 8}
            header = {'Accept': 'application/json', 'Token': self.token}
            response = requests.get(url=url, params=params, headers=header, verify=use_ssl)
            if response.status_code == 200:
                json_payload = response.json()
                return {'url': sample_url, 'category': json_payload['categoryname'], 'info': json_payload['categoryid']}
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp.get("title") or ""
                    error_msg = 'Response [{0}:{1} Details:{2}]'.format(response.status_code, response.reason, failure_msg)
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)

        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error(str(err))
            raise ConnectorError('{0}'.format(str(err)))


def url_review(config, params):
    s = FortiGuard(config)
    sample_url = params.get('sample_url')
    return s.get_response(sample_url)


def health_check(config):
    logger.info('Initiating Connector Health Check')
    s = FortiGuard(config)
    response = s.get_response("https://fortinet.com")
    return True


operations = {
    'url_review': url_review
}
