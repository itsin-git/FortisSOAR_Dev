""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request
from time import time, ctime
from datetime import datetime
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config

logger = get_logger('azure-log-analytics')

MANAGE_SCOPE = 'https://management.azure.com/.default'
LOG_SCOPE = 'https://api.loganalytics.io/.default'
CLIENT_CREDENTIALS = 'client_credentials'


class MicrosoftAuth:
    def __init__(self, config):
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.verify_ssl = config.get('verify_ssl')
        self.scope = config.get('scope', MANAGE_SCOPE)
        tenant_id = config.get('tenant_id')
        self.token_url = "https://login.microsoftonline.com/{0}/oauth2/token".format(tenant_id)

    def convert_ts_epoch(self, ts):
        datetime_object = datetime.strptime(ctime(ts), "%a %b %d %H:%M:%S %Y")
        return datetime_object.timestamp()

    def generate_token(self, scope=MANAGE_SCOPE):
        try:
            resp = self.acquire_token_with_client_credentials(scope)
            ts_now = time()
            resp['expiresOn'] = (ts_now + int(resp['expires_in'])) if resp.get("expires_in") else None
            resp['accessToken'] = resp.get("access_token")
            resp.pop("access_token")
            return resp

        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))

    def validate_token(self, connector_config, connector_info):
        ts_now = time()
        expires = connector_config['expiresOn']
        expires_ts = self.convert_ts_epoch(expires)
        if ts_now > float(expires_ts):
            config_id = connector_config['config_id']
            logger.info("Token expired at {0}".format(expires))
            token_resp = self.generate_token()
            connector_config['accessToken'] = token_resp['accessToken']
            connector_config['expiresOn'] = token_resp['expiresOn']
            connector_config['refresh_token'] = token_resp.get('refresh_token')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                     connector_config,
                                     connector_config['config_id'])
            connector_config['config_id'] = config_id
            return "Bearer {0}".format(connector_config.get('accessToken'))
        else:
            logger.info("Token is valid till {0}".format(expires))
            return "Bearer {0}".format(connector_config.get('accessToken'))

    def validate_log_token(self, connector_config, connector_info):
        ts_now = time()
        expires = connector_config['logExpiresOn']
        expires_ts = self.convert_ts_epoch(expires)
        if ts_now > float(expires_ts):
            logger.info("Token expired at {0}".format(expires))
            token_resp = self.generate_token(LOG_SCOPE)
            connector_config['logAccessToken'] = token_resp['accessToken']
            connector_config['logExpiresOn'] = token_resp['expiresOn']
            connector_config['logRefreshToken'] = token_resp.get('refresh_token')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                     connector_config,
                                     connector_config['config_id'])
            return "Bearer {0}".format(connector_config.get('logAccessToken'))
        else:
            logger.info("Token is valid till {0}".format(expires))
            return "Bearer {0}".format(connector_config.get('logAccessToken'))

    def acquire_token_with_client_credentials(self, scope):
        try:
            data = {
                "grant_type": CLIENT_CREDENTIALS,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": scope,
            }
            if scope == "https://management.azure.com/.default":
                data.update({'resource': 'https://management.azure.com'})
            else:
                data.update({'resource': 'https://api.loganalytics.io'})
            res = request("POST", self.token_url, data=data, verify=self.verify_ssl)
            if res.status_code in [200, 204, 201]:
                return res.json()
            else:
                if res.text != "":
                    err_resp = res.json()
                    if err_resp and 'error' in err_resp:
                        failure_msg = err_resp.get('error_description')
                        error_msg = 'Response {0}: {1} \n Error Message: {2}'.format(res.status_code, res.reason,
                                                                                     failure_msg if failure_msg else '')
                    else:
                        error_msg = res.text
                else:
                    error_msg = '{0}:{1}'.format(res.status_code, res.reason)
                raise ConnectorError(error_msg)
        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))
