""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
# -----------------------------------------
# VMware Carbon Black EDR
# -----------------------------------------

from .operations import *
from connectors.core.connector import Connector, get_logger, ConnectorError, api_health_check
logger = get_logger('cb-response')


operations = {'get_host_details': get_host_details,
              'get_process_list': get_process_list,
              'terminate_process': terminate_process,
              'isolate_sensor': isolate_sensor,
              'unisolate_sensor': unisolate_sensor,
              'get_blacklisted_hash': get_blacklisted_hash,
              'get_file_info_md5': get_file_info_md5,
              'block_hash': block_hash,
              'unblock_hash': unblock_hash,
              'run_query': run_query,
              'list_connections': list_connections,
              'hunt_file': hunt_file,
              'delete_file': delete_file,
              'search_alert': search_alert,
              'get_watchlist': get_watchlist,
              'update_alert': update_alert,
              'bulk_update_alert': bulk_update_alert
              }


class CarbonBlack(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('execute(): operation is {}'.format(str(operation)))
        try:
            operation = operations.get(operation)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config, params)

    def check_health(self, config):
        logger.info('starting health check %s', config)
        #todo use api_check_health
        check_health_ex(config)
        logger.info('completed health check no errors')
