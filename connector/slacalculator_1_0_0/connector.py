from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import functions

logger = get_logger('sla')

import datetime

class sla(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            action = functions.get(operation)
            logger.debug('Action name {}'.format(action))
            return action(config, params)
        except Exception as e:
            raise ConnectorError('{}'.format(e))

    def check_health(self, config):
        full_time = config.get('full_time')
        is_custom = config.get('isCustom')
        customHolidays = config.get('customHolidays')
        if full_time == True or is_custom == False:
          return True
        else:
          custom_Holidays = [day.strip() for day in customHolidays.split(',')]
          for date1 in custom_Holidays:
              try:
                date_text = datetime.datetime.strptime(date1, '%Y-%m-%d')
              except Exception as err:
                logger.exception("Exception - {}".format(err))
                raise ConnectorError('Incorrect custom date format, should be comma separated in YYYY-MM-DD format')
