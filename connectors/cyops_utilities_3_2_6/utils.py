import re
import requests
from connectors.core.connector import get_logger, ConnectorError
from .errors.error_constants import *
from django.conf import settings
log = get_logger('cyops_utilities.builtins')

try:
    cyops_version = settings.RELEASE_VERSION
except Exception as e:
    from connectors.core.connector import SDK_VERSION
    cyops_version = SDK_VERSION

def convert_periodic_time_to_minutes(periodic_time, *args, **kwargs):
    """
    This operation returns the time in minutes for given
    stringified user time eg 1 Year, 2 Months, 3 Weeks, 1 day, 2 Hours
    :param stringified time for escalation to next tier:
    :return: time in minutes
    """
    total_minutes = 0
    if isinstance(periodic_time,str):
        array = periodic_time.split(',')
    else:
        array = periodic_time

    if not isinstance(array, list):
        raise ConnectorError(
            cs_connector_utility_2.format('periodic_time', periodic_time, 'Comma separated string or list',
                                          type(periodic_time)))

    for ele in array:
        if 'year' in ele.lower() or 'years' in ele.lower():
            number_of_year = re.findall(r'\d+', ele)
            if len(number_of_year) and len(number_of_year) == 1:
                total_minutes += eval(number_of_year[0]) * 24 * 60 * 30 * 12
            else:
                log.error(periodic_time)
                raise ConnectorError(cs_connector_utility_17.format('year/years'))
        if 'month' in ele.lower() or 'months' in ele.lower():
            number_of_month = re.findall(r'\d+', ele)
            if len(number_of_month) and len(number_of_month) == 1:
                total_minutes += eval(number_of_month[0]) * 24 * 60 * 30
            else:
                log.error(periodic_time)
                raise ConnectorError(cs_connector_utility_17.format('month/months'))
        if 'week' in ele.lower() or 'weeks' in ele.lower():
            number_of_week = re.findall(r'\d+', ele)
            if len(number_of_week) and len(number_of_week) == 1:
                total_minutes += eval(number_of_week[0]) * 24 * 60 * 7
            else:
                log.error(periodic_time)
                raise ConnectorError(cs_connector_utility_17.format('week/weeks'))
        if 'day' in ele.lower() or 'days' in ele.lower():
            number_of_day = re.findall(r'\d+', ele)
            if len(number_of_day) and len(number_of_day) == 1:
                total_minutes += eval(number_of_day[0]) * 24 * 60
            else:
                log.error(periodic_time)
                raise ConnectorError(cs_connector_utility_17.format('day/days'))
        if 'hour' in ele.lower() or 'hours' in ele.lower():
            number_of_hour = re.findall(r'\d+', ele)
            if len(number_of_hour) and len(number_of_hour) == 1:
                total_minutes += eval(number_of_hour[0]) * 60
            else:
                log.error(periodic_time)
                raise ConnectorError(cs_connector_utility_17.format('hour/hours'))
        if 'minute' in ele.lower() or 'min' in ele.lower() or 'minutes' in ele.lower():
            number_of_minute = re.findall(r'\d+', ele)
            if len(number_of_minute) and len(number_of_minute) == 1:
                total_minutes += eval(number_of_minute[0])
            else:
                log.error(periodic_time)
                raise ConnectorError(cs_connector_utility_17.format('minute/minutes'))
    return {"minutes": total_minutes}


def maybe_json_or_raise(response):
    """
    Helper function for processing request responses

    Returns any json found in the response. Otherwise, it will extract the
    response as text, or, failing that, as bytes.

    :return: the response from the request
    :rtype: dict or str or bytes
    :raises: :class:`requests.HTTPError` if status code was 4xx or 5xx
    """
    if response.ok:
        try:
            log.info('Processing request responses.')
            return response.json(strict=False)
        except Exception:
            log.warn(response.text or response.content)
            return response.text or response.content
    else:
        msg = ''
        try:
            msg = response.json()
            log.warn(msg)
        except Exception:
            pass
        if not msg:
            msg = response.text
            log.warn(msg)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            # add any response content to the error message
            error_msg = getErrorMessage(msg)
            if not error_msg:
                error_msg = '{} :: {}'.format(str(e), msg)
            log.error(error_msg)
            raise requests.exceptions.HTTPError(error_msg, response=response)

def getErrorMessage(msg):
    if type(msg) == dict:
        error_message = msg.get('hydra:description',False)
        if error_message:
            return error_message
        error_message = msg.get('message', False)
        if error_message:
            return error_message
    return False