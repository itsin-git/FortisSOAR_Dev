""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from connectors.core.connector import get_logger, ConnectorError
import pendulum
import holidays as pyholidays
import datetime
from business_duration import businessDuration
import pytz

logger = get_logger('slacalculator')


def calculateSLA(config: dict, params: dict):
    try:
        work_start = config.get('work_start')
        work_end = config.get('work_end')
        first_day_weekend = config.get('firstDayWeekend')
        timezone = config.get('timezone')
        country = config.get('country')
        state = config.get('state')
        province = config.get('province')
        is_custom = config.get('isCustom')
        customHolidays = config.get('customHolidays')
        std_holidays = config.get('stdHolidays')
        full_time = config.get('full_time')

        record_create_time = params.get('recordCreateTime')
        sla_time = params.get('slaTime')

        if type(record_create_time) == str:
            date_object = datetime.datetime.strptime(record_create_time, "%Y-%m-%dT%H:%M:%S.%fZ")
            record_create_time = date_object.timestamp()

        # Converting record create date timestamp to pendulum date
        sla_start = pendulum.from_timestamp(record_create_time)
        # Convert the date to user defined timezone to perform all calculations based on this timezone
        sla_start = sla_start.in_timezone(timezone)
        sla_due_date = ""

        if full_time:
            sla_due_date = sla_start.add(minutes=sla_time)
            logger.info(
                "24X7 support, returning sla due date: {}".format(sla_due_date))
            sla_due_date_timestamp = sla_due_date.timestamp()
            return {"sla_due_date": sla_due_date, "sla_due_date_timestamp": sla_due_date_timestamp}

        # Convert Work Start and Work end hours to datetime
        work_start = pendulum.datetime(
            sla_start.year, sla_start.month, sla_start.day, work_start, 0, 0, tz=timezone)
        work_end = pendulum.datetime(
            sla_start.year, sla_start.month, sla_start.day, work_end, 0, 0, tz=timezone)

        # Converting the Global holidays and Custom Holidays given in String to Python Date Time
        holidays_list = _convert_holidays_into_dates(is_custom, customHolidays, std_holidays, country, province, state)

        logger.info(f"Holidays list are {holidays_list}")

        # Check if sla_start date falls on a weekend or a Holiday
        sla_start = _shift_to_earliest_workday(
            sla_start, holidays_list, work_start, first_day_weekend)

        # Shift Work start and Work end to the date of sla_start for further calculations
        work_start = pendulum.datetime(
            sla_start.year, sla_start.month, sla_start.day, work_start.hour, 0, 0, tz=timezone)
        work_end = pendulum.datetime(
            sla_start.year, sla_start.month, sla_start.day, work_end.hour, 0, 0, tz=timezone)

        # Check if record is created before next start of  work starts on that day
        if sla_start.time() < work_start.time():
            logger.info("Record is created before work starts, sla_start time: {}: work_start time- {}".format(
                sla_start.time(), work_start.time()))
            sla_start = work_start
        # Check if record is created after workend on that day
        elif sla_start > work_end or sla_start.time() > work_end.time():
            sla_start = work_start.add(days=1)
            # After sla_start is shifted check again if it falls on weekend or a holiday
            sla_start = _shift_to_earliest_workday(
                sla_start, holidays_list, work_start, first_day_weekend)
            # Calculate Work start and Work end based on shifted start date
            logger.info(
                "Record is created after workend, new sla_start-  {}".format(sla_start))
            work_start = pendulum.datetime(
                sla_start.year, sla_start.month, sla_start.day, work_start.hour, 0, 0, tz=timezone)
            work_end = pendulum.datetime(
                sla_start.year, sla_start.month, sla_start.day, work_end.hour, 0, 0, tz=timezone)

        # Time left today for sla = workend - sla_start
        time_left_today = sla_start.diff(work_end).in_minutes()
        logger.info("SLA start time_left_today :  {}".format(time_left_today))
        # Check if the sla is not spilling over to next day
        if time_left_today >= sla_time:
            logger.info(
                "SLA due by is within sla start date sla_due_date:{}".format(sla_due_date))
            sla_due_date = sla_start.add(minutes=sla_time)
        else:
            # If sla is spilling over to next day, calculate how much more time is required for the sla and shift the
            # start date, work_start and work_end to next day for further calculations
            tmr_time = sla_time - time_left_today
            logger.info(f"SLA is spilling to next day and remaining time is {tmr_time}")
            sla_start = work_start.add(days=1)
            sla_start = _shift_to_earliest_workday(
                sla_start, holidays_list, work_start, first_day_weekend)
            work_start = pendulum.datetime(
                sla_start.year, sla_start.month, sla_start.day, work_start.hour, 0, 0, tz=timezone)
            work_end = pendulum.datetime(
                sla_start.year, sla_start.month, sla_start.day, work_end.hour, 0, 0, tz=timezone)
            sla_due_date = sla_start.add(minutes=tmr_time)

            time_left_today = sla_start.diff(work_end).in_minutes()

            # Keep shifting start day until the time left does not fall in working window
            while tmr_time > time_left_today:
                logger.info("While loop iteration tmr_time : {} time_left_today: {}".format(
                    tmr_time, time_left_today))
                sla_start = _shift_to_earliest_workday(
                    sla_start, holidays_list, work_start, first_day_weekend)
                work_start = pendulum.datetime(
                    sla_start.year, sla_start.month, sla_start.day, work_start.hour, 0, 0, tz=timezone)
                work_end = pendulum.datetime(
                    sla_start.year, sla_start.month, sla_start.day, work_end.hour, 0, 0, tz=timezone)
                time_left_today = sla_start.diff(work_end).in_minutes()

                # Check if the remaining time falls under current working window
                if time_left_today >= tmr_time:
                    sla_due_date = sla_start.add(minutes=tmr_time)
                    sla_due_date = _shift_to_earliest_workday(
                        sla_due_date, holidays_list, work_start, first_day_weekend)
                    logger.info(
                        "Exiting while loop  as remaining time falls under current working window tmr_time: {} "
                        "time_left_today: {}".format(
                            tmr_time, time_left_today))
                    break
                else:
                    # sla time is more than the current working window hence, shift start time to next day
                    tmr_time = tmr_time - time_left_today
                    sla_start = work_start.add(days=1)
                    sla_due_date = sla_start.add(minutes=tmr_time)
                    sla_due_date = _shift_to_earliest_workday(
                        sla_due_date, holidays_list, work_start, first_day_weekend)
                    logger.info("Continue while loop tmr_time: {} time_left_today: {} sla_due_date : {} ".format(
                        tmr_time, time_left_today, sla_due_date))

        sla_due_date = sla_due_date.replace(tzinfo=timezone)
        logger.info("sla_due_date with tzinfo:  {}".format(sla_due_date))
        sla_due_date_timestamp = sla_due_date.timestamp()
        return {"sla_due_date": sla_due_date, "sla_due_date_timestamp": sla_due_date_timestamp}
    except Exception as e:
        logger.error(f" Error in Calculate SLA with error {e}")
        raise ConnectorError(e)


def _shift_to_earliest_workday(sla_start, holidays_list, work_start, first_day_weekend, iteration_index=0):
    if iteration_index > 10:
        raise ConnectorError(
            'Iteration count reached max limit(10).Check the SLA configurations and input params.')
    logger.info(
        "_shift_to_earliest_workday iteration index count: {}".format(iteration_index))
    days_of_week = ['Monday', 'Tuesday', 'Wednesday',
                    'Thursday', 'Friday', 'Saturday', 'Sunday']
    weekend_day_number = days_of_week.index(first_day_weekend)
    logger.info("sift_to_earliest_workday : SLA start before shifting to working day{}".format(sla_start))

    while sla_start.date() in holidays_list:
        sla_start = sla_start.add(days=1)
        sla_start = _shift_to_earliest_workday(
            sla_start, holidays_list, work_start, first_day_weekend, iteration_index=iteration_index + 1)
        logger.info("sla_start after adjusting holiday: {}".format(sla_start))

    # Check if sla_start is a first day of the Weekend
    day_number = sla_start.weekday()
    if day_number == weekend_day_number:
        logger.info("SLA date is on weekend, adding 2 days")
        sla_start = sla_start.add(days=2)
        sla_start = _shift_to_earliest_workday(
            sla_start, holidays_list, work_start, first_day_weekend, iteration_index=iteration_index + 1)
        logger.info("SLA after weekend adjust: {}".format(sla_start))
    # Check if sla_start is a last day of the weekend
    elif day_number == (weekend_day_number + 1):
        logger.info("SLA date is on the last day of the weekend, adding 1 days")
        sla_start = sla_start.add(days=1)
        sla_start = _shift_to_earliest_workday(
            sla_start, holidays_list, work_start, first_day_weekend, iteration_index=iteration_index + 1)
        logger.info(
            "SLA after last day of weekend adjust: {}".format(sla_start))

    return sla_start


def calculate_elapsed_time(config: dict, params: dict):
    work_start_hour = config.get('work_start')
    work_end_hour = config.get('work_end')
    first_day_weekend = config.get('firstDayWeekend')
    timezone = config.get('timezone')
    country = config.get('country')
    state = config.get('state')
    province = config.get('province')
    is_custom = config.get('isCustom')
    customHolidays = config.get('customHolidays')
    std_holidays = config.get('stdHolidays')
    full_time = config.get('full_time')
    total_sla_time = params.get('sla_time', 0)

    target_timezone = pytz.timezone(timezone)

    start_datetime = params.get('start_datetime')
    end_datetime = params.get('end_datetime')

    if type(start_datetime) == str:
        date_object = datetime.datetime.strptime(start_datetime, "%Y-%m-%dT%H:%M:%S.%fZ")
        start_datetime = date_object.timestamp()

    if type(end_datetime) == str:
        date_object = datetime.datetime.strptime(end_datetime, "%Y-%m-%dT%H:%M:%S.%fZ")
        end_datetime = date_object.timestamp()

    if start_datetime > end_datetime:
        raise ConnectorError("Start time is greater than End Time")

    # Converting record create date timestamp to pendulum date with timezone
    sla_start = pendulum.from_timestamp(start_datetime, tz=timezone)
    logger.info("sla_start {}".format(sla_start))

    if full_time:
        sla_end = pendulum.from_timestamp(end_datetime, tz=timezone)
        minutes_left = sla_end.diff(sla_start).in_minutes()
        minutes_past = total_sla_time - minutes_left
        logger.info("minutes_past: {} and minutes_left: {}".format(
            minutes_past, minutes_left))
        return {"minutes_past": minutes_past, "minutes_left": minutes_left}

    # Converting the Global holidays and Custom Holidays given in String to Python Date Time
    holidays_list = _convert_holidays_into_dates(is_custom, customHolidays, std_holidays, country, province, state)

    days_of_week = ['Monday', 'Tuesday', 'Wednesday',
                    'Thursday', 'Friday', 'Saturday', 'Sunday']
    first_day_weekend = days_of_week.index(first_day_weekend)

    # date must be in standard python datetime format
    start_date = datetime.datetime.fromtimestamp(start_datetime).astimezone(target_timezone)
    end_date = datetime.datetime.fromtimestamp(end_datetime).astimezone(target_timezone)
    work_start_time = datetime.time(work_start_hour, 0, 0)
    work_end_time = datetime.time(work_end_hour, 0, 0)
    weekendlist = [first_day_weekend, first_day_weekend + 1]
    minutes_past = businessDuration(startdate=start_date, enddate=end_date, starttime=work_start_time,
                                    endtime=work_end_time, weekendlist=weekendlist, holidaylist=holidays_list,
                                    unit='min')

    return {"minutes_past": minutes_past, "minutes_left": total_sla_time - minutes_past}


def _convert_holidays_into_dates(is_custom: bool, customHolidays: str, std_holidays: bool, country: str, province: str,
                                 state: str):
    holidays_list = []
    if is_custom and (len(customHolidays) > 0):
        # save Custom Holidays in a list
        try:
            holidays_list = [datetime.datetime.strptime(day.strip(), '%Y-%m-%d').date()
                             for day in customHolidays.split(',')]
        except Exception as err:
            logger.exception("Exception - {}".format(err))
            raise ConnectorError(
                'Incorrect custom date format, should be comma separated in YYYY-MM-DD format')

    if std_holidays:
        # Get the list of global holidays using holidays package
        for ptr in pyholidays.country_holidays(country=country, prov=province, state=state,
                                               years=datetime.date.today().year).items():
            holidays_list.append(ptr[0])

    return holidays_list


functions = {
    'calculateSLA': calculateSLA,
    'calculate_elapsed_time': calculate_elapsed_time
}
