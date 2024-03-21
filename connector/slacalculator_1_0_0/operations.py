
from connectors.core.connector import get_logger, ConnectorError
import pendulum
import holidays as pyholidays
import datetime


logger = get_logger('sla')

def calculateSLA(config, params):
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
        stdHolidays = config.get('stdHolidays')
        full_time = config.get('full_time')

        recd_ct_time = params.get('recordCreateTime')
        sla_time = params.get('slaTime')

        # Converting record create date timestamp to pendulum date
        sla_start = pendulum.from_timestamp(recd_ct_time)
        # Convert the date to user defined timezone to perform all calculations based on this timezone
        sla_start = sla_start.in_timezone(timezone)
        logger.info("sla_start {}".format(sla_start))
        sla_due_date = ""
        logger.info(" full_time {}".format(full_time))

        if full_time == True:
          sla_due_date = sla_start.add(minutes=sla_time)
          logger.info("sla_due_date {}".format(sla_due_date))
          sla_due_date_timestamp = sla_due_date.timestamp()
          return {"sla_due_date" : sla_due_date, "sla_due_date_timestamp": sla_due_date_timestamp}


        # Convert Work Start and Work end hours to datetime
        work_start = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_start,0,0,tz=timezone)
        work_end = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_end,0,0,tz=timezone)


        custom_Holidays = []
        if is_custom == True and (len(customHolidays) > 0):
        # save Custom Holidays in a list
          custom_Holidays = [day.strip() for day in customHolidays.split(',')]
          for date1 in custom_Holidays:
              try:
                date_text = datetime.datetime.strptime(date1, '%Y-%m-%d')
              except Exception as err:
                logger.exception("Exception - {}".format(err))
                raise ConnectorError('Incorrect custom date format, should be comma separated in YYYY-MM-DD format')

        holidays_list = pyholidays.HolidayBase()
        if stdHolidays == True:
          # Get the list of global holidays using holidays package
          holidays_list = pyholidays.CountryHoliday(country, prov=province, state=state)

        # Append Custom Holidays to holidays_list
        holidays_list.append(custom_Holidays)

        # Check if sla_start date falls on a weekend or a Holiday
        sla_start = _shift_to_earliest_workday(sla_start, holidays_list, work_start, first_day_weekend)
        # Shift Work start and Work end to the date of sla_start for further calculations
        work_start = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_start.hour,0,0,tz=timezone)
        work_end = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_end.hour,0,0,tz=timezone)

        # Check if record is created before next start of  work starts on that day
        if sla_start.time() < work_start.time():
          sla_start = work_start
        # Check if record is created after workend on that day
        elif sla_start > work_end or sla_start.time() > work_end.time():
          sla_start = work_start.add(days=1)
          # After sla_start is shifted check again if it falls on weekend or a holiday
          sla_start = _shift_to_earliest_workday(sla_start, holidays_list, work_start, first_day_weekend)
          # Calculate Work start and Work end based on shifted start date
          work_start = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_start.hour,0,0,tz=timezone)
          work_end = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_end.hour,0,0,tz=timezone)

        # Time left today for sla = workend - sla_start
        time_left_today = sla_start.diff(work_end).in_minutes()
        # Check if the sla is not spilling over to next day
        if time_left_today >= sla_time:
          sla_due_date = sla_start.add(minutes=sla_time)
        else:
          # If sla is spilling over to next day, calculate how much more time is required for the sla and shift the star date to next day for further calculations
          tmr_time = sla_time - time_left_today
          sla_start = work_start.add(days=1)
          sla_start = _shift_to_earliest_workday(sla_start, holidays_list, work_start, first_day_weekend)
          sla_due_date = sla_start.add(minutes=tmr_time)

          # Keep shifting start day untill the time left does not fall in working window
          while tmr_time > time_left_today:
            sla_start = _shift_to_earliest_workday(sla_start, holidays_list, work_start, first_day_weekend)
            work_start = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_start.hour,0,0,tz=timezone)
            work_end = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_end.hour,0,0,tz=timezone)
            time_left_today = sla_start.diff(work_end).in_minutes()

           # Check if the remaining time falls under current working window
            if time_left_today >= sla_time:
              sla_due_date = sla_start.add(minutes = tmr_time)
              sla_due_date = _shift_to_earliest_workday(sla_due_date, holidays_list, work_start, first_day_weekend)
              break
            else:
              # sla time is more than the current working window hence, shift start time to next day
              tmr_time = tmr_time - time_left_today
              sla_start = work_start.add(days=1)
              sla_due_date = work_start.add(minutes = tmr_time)
              sla_due_date = _shift_to_earliest_workday(sla_due_date, holidays_list, work_start, first_day_weekend)

        #sla_due_date = sla_due_date.in_timezone(timezone)
        sla_due_date = sla_due_date.replace(tzinfo=timezone)
        sla_due_date_timestamp = sla_due_date.timestamp()
        return {"sla_due_date" : sla_due_date, "sla_due_date_timestamp": sla_due_date_timestamp}
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)

def _shift_to_earliest_workday(sla_start, holidays_list, work_start, first_day_weekend):
    days_of_week = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    first_day_weekend = days_of_week.index(first_day_weekend)

    while sla_start in holidays_list:
      sla_start = sla_start.add(days=1)
      #sla_start = pendulum.datetime(sla_start.year, sla_start.month, sla_start.day, work_start.hour, 0, 0)

    # Check if sla_start is a first day of the Weekend
    day = sla_start.weekday()
    if day == first_day_weekend:
      sla_start = sla_start.add(days=2)
    # Check if sla_start is a last day of the weekend
    elif day == (first_day_weekend +1):
      sla_start = sla_start.add(days=1)

    return sla_start

functions = {
    'calculateSLA': calculateSLA

}
