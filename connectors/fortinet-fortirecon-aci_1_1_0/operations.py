""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


from .get_iocs import get_iocs
from .get_leaked_cards import get_leaked_cards
from .get_widgets import get_widgets
from .get_osint_feeds import get_osint_feeds
from .get_reports import get_reports
from .get_reports_with_iocs import get_reports_with_iocs
from .get_stealers_log import get_stealers_log



operations = {
    "get_iocs": get_iocs,
    "get_leaked_cards": get_leaked_cards,
    "get_widgets": get_widgets,
    "get_osint_feeds": get_osint_feeds,
    "get_reports": get_reports,
    "get_reports_with_iocs": get_reports_with_iocs,
    "get_stealers_log": get_stealers_log,
}
