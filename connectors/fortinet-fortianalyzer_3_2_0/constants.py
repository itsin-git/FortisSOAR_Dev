""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

messages_codes = {
    400: 'Invalid input',
    401: 'Unauthorized: Invalid credentials',
    500: 'Invalid input',
    404: 'Invalid input',
    'ssl_error': 'SSL certificate validation failed',
    'timeout_error': 'The request timed out while trying to connect to the remote server. Invalid Server URL.'
}

category_mapping = {
    "Unauthorized Access": "CAT1",
    "Denial of Service": "CAT2",
    "Malicious Code": "CAT3",
    "Improper Usage": "CAT4",
    "Scans/Probes/Attempted Access": "CAT5",
    "Uncategorized": "CAT6"
}

status_mapping = {
    "New": "draft",
    "Analysis": "analysis",
    "Response": "response",
    "Closed: Remediated": "closed",
    "Closed: False Positive": "cancelled"
}

severity_mapping = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Critical": "critical"
}

detail_level_mapping = {
    "Basic": "basic",
    "Standard": "standard",
    "Extended": "extended"
}

log_type_mapping = {
    "Traffic": "traffic",
    "Application control": "app-ctrl",
    "Attack": "attack",
    "Content": "content",
    "DLP": "dlp",
    "Email Filter": "emailfilter",
    "Event": "event",
    "History": "history",
    "Virus": "virus",
    "VOIP": "voip",
    "Web Filter": "webfilter",
    "Netscan": "netscan",
    "FCT Event": "fct-event",
    "FCT Traffic": "fct-traffic",
    "WAF": "waf",
    "GTP": "gtp"
}

time_order_mapping = {
    "ASC": "asc",
    "DESC": "desc"
}

APIVER = 3
JSONRPC = "2.0"
CONST_ID = 1
VERSION = 600

action_input_parameters = {
    "create_incident": ["reporter", "endpoint", "assigned-to", "category", "severity", "status", "euid", "description", "adom_name"],
    "list_incidents": ["incids", "status", "filter", "detail-level", "limit", "offset", "sort-by", "field", "order", "adom_name"],
    "update_incident_details": ["incid", "assigned-to", "category", "status", "endpoint", "severity", "euid", "description", "adom_name"],
    "get_events_for_incident": ["incid", "limit", "offset", "adom_name"],
    "get_incident_assets": ["incid", "limit", "offset", "adom_name"],
    "get_users": ["euids", "filter", "detail-level", "limit", "offset", "field", "order", "sort-by", "adom_name"],
    "get_endpoints": ["epids", "filter", "limit", "offset", "sort-by", "field", "order", "adom_name"],

    "list_log_fields": ["devtype", "logtype", "subtype", "adom_name"],
    "get_log_file_content": ["devid", "filename", "vdom", "data-type", "offset", "length", "adom_name"],
    "log_search_over_log_file": ["devid", "filename", "vdom", "case-sensitive", "filter", "logtype", "offset", "limit", "adom_name"],
    "get_log_file_state": ["devid", "filename", "vdom", "start", "end", "adom_name"],
    "start_log_search_request": ["devid", "devname", "filter", "logtype", "case-sensitive", "time-order", "start",
                                 "end", "adom_name"],
    "start_bulk_device_log_search_request": ["devid", "filter", "logtype", "case-sensitive", "time-order", "start",
                                 "end", "adom_name"],
    "fetch_log_search_result_by_task_id": ["tid", "offset", "limit", "adom_name"],
    "get_alerts": ["alertid", "devid", "devname", "severity", "filter", "limit", "offset", "start", "end", "adom_name"],
    "get_alert_event_logs": ["alertid", "filter", "limit", "offset", "start", "end", "time-order", "adom_name"],

    "add_attachment": ["incid", "data", "attachtype", "attachsrc", "attachsrcid", "attachsrctrigger", "lastuser", "adom_name"],
    "get_attachments_for_incident": ["incid", "attachtype", "limit", "offset", "adom_name"],
    "update_attachment": ["attachid", "data", "attachsrc", "attachsrcid", "attachsrctrigger", "lastrevision", "lastuser", "adom_name"],

    "add_master_device": ["name", "ip", "sn", "os_ver", "adom_name"],
    "add_slave_device": ["slave_name", "slave_sn", "master_name", "master_sn", "adom_name"],
    "add_new_device": ["name", "ip", "sn", "os_ver", "adom_name"],
    "get_log_status": ["devid", "adom_name"],
    "get_device_info": ["name", "adom_name"],
    "authorize_device": ["name", "sn", "os_ver", "adom_name"],
    "delete_device": ["name", "adom_name"],


    "get_alerts_for_multiple_adoms": ["alertid", "devid", "devname", "severity", "filter", "limit", "offset", "start", "end"],
    "count_alerts_for_multiple_adoms": ["group-by", "start", "end", "filter"],
    "list_incidents_for_multiple_adoms": ["incids", "status", "filter", "detail-level", "limit", "offset", "sort-by", "field", "order"],
    "count_incidents_for_multiple_adoms": ["incids", "filter"]
}
