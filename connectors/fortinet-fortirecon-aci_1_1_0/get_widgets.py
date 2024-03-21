""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .make_rest_api_call import MakeRestApiCall


def get_widgets(config: dict, params: dict) -> dict:

    MK = MakeRestApiCall(config=config)
    endpoint = "/aci/{org_id}/osint_feed_widgets"
    method = "GET"
    if params.get("start_date"):
        params["start_date"] = MK.handle_date(params.get("start_date"))
    if params.get("end_date"):
        params["end_date"] = MK.handle_date(params.get("end_date"))

    response = MK.make_request(endpoint=endpoint, method=method, params=params)
    return response