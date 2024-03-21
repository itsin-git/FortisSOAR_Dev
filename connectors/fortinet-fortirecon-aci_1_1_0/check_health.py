""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .make_rest_api_call import MakeRestApiCall


def _check_health(config: dict) -> bool:
    try:
        endpoint = "/aci/{org_id}/osint_feeds"
        method = "GET"
        MS = MakeRestApiCall(config=config)
        MS.make_request(endpoint=endpoint, method=method)
        return True
    except Exception as e:
        raise Exception(e)
