""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json
import shutil
import gzip
import os
from django.conf import settings

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass
from connectors.core.connector import get_logger, ConnectorError
from .ingest_feeds import ingest_feeds
from .base import FortiguardThreatIntelligence
from .const import BATCH_SIZE
from .const import SOURCE as Source

logger = get_logger('fortinet-fortiguard-threat-intelligence')


def threat_intel_search(config, params, **kwargs):
    try:
        etp = FortiguardThreatIntelligence(config)
        endpoint = "v1/cts/threat_intel_search"
        payload = {
            'indicator': params.get('indicator')
        }
        response = etp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_threat_categories(config, params, **kwargs):
    try:
        etp = FortiguardThreatIntelligence(config)
        endpoint = "v1/cts/categories"
        response = etp.make_rest_call(endpoint, 'GET', params=params)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_encyclopedia_lookup(config, params, **kwargs):
    try:
        etp = FortiguardThreatIntelligence(config)
        endpoint = "v1/fgd/lookup/ency"
        payload = {
            'source': Source.get(params.get('source')),
            'id': params.get('id')
        }
        response = etp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        response = get_threat_categories(config, params={})
        if response:
            return True
    except Exception as err:
        logger.exception('Invalid URL'.format(err))
        raise ConnectorError('Invalid URL'.format(err))


operations = {
    'threat_intel_search': threat_intel_search,
    'get_threat_categories': get_threat_categories,
    'get_encyclopedia_lookup': get_encyclopedia_lookup,
    'ingest_feeds': ingest_feeds
}
