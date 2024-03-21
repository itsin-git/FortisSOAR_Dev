""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError

from .utils import *
from .utils import _validate_vdom, _api_request

logger = get_logger('fortigate-firewall')


def create_firewall_service(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        app_param = {'vdom': vdom_list} if vdom_list  else {}
        body = {
            'name': params.get('name'),
            'category': params.get('category'),
            'protocol': params.get('protocol'),
            'iprange': params.get('iprange'),
            'fqdn': params.get('fqdn'),
            'tcp-portrange': params.get('tcp_portrange'),
            'udp-portrange': params.get('udp_portrange'),
            'sctp-portrange': params.get('sctp_portrange'),
            'comment': params.get('comment'),
            'visibility': params.get('visibility').lower() if params.get('visibility') else None,
            'protocol-number': params.get('protocol-number') if params.get('protocol-number') else None,
            'icmptype': params.get('icmptype') if params.get('icmptype') else None,
            'icmpcode': params.get('icmpcode') if params.get('icmpcode') else None
        }
        body_param = {k: v for k, v in body.items() if v is not None and v != '' and v != {} and v != []}
        return _api_request(config, FIREWALL_SERVICE_API, parameters=app_param, method='POST', body=body_param)
    except Exception as Err:
        raise ConnectorError(str(Err))


def get_firewall_services(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)

        app_param = {'vdom': vdom_list} if vdom_list else {}
        if params.get('name'):
            return _api_request(config, '{}/{}'.format(FIREWALL_SERVICE_API, params.get('name').replace('/', '%2f')), parameters=app_param)
        else:
            return _api_request(config, FIREWALL_SERVICE_API, parameters=app_param)
    except Exception as Err:
        raise ConnectorError(str(Err))


def update_firewall_service(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        app_param = {'vdom': vdom_list} if vdom_list else {}
        body = {
            'name': params.get('name'),
            'category': params.get('category'),
            'protocol': params.get('protocol'),
            'iprange': params.get('iprange'),
            'fqdn': params.get('fqdn'),
            'tcp-portrange': params.get('tcp_portrange'),
            'udp-portrange': params.get('udp_portrange'),
            'sctp-portrange': params.get('sctp_portrange'),
            'comment': params.get('comment'),
            'visibility': params.get('visibility').lower() if params.get('visibility') else None,
            'protocol-number': params.get('protocol-number') if params.get('protocol-number') else None,
            'icmptype': params.get('icmptype') if params.get('icmptype') else None,
            'icmpcode': params.get('icmpcode') if params.get('icmpcode') else None
        }
        if params.get('new_name'):
            body.update({'name': params.get('new_name')})
        body_param = {k: v for k, v in body.items() if v is not None and v != '' and v != {} and v != []}
        return _api_request(config, FIREWALL_SERVICE_API + params.get('name').replace('/', '%2f'), parameters=app_param, method='PUT',
                            body=body_param)
    except Exception as Err:
        raise ConnectorError(str(Err))


def delete_firewall_service(config, params):
    try:
        vdom_list, vdom_not_exists = _validate_vdom(config, params, check_multiple_vdom=False)
        app_param = {'vdom': vdom_list} if vdom_list else {}
        return _api_request(config, FIREWALL_SERVICE_API + params.get('name').replace('/', '%2f'), parameters=app_param, method='DELETE')
    except Exception as Err:
        raise ConnectorError(str(Err))