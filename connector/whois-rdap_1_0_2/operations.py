""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import socket
from connectors.core.connector import get_logger, ConnectorError
from ipwhois import IPWhois

logger = get_logger('whois-rdap')

MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs"]

CONNECTOR_NAME = "whois-rdap"


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False
    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True


def whois_ip(params):
    try:
        ip = params.get('ip')
        if is_valid_ipv4_address(ip) or is_valid_ipv6_address(ip):
            obj_whois = IPWhois(ip)
            response = obj_whois.lookup_rdap()
            if response['objects']:
                objects = response['objects']
                new_objects = [objects[key] for key in objects]
                response['objects'] = new_objects
            return response
        else:
            raise ConnectorError('Invalid IP address {}'.format(ip))
    except Exception as err:
        message = 'Got exception: type: {0}, str: {1}'.format(type(err).__name__, str(err))
        logger.error(message)
        raise ConnectorError(message)


operations = {
    "whois_ip": whois_ip
}
