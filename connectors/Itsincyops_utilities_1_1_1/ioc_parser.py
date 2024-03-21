from configparser import ConfigParser
import json
import re
import os
import ipaddress
import urllib
from connectors.core.connector import get_logger, ConnectorError
from .errors.error_constants import *

logger = get_logger('cyops_utilities.builtins.ioc_parser')


class Parser(object):
    patterns = {}
    defang = {}

    def __init__(self, custom_regex=None):
        self.__load_patterns(custom_regex)

    def __load_patterns(self, custom_regex):
        patterns_config = ConfigParser()
        patterns_config.read(os.path.join(os.path.dirname(__file__), 'patterns.ini'))
        for ind_type in patterns_config.sections():
            try:
                if custom_regex and custom_regex.get(ind_type):
                    ind_pattern = custom_regex.get(ind_type)
                else:
                    ind_pattern = patterns_config.get(ind_type, 'pattern')
            except:
                continue
            if ind_pattern:
                ind_regex = re.compile(ind_pattern, re.IGNORECASE)
                self.patterns[ind_type] = ind_regex
            try:
                ind_defang = patterns_config.get(ind_type, 'defang')
            except:
                continue

            if ind_defang:
                self.defang[ind_type] = True

    def omitValue(self, key, value, dedup_store):
        if key == 'URL':
            if ('IP', value) in dedup_store:
                return True
        else:
            return False

    def parse(self, data, whitelist, case_sensitive):
        base_picklist_iri = "/api/3/picklists/"
        result = {
            "Host": [],
            "URL": [],
            "IP": [],
            "Email": [],
            "MD5": [],
            "SHA1": [],
            "SHA256": [],
            "CVE": [],
            "Registry": [],
            "Filename": [],
            "Filepath":[],
            "unified_result": []
        }
        unified_result_format = {
            "Host": {"uuid": "3272abd8-a1ae-4663-8c47-6d1195e684d9", "type": "Host"},
            "URL": {"uuid": "353a37b4-3eeb-43ee-aac6-64806422cfec", "type": "URL"},
            "IP": {"uuid": "c0beeda4-2c7a-4214-b7e5-53ba1649539c", "type": "IP Address"},
            "Email": {"uuid": "80bd55b0-6d88-4beb-bec3-97954f261c4d", "type": "Email Address"},
            "MD5": {"uuid": "0ca054f2-d923-4992-a4a7-c516e6df281e", "type": "FileHash-MD5"},
            "SHA1": {"uuid": "143e40b0-e643-468d-b968-a542fc85f08d", "type": "FileHash-SHA1"},
            "SHA256": {"uuid": "4ea7b083-a0af-41ea-8d7c-7ace16021722", "type": "FileHash-SHA256"},
            "CVE": {"uuid": "", "type": "CVE"},
            "Registry": {"uuid": "9e783ec9-90cd-40bb-afec-976f30055108", "type": "Registry"},
            "Filename": {"uuid": "0162241b-f5bf-4917-a150-00e920be47bd", "type": "File"},
            "Filepath": {"uuid": "0162241b-f5bf-4917-a150-00e920be47bd", "type": "File"}
        }
        unified_result = []
        dedup_store = set()
        temp_ipv6 = []
        try:
            for ind_type, ind_regex in self.patterns.items():
                matches = ind_regex.findall(data)

                for ind_match in matches:
                    if isinstance(ind_match, tuple):
                        ind_match = ind_match[0]

                    if ind_type in self.defang:
                        ind_match = re.sub(r'\[\.\]', '.', ind_match)

                    if (ind_type, ind_match) in dedup_store:
                        continue

                    if ind_type == 'IPv6':
                        temp_ipv6.append(ind_match)
                        ind_type = 'IP'

                    dedup_store.add((ind_type, ind_match))

            for key, value in dedup_store:
                if not self.omitValue(key, value, dedup_store):
                    indicator_value = {}
                    is_value_valid = True
                    if key == 'IPv4':
                        key = 'IP'
                        for IP_value in temp_ipv6:
                            if value in IP_value:
                                is_value_valid = False
                                break
                    if not is_value_valid:
                        continue
                    indicator_value['value'] = value
                    indicator_value['type'] = unified_result_format[key]['type']
                    indicator_value['picklist_iri'] = base_picklist_iri + unified_result_format[key]['uuid']
                    unified_result.append(indicator_value)
                    if key not in result.keys():
                        result[key] = [value]
                    else:
                        result[key].append(value)
            unified_result_whitelist_excluded = list(unified_result)
            whitelist_excluded = []
            visted_whitelisted_values = []
            for item in unified_result[:]:
                for value in whitelist:
                    if not item['value'] in visted_whitelisted_values:
                        if check_ipv4(value) and check_ipv4(item['value']):
                            if ipaddress.ip_address(item['value']) in ipaddress.IPv4Network(value, False):
                                try:
                                    whitelist_excluded.append(item)
                                    unified_result_whitelist_excluded.remove(item)
                                    visted_whitelisted_values.append(item['value'])
                                except:
                                    break
                        elif check_ipv6(value) and check_ipv6(item):
                            if ipaddress.ip_address(item['value']) in ipaddress.IPv6Network(value, False):
                                try:
                                    whitelist_excluded.append(item)
                                    unified_result_whitelist_excluded.remove(item)
                                    visted_whitelisted_values.append(item['value'])
                                except:
                                    break
                        elif value:
                            if case_sensitive:
                                if re.match(value, item['value']) or (str(item['value']).find(value) >= 0):
                                    try:
                                        whitelist_excluded.append(item)
                                        unified_result_whitelist_excluded.remove(item)
                                        visted_whitelisted_values.append(item['value'])
                                    except:
                                        break
                            else:
                                if re.match(value, item['value'], re.IGNORECASE) or (str(item['value']).lower().find(value.lower()) >= 0):
                                    try:
                                        whitelist_excluded.append(item)
                                        unified_result_whitelist_excluded.remove(item)
                                        visted_whitelisted_values.append(item['value'])
                                    except:
                                        break
            result['whitelisted_results'] = whitelist_excluded
            result['results'] = unified_result_whitelist_excluded
            result['unified_result'] = unified_result_whitelist_excluded
            return result
        except Exception as exp:
            logger.error("{0} ERROR :: {1}".format(cs_connector_utility_10,str(exp)))
            raise ConnectorError(cs_connector_utility_10)


def extract_artifacts(data, *args, **kwargs):
    custom_regex = None
    if type(data) == dict:
        data = json.dumps(data)

    private_whitelist_values = ["172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8"]
    whitelist = _whitelist(kwargs.get('whitelist', []))
    case_sensitive = _whitelist(kwargs.get('case_sensitive', False))
    if kwargs.get('private_whitelist', False):
        whitelist.extend(private_whitelist_values)
    override_regex = kwargs.get('override_regex', False)

    if override_regex:
        custom_regex = {
            'URL': kwargs.get('url_regex', None),
            'Host': kwargs.get('host_regex', None),
            'IPv4': kwargs.get('ipv4_regex', None),
            'IPv6': kwargs.get('ipv6_regex', None),
            'Email': kwargs.get('email_regex', None)
        }
    data = urllib.parse.unquote(data)
    return Parser(custom_regex).parse(data, whitelist, case_sensitive)


extract_artifacts.__str__ = lambda: 'Extract Indicators'


def check_ipv4(addr):
    try:
        ipaddress.IPv4Network(addr, False)
        return True
    except:
        return False


def check_ipv6(addr):
    try:
        ipaddress.IPv6Network(addr, False)
        return True
    except:
        return False


def _whitelist(whitelist):
    if isinstance(whitelist, str):
        whitelist = whitelist.replace(" ", "").split(",")
    elif isinstance(whitelist, tuple):
        whitelist = list(whitelist)
    return whitelist
