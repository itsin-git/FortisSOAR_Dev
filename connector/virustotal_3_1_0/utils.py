""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import re, json
import base64
from .const import TEMPLATE, IP_TEMPLATE, DOMAIN_TEMPLATE, URL_TEMPLATE, FILE_TEMPLATE

from connectors.cyops_utilities.builtins import download_file_from_cyops
from integrations.crudhub import make_request
from connectors.core.connector import get_logger, ConnectorError
from os.path import join

logger = get_logger('virustotal')

IP_RELATIONSHIP_VALUE = {
    "Comments": "comments",
    "Historical SSL Certificates": "historical_ssl_certificates",
    "Graphs": "graphs",
    "Historical Whois": "historical_whois",
    "Referrer Files": "referrer_files",
    "Resolutions": "resolutions",
    "Votes": "votes",
    "Related Comments": "related_comments"
}

DOMAIN_RELATIONSHIP_VALUE = {
    "Historical Whois": "historical_whois",
    "Subdomains": "subdomains",
    "Comments": "comments",
    "Graphs": "graphs",
    "Historical SSL Certificates": "historical_ssl_certificates",
    "Immediate Parent": "immediate_parent",
    "Parent": "parent",
    "Referrer Files": "referrer_files",
    "Related Comments": "related_comments",
    "Resolutions": "resolutions",
    "Siblings": "siblings",
    "URLs": "urls",
    "Votes": "votes"
}

URL_RELATIONSHIP_VALUE = {
    "Comments": "comments",
    "Graphs": "graphs",
    "Last Serving IP Address": "last_serving_ip_address",
    "Network Location": "network_location",
    "Related Comments": "related_comments",
    "Votes": "votes"
}

FILE_RELATIONSHIP_VALUE = {
    "Behaviours": "behaviours",
    "Bundled Files": "bundled_files",
    "Comments": "comments",
    "Contacted Domains": "contacted_domains",
    "Contacted IPs": "contacted_ips",
    "Contacted URLs": "contacted_urls",
    "Dropped Files": "dropped_files",
    "Execution Parents": "execution_parents",
    "PE Resource Children": "pe_resource_children",
    "PE Resource Parents": "pe_resource_parents",
    "Screenshots": "screenshots",
    "Votes": "votes",
    "Graphs": "graphs"
}


class VirusTotalConnection(object):
    def __init__(self, config):
        self.log = logger
        self.maximum_file_size = 32000000
        self.base_url = config.get('server').strip() + '/api/v3/{endpoint}'
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://' + self.base_url
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')
        self.__setupSession()

    def __setupSession(self):
        self.log.info('Setup session')
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update({'x-apikey': self.api_key})

    def __postUrl(self, endpoint, params={}, data={}, files=None):
        try:
            self.log.info('POST to endpoint: {0}'.format(endpoint))
            self.log.info('Params: {0}'.format(params))
            if files is not None:
                self.log.info('Posting files')
            url = self.base_url.format(endpoint=endpoint)
            self.log.info('Posting to URL: {0}'.format(url))
            res = self.session.post(url, params=params, data=data, files=files)
            if res.status_code == 204:
                return {'message': 'Request rate limit exceeded. You are making more requests than allowed.'}
            elif res.status_code == 429:
                return res.json()
            elif res.status_code == 400:
                return res.json()
            elif res.status_code == 401:
                raise ConnectorError("Invalid URL or Credentials")
            elif res.status_code == 500:
                raise ConnectorError("Internal Server Error")
            return res.json()
        except Exception as Err:
            raise ConnectorError(Err)

    def __getUrl(self, endpoint, params={}):
        try:
            self.log.info('GET to endpoint: {0}'.format(endpoint))
            self.log.info('Params: {0}'.format(params))
            if 'www.virustotal.com' in endpoint:
                url = endpoint
                headers = {
                    'user-agent': "FortiSOAR Integration"
                }
            else:
                url = self.base_url.format(endpoint=endpoint)
                headers = {}
            self.log.info('GET to URL: {0}'.format(url))
            res = self.session.get(url, params=params, headers=headers)
            if res.status_code == 204:
                return {'message': 'Request rate limit exceeded. You are making more requests than allowed.'}
            elif res.status_code == 429:
                return res.json()
            elif res.status_code == 400:
                return res.json()
            elif res.status_code == 401:
                raise ConnectorError("Invalid URL or Credentials")
            elif res.status_code == 500:
                raise ConnectorError("Internal Server Error")
            if 'json' in str(res.headers):
                return res.json()
            else:
                return res.text
        except Exception as Err:
            logger.exception(Err)
            raise ConnectorError(Err)

    def create_relationship(self, params, relationship_type):
        relationships_list = []
        relationships = params.get('relationships')
        if relationship_type == 'IP':
            relationships_list = [IP_RELATIONSHIP_VALUE.get(r) for r in relationships]
        elif relationship_type == 'DOMAIN':
            relationships_list = [DOMAIN_RELATIONSHIP_VALUE.get(r) for r in relationships]
        elif relationship_type == 'URL':
            relationships_list = [URL_RELATIONSHIP_VALUE.get(r) for r in relationships]
        elif relationship_type == 'FILE':
            relationships_list = [FILE_RELATIONSHIP_VALUE.get(r) for r in relationships]
        return relationships_list

    def create_output_schema(self, params, relationship_type):
        relationships_list = self.create_relationship(params, relationship_type)
        relationship = relationships_list if relationships_list else []
        output_object = {'relationships': {}}
        for relation_name in relationship:
            output_object['relationships'].update({relation_name: TEMPLATE})
        return output_object

    def build_output_schema_ip(self, config, params):
        output_object = self.create_output_schema(params, 'IP')
        output_object.update(IP_TEMPLATE)
        return output_object

    def build_output_schema_domain(self, config, params):
        output_object = self.create_output_schema(params, 'DOMAIN')
        output_object.update(DOMAIN_TEMPLATE)
        return output_object

    def build_output_schema_url(self, config, params):
        output_object = self.create_output_schema(params, 'URL')
        output_object.update(URL_TEMPLATE)
        return output_object

    def build_output_schema_file(self, config, params):
        output_object = self.create_output_schema(params, 'FILE')
        output_object.update(FILE_TEMPLATE)
        return output_object

    def getUrlEndpoint(self, url, method, body):
        try:
            parts = url.split('/api/v3/')
            endpoint = parts[-1]
            self.log.info('GET url endpoint: {0}'.format(endpoint))
            if method == 'GET':
                response = self.__getUrl(endpoint)
            if method == 'POST':
                response = self.__postUrl(endpoint, data=json.dumps(body))
            if response.get('error'):
                return response.get('error')
            return response
        except Exception as Err:
            raise ConnectorError('Error in getUrlEndpoint(): %s' % Err)

    def submitFile(self, file_iri):
        try:
            endpoint = 'files'
            file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
            logger.info(file_path)
            with open(file_path, 'rb') as attachment:
                file_data = attachment.read()
            if file_data:
                files = {'file': file_data}
                res = self.__postUrl(endpoint, files=files)
                if res.get('error'):
                    return res.get('error')
                return res.get('data')
            raise ConnectorError('File size too large, submit file up to 32 MB')
        except Exception as Err:
            logger.error('Error in submitFile(): %s' % Err)
            logger.exception('Error in submitFile(): %s' % Err)
            raise ConnectorError('Error in submitFile(): %s' % Err)

    def getHashReport(self, hash_str, relationships):
        try:
            relationships_list = []
            self.log.info('Getting hash report')
            if not self.isValidHash(len(hash_str), hash_str):
                msg = 'Invalid hash provided'
                self.log.error(msg)
                return {'error': msg}
            if relationships:
                for r in relationships:
                    relationships_list.append(FILE_RELATIONSHIP_VALUE.get(r))
                relationships_string = ",".join(relationships_list)
                endpoint = 'files/{0}?relationships={1}'.format(hash_str, relationships_string)
            else:
                endpoint = 'files/{0}'.format(hash_str)
            response = self.__getUrl(endpoint)
            if response.get('error'):
                return response.get('error')
            if response:
                id = response['data']['id']
                response['data']['attributes'].update(
                    {'names': [ascii(x).strip("'") for x in response['data']['attributes']['names']]})
                response['data']['links']['self'] = 'https://www.virustotal.com/gui/file/{0}/detection'.format(id)
                return response.get('data')
        except Exception as Err:
            logger.exception('Error in getHashReport(): %s' % Err)
            raise ConnectorError('Error in getHashReport(): %s' % Err)

    def getWidgetUrl(self, config, params):
        try:
            endpoint = 'widget/url'
            response = self.__getUrl(endpoint, params=params)
            if response.get('error'):
                return response.get('error')
            return response
        except Exception as Err:
            logger.exception('Error in getWidgetUrl(): %s' % Err)
            raise ConnectorError('Error in getWidgetUrl(): %s' % Err)

    def getWidgetHtmlContent(self, config, params):
        try:
            token = params.get('token')
            if '/' in token:
                token = token.split("/")[-1]
            endpoint = 'https://www.virustotal.com/ui/widget/html/{0}'.format(token)
            response = self.__getUrl(endpoint)
            return response
        except Exception as Err:
            logger.exception('Error in getWidgetHtmlContent(): %s' % Err)
            raise ConnectorError('Error in getWidgetHtmlContent(): %s' % Err)

    def scanUrl(self, url):
        try:
            self.log.info('Get URL report')
            endpoint = 'urls'
            params = {
                'url': url
            }
            response = self.__postUrl(endpoint, data=params)
            if response.get('error'):
                return response.get('error')
            return response.get('data')
        except Exception as Err:
            logger.exception('Error in getUrlReport(): %s' % Err)
            raise ConnectorError('Error in getUrlReport(): %s' % Err)

    def getUrlReport(self, url, relationships):
        try:
            relationships_list = []
            self.log.info('Get URL report')
            if relationships:
                for r in relationships:
                    relationships_list.append(URL_RELATIONSHIP_VALUE.get(r))
                relationships_string = ",".join(relationships_list)
                endpoint = 'urls/{0}?relationships={1}'.format(
                    base64.urlsafe_b64encode(url.encode()).decode().strip("="),
                    relationships_string)
            else:
                endpoint = 'urls/{0}'.format(base64.urlsafe_b64encode(url.encode()).decode().strip("="))
            response = self.__getUrl(endpoint)
            if response.get('error'):
                response['error']['message'] = "URL '{0}' not found".format(url)
                return response.get('error')
            if response:
                id = response['data']['id']
                response['data']['links']['self'] = 'https://www.virustotal.com/gui/url/{0}/detection'.format(id)
                return response.get('data')
        except Exception as Err:
            logger.exception('Error in getUrlReport(): %s' % Err)
            raise ConnectorError('Error in getUrlReport(): %s' % Err)

    def getIpReport(self, ip, relationships):
        try:
            relationships_list = []
            self.log.info('Get IP report')
            if relationships:
                for r in relationships:
                    relationships_list.append(IP_RELATIONSHIP_VALUE.get(r))
                relationships_string = ",".join(relationships_list)
                endpoint = 'ip_addresses/{0}?relationships={1}'.format(ip, relationships_string)
            else:
                endpoint = 'ip_addresses/{0}'.format(ip)
            response = self.__getUrl(endpoint)
            if response.get('error'):
                return response.get('error')
            try:
                whois = response['data']['attributes']['whois']
                response['data']['attributes']['whois'] = {'raw': [], 'data': whois}
            except:
                response['data']['attributes']['whois'] = {'raw': [], 'data': 'No match found for {0}'.format(ip)}
            response['data']['links']['self'] = 'https://www.virustotal.com/gui/ip-address/{0}'.format(ip)
            return response.get('data')
        except Exception as Err:
            logger.exception('Error in getIpReport(): %s' % Err)
            raise ConnectorError('Error in getIpReport(): %s' % Err)

    def getDomainReport(self, domain, relationships):
        try:
            relationships_list = []
            self.log.info('Get Domain report')
            if relationships:
                for r in relationships:
                    relationships_list.append(DOMAIN_RELATIONSHIP_VALUE.get(r))
                relationships_string = ",".join(relationships_list)
                endpoint = 'domains/{0}?relationships={1}'.format(domain, relationships_string)
            else:
                endpoint = 'domains/{0}'.format(domain)
            response = self.__getUrl(endpoint)
            if response.get('error'):
                return response.get('error')
            try:
                whois = response['data']['attributes']['whois']
                response['data']['attributes']['whois'] = {'raw': [], 'data': whois}
            except:
                response['data']['attributes']['whois'] = {'raw': [], 'data': 'No match found for {0}'.format(domain)}
            response['data']['links']['self'] = 'https://www.virustotal.com/gui/domain/{0}'.format(domain)
            return response.get('data')
        except Exception as Err:
            logger.exception('Error in getDomainReport(): %s' % Err)
            raise ConnectorError('Error in getDomainReport(): %s' % Err)

    def getFileAnalysis(self, id, type):
        try:
            self.log.info('Get File Analysis report')
            endpoint = 'analyses/{0}'.format(id)
            response = self.__getUrl(endpoint)
            if response.get('error'):
                return response.get('error')
            if response:
                try:
                    id = response['meta']['url_info']['id']
                    response['data']['links']['self'] = 'https://www.virustotal.com/gui/url/{0}/detection'.format(id)
                    return response
                except:
                    sha256 = response['meta']['file_info']['sha256']
                    response['data']['links']['self'] = 'https://www.virustotal.com/gui/file/{0}/detection'.format(
                        sha256)
                    return response
        except Exception as Err:
            logger.exception('Error in getFileAnalysis(): %s' % Err)
            raise ConnectorError('Error in getFileAnalysis(): %s' % Err)

    def isValidHash(self, _len, file_hash):
        if _len in [32, 40, 64]:  # md5/sha1/sha256
            pattern = re.compile(r'[0-9a-fA-F]{%s}' % _len)
            match = re.match(pattern, file_hash)
            if match is not None:
                return True
        return False

    def handle_params(self, params):
        value = str(params.get('value'))
        input_type = params.get('input')
        try:
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            if input_type == 'Attachment ID':
                if not value.startswith('/api/3/attachments/'):
                    value = '/api/3/attachments/{0}'.format(value)
                attachment_data = make_request(value, 'GET')
                file_iri = attachment_data['file']['@id']
                file_name = attachment_data['file']['filename']
                logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
                return file_iri
            elif input_type == 'File IRI':
                if value.startswith('/api/3/files/'):
                    return value
                else:
                    raise ConnectorError('Invalid File IRI {0}'.format(value))
        except Exception as err:
            logger.info('handle_params(): Exception occurred {0}'.format(err))
            raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                                 (input_type, value.replace('/api/3/attachments/', '')))
