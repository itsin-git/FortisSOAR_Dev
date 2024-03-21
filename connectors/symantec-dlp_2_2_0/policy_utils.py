"""
   Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end
"""
from requests.cookies import RequestsCookieJar, cookielib
from bs4 import BeautifulSoup
import requests
import uuid
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('symantec-dlp')


class SymatecDLP_Policy(object):
    def __init__(self, config):
        """
        Initialize a Symatec DLP Policy API instance.
        """
        port = config.get('port') if config.get('port') else 8443
        self.base_url = '{protocol}://{server_url}:{port}'.format(protocol=config.get('protocol'),
                                                                  server_url=config.get('server_url'), port=port)

        self.username = config.get("username")
        self.password = config.get("password")
        self.verify_ssl = config.get("verify_ssl")
        self.type = config.get("type")
        self.pattern = self.type.lower().replace(" ", "_") + "s"
        self.csrf_protection_token = None
        self.response = None
        self.jsessionid = None
        self.data_object_id = None
        self.data_object_version = None
        self.data_precheck_url = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        self.get_jsessionid()

    def get_jsessionid(self):
        try:
            url = "{server_url}/ProtectManager/j_security_check".format(server_url=self.base_url)
            payload = 'username={username}&j_username={username}&j_password={j_password}'.format(username=self.username,
                                                                                                 j_password=self.password)
            headers = {
                'Origin': self.base_url,
                'Referer': '{server_url}/ProtectManager/Logon'.format(server_url=self.base_url),
                'Cookie': 'JSESSIONID=' + uuid.uuid1().hex.upper()
            }
            response = self.api_request("POST", url, headers=headers, data=payload)
            html_content = response.text
            soup = BeautifulSoup(html_content)
            if soup.find("title").text.startswith("Symantec Data Loss Prevention"):
                error_msg = soup.find("h2", class_="section-header").text
                raise ConnectorError(error_msg)
            else:
                rcj = RequestsCookieJar(response.history[0].cookies)
                cookies_list = rcj._policy._cookies
                for item in cookies_list.items():
                    for i in item:
                        ck = item[1]['/ProtectManager']['JSESSIONID']
                        self.jsessionid = "{0}={1}".format(str(ck.name), str(ck.value))
                        logger.debug("[jsessionid:{0}".format(self.jsessionid))
                        break

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def get_list(self, rule_name):
        try:
            rule_attributes = 'None'
            payload = {}
            url = "{server_url}/ProtectManager/enforce/admin/senderrecipientpatterns/list".format(
                server_url=self.base_url)
            headers = {
                'Cookie': self.jsessionid,
                'Referer': '{server_url}/ProtectManager/ViewAllReports.do'.format(server_url=self.base_url)
            }
            response = self.api_request("GET", url, headers=headers, data=payload)

            # get csrf token and content object ID and object version.
            html_content = response.text
            soup = BeautifulSoup(html_content)
            metadata = soup.find_all('meta')
            for item in metadata:
                for i, v in item.attrs.items():
                    if v == "csrf-protection-token":
                        self.csrf_protection_token = item.attrs["content"]
                        break

            if not self.csrf_protection_token:
                logger.error("No csrf_protection_token found")

            tag_list = soup.find_all('tr')
            for item in tag_list:
                attr_str = item.text
                attr_item = attr_str.split('\n')
                attr_item = list(filter(None, attr_item))
                attr_item = [i.strip() for i in attr_item]
                attr_item = list(filter(None, attr_item))

                if rule_name in attr_item:
                    if self.type in attr_item:
                        rule_attributes = item.attrs
                        self.data_precheck_url = rule_attributes["data-precheck-url"]
                        if self.data_precheck_url.startswith(self.pattern):
                            break
                        else:
                            rule_attributes = None

            if rule_attributes != None:
                self.data_object_id = rule_attributes.get('data-objectid')
                self.data_object_version = rule_attributes.get("data-objectversion")
                self.data_precheck_url = rule_attributes.get("data-precheck-url")
            else:
                raise ConnectorError("{0} Sender/Recipient Pattern rule not found.".format(rule_name))

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def check_list_edit_status(self):
        try:
            url = "{server_url}/ProtectManager/enforce/admin/senderrecipientpatterns/{pattern}/retrieve?id={id}" \
                  "&version={version}".format(server_url=self.base_url, pattern=self.pattern, id=self.data_object_id,
                                              version=self.data_object_version)

            payload = {}
            headers = {
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': '{server_url}/ProtectManager/enforce/admin/senderrecipientpatterns/list'.format(
                    server_url=self.base_url),
                'Cookie': self.jsessionid
            }

            response = self.api_request("GET", url, headers=headers, data=payload)
            # Open List for Edit operation:
            json_resp = response.json() if response.ok else None
            if json_resp["success"]:
                return True
            else:
                return False

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def edit_list(self):
        try:
            ip_list = email_id_list = url_domain_list = []
            description = ''
            payload = {}
            url = "{server_url}/ProtectManager/enforce/admin/senderrecipientpatterns/{pattern}/edit?id={id}&" \
                  "version={version}".format(server_url=self.base_url, pattern=self.pattern, id=self.data_object_id,
                                             version=self.data_object_version)
            headers = {
                'Referer': '{server_url}/ProtectManager/enforce/admin/senderrecipientpatterns/list'.
                    format(server_url=self.base_url),
                'Cookie': self.jsessionid
            }

            response = self.api_request("GET", url, headers=headers, data=payload)

            # get current policy members
            html_content = response.text
            soup = BeautifulSoup(html_content)

            if self.pattern.startswith("recipient"):
                if len(soup.find(id="recipient-ipAddresses-edit").contents):
                    ip_list = soup.find(id="recipient-ipAddresses-edit").contents[0].split(',')

                if len(soup.find(id="recipient-emailAddresses-edit").contents):
                    email_id_list = soup.find(id="recipient-emailAddresses-edit").contents[0].split(',')

                if len(soup.find(id="recipient-urlDomains-edit").contents):
                    url_domain_list = soup.find(id="recipient-urlDomains-edit").contents[0].split(',')

                if len(soup.find(id="recipient-description-edit").contents):
                    description = str(soup.find(id="recipient-description-edit").contents[0])
            else:
                if len(soup.find(id="sender-ipAddresses-edit").contents):
                    ip_list = soup.find(id="sender-ipAddresses-edit").contents[0].split(',')

                if len(soup.find(id="sender-description-edit").contents):
                    description = str(soup.find(id="sender-description-edit").contents[0])

                """
                This extraction will fetch different user patterns e.g  company.com, john.smith@business.com, 
                sample.company.com, jsmith, jsmith@company*)
                Windows User (e.g., jsmith, domain\jsmith)
                IM Screen Name (e.g., jsmith, john smith, john.smith@yahoo.com)
                """
                if len(soup.find(id="sender-userPatterns-edit").contents):
                    email_id_list = soup.find(id="sender-userPatterns-edit").contents[0].split(',')

            return ip_list, email_id_list, url_domain_list, description

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def update_policy(self, params):
        try:
            # Following operation will only responsible to update the list.
            ADD_ITEMS = params.get('add_items', True)

            input_ip_list = params.get('ips')
            if input_ip_list:
                input_ip_list = self.str_to_list(input_ip_list)

            input_emails_list = params.get('emails')
            if input_emails_list:
                input_emails_list = self.str_to_list(input_emails_list)

            url = "{server_url}/ProtectManager/enforce/admin/senderrecipientpatterns/{pattern}/update".format(
                server_url=self.base_url, pattern=self.pattern)

            headers = {
                'Origin': self.base_url,
                'Referer': '{server_url}/ProtectManager/enforce/admin/senderrecipientpatterns/{pattern}/edit?'
                           'id={id}&version={version}'.format(server_url=self.base_url, id=self.data_object_id,
                                                              version=self.data_object_version, pattern=self.pattern),
                'Cookie': self.jsessionid,
            }

            if self.check_list_edit_status():
                ip_list, email_id_list, url_domain_list, description = self.edit_list()
                fin_ip_list = self.update_list_items(ip_list, input_ip_list, ADD_ITEMS)
                fin_emails_list = self.update_list_items(email_id_list, input_emails_list, ADD_ITEMS)

                payload = {
                    "name": params.get('pattern_name'),
                    "description": description,
                    "userPatterns": ",".join(fin_emails_list) if fin_emails_list else [],
                    "ipAddresses": ",".join(fin_ip_list) if fin_ip_list else [],
                    "id": self.data_object_id,
                    "version": self.data_object_version,
                    "csrfProtectionToken": self.csrf_protection_token,
                    "value(csrfProtectionToken)": self.csrf_protection_token
                }

                if self.pattern.startswith("recipient"):
                    input_urls_list = params.get('urls')
                    if input_urls_list:
                        input_urls_list = self.str_to_list(input_urls_list)
                        fin_urls = self.update_list_items(url_domain_list, input_urls_list, ADD_ITEMS)
                        payload["urlDomains"] = ",".join(fin_urls) if fin_urls else []

                response = self.api_request("POST", url, headers=headers, data=payload)
                return {"result": "Successfully updated the sender/recipient rule."}
            else:
                raise ConnectorError("Fail to fetch the pattern rule list.")

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def get_policy(self):
        try:
            if self.check_list_edit_status():
                return self.edit_list()
            else:
                msg = 'Exception: {0} Policy is not editable.'.format(self.pattern)
                logger.error(msg)
                raise ConnectorError(msg)

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def logoff(self):
        # LogOff
        try:
            url = '{server_url}/ProtectManager/Logoff'.format(server_url=self.base_url)

            payload = 'userid=1&type=STANDARD&csrfProtectionToken={csrf_protection_token}&' \
                      'value(csrfProtectionToken)={csrf_protection_token}'.format(
                csrf_protection_token=self.csrf_protection_token)
            headers = {
                'Referer': '{server_url}/ProtectManager/enforce/admin/senderrecipientpatterns/recipient_patterns/edit?'
                           'id={id}&version={version}'.format(server_url=self.base_url, id=self.data_object_id,
                                                              version=self.data_object_version),
                'Origin': self.base_url,
                'Cookie': self.jsessionid
            }

            response = self.api_request("POST", url, headers=headers, data=payload)

            logger.debug("[Logoff: {0}]".format(response.text))
            logger.info("Successfully logoff")
            return 1

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    # Utility methods
    def update_list_items(self, curr, input_list, join_list):
        # Add or Delete items from the list.
        if len(input_list) and curr:
            if join_list:
                final = list(set(curr) | set(input_list))
                return final
            else:
                # Get elements which are not in current list
                diff_list = [elem for elem in input_list if elem not in curr]
                if diff_list:
                    logger.error("{0} cannot be found in pattern rule".format(diff_list))
                res = list(set(curr) ^ set(input_list))
                return res

        return curr if curr else input_list

    def str_to_list(self, param):
        if isinstance(param, str):
            param_list = list(map(lambda x: x.strip(' '), param.split(',')))
        else:
            param_list = param
        return param_list

    def api_request(self, method, url, headers, data=None):
        try:
            self.headers.update(headers)
            logger.debug("URL:[{0}]  Headers:[{1}] Payload:[{2}]".format(url, headers, data))
            response = requests.request(method, url, headers=self.headers, data=data, verify=self.verify_ssl)
            logger.debug("Response: [{0}]".format(response.text))

            if response.ok:
                return response
            else:
                error_msg = "Response Code: {0}".format(response.status_code)
                logger.error(error_msg)
                raise ConnectorError(error_msg)

        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred.')
            raise ConnectorError('An SSL error occurred.')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred.')
            raise ConnectorError('A connection error occurred.')
        except Exception as error:
            logger.error(error)
            raise ConnectorError(error)
