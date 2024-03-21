import requests
import json, datetime
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('cyberark')

ok = [200, 201, 204]


class CyberARK:
    def __init__(self, config):
        self.base_url = config['server_url'].strip("/")
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.username = config.get('username')
        self.password = config.get('password')
        self.error_msg = {
            400: 'Bad/Invalid Request',
            401: 'Invalid credentials were provided',
            403: 'Access Denied',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'
        }
        self.verify_ssl = config.get('verify_ssl')
        self.headers = {'Content-Type': 'application/json'}

    def make_request_call(self, endpoint, payload=None, query_params=None, method='GET', flag=None):
        url = '{base}{endpoint}'.format(base=self.base_url, endpoint=endpoint)
        try:
            response = requests.request(method, url, data=payload, params=query_params, headers=self.headers,
                                        verify=self.verify_ssl)
            if response.status_code in ok:
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            elif flag == 1:
                return response.status_code
            elif self.error_msg.get(response.status_code):
                raise ConnectorError(self.error_msg[response.status_code])
            response.raise_for_status()
        except requests.exceptions.SSLError as e:
            logger.exception(e)
            raise ConnectorError(self.error_msg['ssl_error'])
        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
            raise ConnectorError(self.error_msg['time_out'])
        except Exception as e:
            logger.exception(e)
            raise ConnectorError(e)

    def login(self):
        endpoint = '/PasswordVault/api/Auth/Cyberark/Logon'
        payload = {
            'UserName': self.username,
            'Password': self.password
        }
        token = self.make_request_call(endpoint, payload=json.dumps(payload), method='POST')
        self.headers.update({'Authorization': token})

    def logout(self):
        endpoint = '/PasswordVault/api/Auth/Logoff'
        self.make_request_call(endpoint, method='POST')


def _check_health(config):
    try:
        flag = False
        cyber_ark = CyberARK(config)
        cyber_ark.login()
        vault = config.get('vault')
        if vault is True:
            get_account_details = get_credentials(config, None)
            if get_account_details:
                for account in get_account_details:
                    params = {}
                    keys = account.get("key")
                    params.update({"key": keys})
                    get_application_detail = application_validation(config, params)
                    if isinstance(get_application_detail, dict):
                        flag = True
                        break
                    else:
                        pass
                if flag is True:
                    return True
                else:
                    raise ConnectorError("{0}".format("Invalid Application ID"))
            else:
                raise ConnectorError("{0}".format("Invalid Safe"))
        if cyber_ark.headers.get('Authorization'):
            return True

    except Exception as err:
        logger.exception("{}".format(str(err)))
        raise ConnectorError("{}".format(str(err)))


def add_account_group(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['add_account_group'][1].format(params.get('GroupID'))
    del params['GroupID']
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(params), method='POST')
    cyber_ark.logout()
    return response


def get_account(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['get_account'][1]
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def get_account_group_members(config, params):
    cyber_ark = CyberARK(config)
    GroupID = str(params.get('GroupID'))
    endpoint = operations['get_account_group_members'][1].format(GroupID)
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def delete_account_group_members(config, params):
    cyber_ark = CyberARK(config)
    GroupID = str(params.get('GroupID'))
    AccountID = str(params.get('AccountID'))
    endpoint = operations['delete_account_group_members'][1].format(GroupID, AccountID)
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, method='DELETE')
    cyber_ark.logout()
    return response


def add_user(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['add_user'][1]
    expiryDate = params.get('expiryDate')
    payload = {
        "username": params.get('UserName'),
        "initialPassword": params.get('InitialPassword'),
        "enableUser": params.get("enableUser"),
        "vaultAuthorization": params.get("vaultAuthorization"),
        "changePassOnNextLogon": params.get("ChangePasswordOnTheNextLogon"),
        "internet": {
            "homeEmail": params.get('Email')
        },
        "personalDetails": {
            "firstName": params.get('FirstName'),
            "lastName": params.get('LastName')
        },
        "UserTypeName": "EPVUser"
    }
    if expiryDate:
        date_time = expiryDate.split('T')
        date = date_time[0].split("-")
        time = date_time[1].split(':')
        milli_sec = time[2].split(".")
        epoch = (datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(time[0]), int(time[1]),int(milli_sec[0]), int(milli_sec[1][2])) - datetime.datetime(1970, 1, 1)).total_seconds()
        payload.update({'expiryDate': epoch})
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(payload), method='POST')
    cyber_ark.logout()
    return response


def update_user(config, params):
    cyber_ark = CyberARK(config)
    UserID = params.get('UserID')
    if UserID:
        if UserID < 1:
            raise ConnectorError("{0} should be positive".format("UserID"))
    endpoint = operations['update_user'][1].format(UserID)
    cyber_ark.login()
    params.update({"UserTypeName": "EPVUser"})
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(params), method='POST')
    cyber_ark.logout()
    return response


def delete_user(config, params):
    cyber_ark = CyberARK(config)
    UserID = params.get('UserID')
    if UserID < 1:
        raise ConnectorError("{0} should be positive".format("UserID"))
    endpoint = operations['delete_user'][1].format(UserID)
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, method='DELETE')
    cyber_ark.logout()
    return response


def reset_user_password(config, params):
    cyber_ark = CyberARK(config)
    UserID = params.get('userID')
    if UserID:
        if UserID < 1:
            raise ConnectorError("{0} should be positive".format("UserID"))
    endpoint = operations['reset_user_password'][1].format(UserID)
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(params), method='POST')
    cyber_ark.logout()
    if response:
        return {"message": "Successfull reset user password"}


def logged_on_user_details(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['logged_on_user_details'][1]
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def get_groups(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['get_groups'][1]
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def get_user_details(config, params):
    cyber_ark = CyberARK(config)
    userID = params.get('userID')
    if userID < 1:
        raise ConnectorError("{0} should be positive".format("userID"))
    endpoint = operations['get_user_details'][1].format(userID)
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def activate_user(config, params):
    cyber_ark = CyberARK(config)
    userID = params.get('userID')
    if userID < 1:
        raise ConnectorError("{0} should be positive".format("userID"))
    endpoint = operations['activate_user'][1].format(userID)
    del params['userID']
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(params), method='POST')
    cyber_ark.logout()
    if not response:
        return {"result": "Successfully Activated"}


def add_user_to_group(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['add_user_to_group'][1].format(params.get('GroupID'))
    del params['GroupID']
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(params), method='POST')
    cyber_ark.logout()
    return response


def add_safe(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['add_safe'][1]
    NumberOfVersionsRetention = params.get('NumberOfVersionsRetention')
    NumberOfDaysRetention = params.get('NumberOfDaysRetention')
    Description = params.get('Description')
    if NumberOfDaysRetention:
        if NumberOfDaysRetention < 1 or NumberOfDaysRetention > 999:
            raise ConnectorError("{0} should be between 1 to 999".format("NumberOfDaysRetention"))
    if NumberOfVersionsRetention:
        if NumberOfVersionsRetention < 1 or NumberOfVersionsRetention > 3650:
            raise ConnectorError("{0} should be between 1 to 3650".format("NumberOfVersionRetention"))
    if Description:
        if len(Description) > 100:
            raise ConnectorError("{0} length should not be greater than 100 characters".format("Description"))
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(params), method='POST')
    cyber_ark.logout()
    return response


def list_safes(config, params):
    cyber_ark = CyberARK(config)
    limit = params.get('limit') if params.get('limit') else 500
    endpoint = operations['list_safes'][1].format(int(limit))
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def get_safe_details(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['get_safe_details'][1].format(params.get('Safe'))
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def search_safe(config, params):
    cyber_ark = CyberARK(config)
    query = params.get('query')
    endpoint = operations['search_safe'][1].format(query)
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    result = []
    for key, value in response.items():
        if key == "Safes":
            for d in value:
                for k, v in d.items():
                    if k == "SafeName":
                        n = v.lower().find(query.lower())
                        if int(n) > -1:
                            result.append(dict(d))
    if len(result) == 0:
        raise ConnectorError("No safes found")
    else:
        return result


def get_safe_account_groups(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['get_safe_account_groups'][1].format(params.get('SafeName'))
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def update_safe(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['update_safe'][1].format(params.get('SafeName'))
    NumberOfVersionsRetention = params.get('NumberOfVersionsRetention')
    NumberOfDaysRetention = params.get('NumberOfDaysRetention')
    Description = params.get('Description')
    Location = params.get('Location')
    if Location:
        params.update({"Location": "\\"})
    if NumberOfDaysRetention:
        if NumberOfDaysRetention < 1 or NumberOfDaysRetention > 999:
            raise ConnectorError("{0} should be between 1 to 999".format("NumberOfDaysRetention"))
    if NumberOfVersionsRetention:
        if NumberOfVersionsRetention < 1 or NumberOfVersionsRetention > 3650:
            raise ConnectorError("{0} should be between 1 to 3650".format("NumberOfVersionRetention"))
    if Description:
        if len(Description) > 100:
            raise ConnectorError("{0} length should not be greater than 100 characters".format("Description"))
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(params), method='PUT')
    cyber_ark.logout()
    return response


def delete_safe(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['delete_safe'][1].format(params.get('SafeName'))
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, method='DELETE')
    cyber_ark.logout()
    return response


def add_safe_member(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['add_safe_member'][1].format(params.get('SafeName'))
    del params['SafeName']
    payload = {
        'MemberName': params.get('MemberName'),
        'IsExpiredMembershipEnable': params.get('IsExpiredMembershipEnable')
    }
    del params['MemberName']
    del params['IsExpiredMembershipEnable']
    payload['Permissions'] = params
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(payload), method='POST')
    cyber_ark.logout()
    return response


def list_safe_members(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['list_safe_members'][1].format(params.get('SafeName'))
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint)
    cyber_ark.logout()
    return response


def update_safe_member(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['update_safe_member'][1].format(params.get('SafeName'), params.get('MemberName'))
    del params['MemberName']
    del params['SafeName']
    payload = {
        "IsExpiredMembershipEnable": params.get('IsExpiredMembershipEnable')
    }
    del params['IsExpiredMembershipEnable']
    payload['Permissions'] = params
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, payload=json.dumps(payload), method='PUT')
    cyber_ark.logout()
    return response


def delete_safe_member(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['delete_safe_member'][1].format(params.get('Safe'), params.get('MemberName'))
    cyber_ark.login()
    response = cyber_ark.make_request_call(endpoint, method='DELETE')
    cyber_ark.logout()
    return response


def get_credentials(config, params):
    cyber_ark = CyberARK(config)
    endpoint = operations['get_credentials'][1]
    cyber_ark.login()
    get_account_det = cyber_ark.make_request_call(endpoint, method='GET')
    formatted_output = []
    list_items = get_account_det.get('value')
    for item in list_items:
        if item.get('safeName') == config.get('Safe'):
            userName = item.get('userName')
            if userName:
                formatted_output.append(
                    {
                        "key": item.get('name'),
                        "display_name": item.get('userName')
                    }
                )
            else:
                formatted_output.append(
                    {
                        "key": item.get('name'),
                        "display_name": item.get('name')
                    }
                )

    cyber_ark.logout()
    return formatted_output


def get_credentials_details(config, params):
    cyber_ark = CyberARK(config)
    Object = params.get('secret_id')
    endpoint = operations['get_credentials_details'][1].format(config.get('AppID'), config.get('Safe'), Object)
    cyber_ark.login()
    get_account_det = cyber_ark.make_request_call(endpoint, method='GET')
    cyber_ark.logout()
    formatted_output = []
    list_items = list(get_account_det.keys())
    for item in list_items[:8]:
        formatted_output.append(
            {
                "field_name": item,
                "value": "*****"
            }
        )
    cyber_ark.logout()
    return formatted_output


def get_credential(config, params):
    cyber_ark = CyberARK(config)
    Object = params.get('secret_id')
    endpoint = operations['get_credentials_details'][1].format(config.get('AppID'), config.get('Safe'), Object)
    cyber_ark.login()
    get_account_det = cyber_ark.make_request_call(endpoint, method='GET')
    cyber_ark.logout()
    attribute_name = params.get('attribute_name')
    if attribute_name in get_account_det:
        return {
            "password": get_account_det.get(attribute_name)
        }
    else:
        return {
            "message": "Invalid Attribute"
        }


def application_validation(config, params):
    cyber_ark = CyberARK(config)
    Object = params.get('key')
    endpoint = operations['get_credentials_details'][1].format(config.get('AppID'), config.get('Safe'), Object)
    cyber_ark.login()
    get_account_det = cyber_ark.make_request_call(endpoint, method='GET', flag=1)
    cyber_ark.logout()
    return get_account_det


operations = {
    'add_account_group': [add_account_group, '/PasswordVault/api/v10.10/AccountGroups/{0}/Members'],
    'get_account_group_members': [get_account_group_members, '/PasswordVault/api/v10.10/AccountGroups/{0}/Members'],
    'delete_account_group_members': [delete_account_group_members,
                                     '/PasswordVault/api/v10.10/AccountGroups/{0}/Members/{1}'],

    'add_user': [add_user, '/PasswordVault/api/v10.10/Users'],
    'update_user': [update_user, '/PasswordVault/api/v10.10/Users/{0}'],
    'delete_user': [delete_user, '/PasswordVault/Users/{0}'],
    'reset_user_password': [reset_user_password, '/PasswordVault/api/v10.10/Users/{0}/ResetPassword'],
    'logged_on_user_details': [logged_on_user_details, '/PasswordVault/api/v10.10/Users'],
    'get_groups': [get_groups, '/PasswordVault/api/v10.10/UserGroups'],
    'get_user_details': [get_user_details, '/PasswordVault/api/v10.10/Users/{0}'],
    'activate_user': [activate_user, '/PasswordVault/api/Users/{0}/Activate'],
    'add_user_to_group': [add_user_to_group, '/PasswordVault/api/v10.10/UserGroups/{0}/Members'],

    'add_safe': [add_safe, '/PasswordVault/api/v10.10/Safes'],
    'list_safes': [list_safes, '/PasswordVault/api/v10.10/Safes?limit={0}'],
    'get_safe_details': [get_safe_details, '/PasswordVault/api/v10.10/Safes/{0}'],
    'search_safe': [search_safe, '/PasswordVault/api/v10.10/Safes?query={{0}}'],
    'get_safe_account_groups': [get_safe_account_groups, '/PasswordVault/api/v10.10/Safes/{0}/accountgroups'],
    'update_safe': [update_safe, '/PasswordVault/api/v10.10/Safes/{0}'],
    'delete_safe': [delete_safe, '/PasswordVault/api/v10.10/Safes/{0}'],

    'add_safe_member': [add_safe_member, '/PasswordVault/api/v10.10/Safes/{0}/Members'],
    'list_safe_members': [list_safe_members, '/PasswordVault/api/v10.10/Safes/{0}/Members'],
    'update_safe_member': [update_safe_member, '/PasswordVault/api/v10.10/Safes/{0}/Members/{1}'],
    'delete_safe_member': [delete_safe_member, '/PasswordVault/api/v10.10/Safes/{0}/Members/{1}'],

    'get_account': [get_account, '/PasswordVault/api/v10.10/Accounts'],
    'get_credentials': [get_credentials, '/PasswordVault/api/v10.10/Accounts'],
    'get_credentials_details': [get_credentials_details, '/AIMWebService/api/Accounts?appID={0}&Safe={1}&Object={2}'],
    'get_credential': [get_credential, '/AIMWebService/api/Accounts?appID={0}&Safe={1}&Object={2}']
}
