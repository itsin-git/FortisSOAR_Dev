""""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import base64, ipaddress, json, ldap3, time
from connectors.core.connector import get_logger, ConnectorError
from .constant import *

logger = get_logger('activedirectory')


def bind_server(hostname, custom_port, username, password, use_tls):
    try:
        if use_tls:
            auto_bind = ldap3.AUTO_BIND_TLS_BEFORE_BIND
            port = custom_port if custom_port else SSL_PORT
        else:
            if custom_port:
                port = custom_port
            else:
                port = PORT
            auto_bind = ldap3.AUTO_BIND_NO_TLS
        conn = ldap3.Connection(ldap3.Server(hostname, port=port, use_ssl=use_tls), auto_bind=auto_bind,
                                user=username, password=password)
        if use_tls:
            conn.start_tls()
        if conn.result:
            result = conn.result.get('description')
            if 'success' in result.lower():
                logger.info('bind successfully: {0}'.format(str(result)))
                return conn
            else:
                raise ConnectorError('Error in bind: {0}'.format(str(result)))

    except Exception as err:
        raise ConnectorError('{0}'.format(str(err)))


def login_logon_name(hostname, port, username, password, baseDN, use_tls):
    try:
        domain = []
        for x in baseDN.split(','):
            if 'DC=' in x.upper():
                domain.append(x.split('=')[-1])
        username = '{0}@{1}'.format(username, '.'.join(domain))
        return bind_server(hostname, port, username, password, use_tls)
    except Exception as err:
        raise ConnectorError('{0}'.format(str(err)))


def server_connection(config):
    try:
        hostname = config.get('hostname')
        port = config.get('port')
        username = config.get('username')
        password = config.get('password')
        baseDN = config.get('baseDN')
        bindDN = config.get('bindDN')
        use_tls = config.get('use_tls', False)
        if bindDN:
            return bind_server(hostname, port, bindDN, password, use_tls)
        if '@' not in username and '\\' not in username:
            return login_logon_name(hostname, port, username, password, baseDN, use_tls)
        else:
            return bind_server(hostname, port, username, password, use_tls)
    except Exception as err:
        raise ConnectorError('{0}'.format(str(err)))


def get_user_account_control_detail(data):
    result = ''
    for key, val in USER_ACCOUNT_CONTROL_DICT.items():
        int_key = int(key, 16)
        if int(data) & int_key:
            if result:
                result = result + ' | ' + val
            else:
                result = val
    return result


def convert_ad_timestamp(timestamp):
    epoch_time = []
    if isinstance(timestamp, str):
        try:
            timestamp = timestamp.split("+")
            timestamp = timestamp[0]
            if '.' in timestamp:
                timestamp = timestamp.split('.')
                timestamp = timestamp[0]
            time_tuple = time.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            time_epoch = time.mktime(time_tuple)
            time_epoch_int = int(time_epoch)
            if time_epoch_int < 0:
                time_epoch_int = None
            return time_epoch_int
        except:
            return None
    elif isinstance(timestamp, list):
        try:
            for time_str in timestamp:
                time_str = time_str.split("+")
                time_str = time_str[0]
                if '.' in time_str:
                    time_str = time_str.split('.')
                    time_str = time_str[0]
                time_tuple = time.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                epoch_val = time.mktime(time_tuple)
                epoch_val_int = int(epoch_val)
                if epoch_val_int < 0:
                    epoch_val_int = None
                epoch_time.append(epoch_val_int)
        except:
            epoch_time.append(None)
    return epoch_time


def search(conn, baseDN, filter_str, size_limit=0, page_size=None, cookie=None):
    try:
        if cookie:
            cookie = base64.b64decode(cookie)
        conn.search(search_base=baseDN,
                    search_filter=filter_str,
                    search_scope=ldap3.SUBTREE,
                    attributes=ldap3.ALL_ATTRIBUTES,
                    size_limit=size_limit if size_limit else 0,
                    paged_size=page_size if page_size else None,
                    paged_cookie=cookie if cookie else None
                    )
        controls = conn.result.get('controls')
        if controls:
            cookie = controls.get('1.2.840.113556.1.4.319').get('value').get('cookie')
            cookie = base64.b64encode(cookie)
        else:
            if cookie:
                cookie = base64.b64encode(cookie)
        result_set = conn.response_to_json()
        if result_set:
            result_set = result_set.replace(u'\u0000', '').replace(u'\\u0000', '')
            json_data = json.loads(result_set)
            json_data.update({'cookie': cookie})
            return json_data
    except Exception as err:
        logger.exception('Failure: {0}'.format(str(err)))
        raise ConnectorError('{0}'.format(str(err)))


def get_attribute(conn, baseDN, search_attr_name, search_attr_value, object_type=None):
    try:
        filter = '(objectclass=*)'
        if search_attr_name == 'sAMAccountName':
            if object_type and object_type.lower() == 'computer':
                if search_attr_value and not search_attr_value.endswith('$') and not '*' in search_attr_value:
                    search_attr_value = search_attr_value.upper() + '$'
                filter = '(&(objectCategory=computer)(objectClass=computer)(sAMAccountName={1}))'.format(filter, search_attr_value)
            else:
                filter = '(&{0}(sAMAccountName={1}))'.format(filter, search_attr_value)

        if search_attr_name == 'userPrincipalName':
            filter = '(&{0}(|(userPrincipalName={1})(mail={1})))'.format(filter,
                                                                         search_attr_value)
        if search_attr_name == 'distinguishedName':
            filter = '(&{0}(distinguishedName={1}))'.format(filter, search_attr_value)
        return search(conn, baseDN, filter_str=filter)
    except Exception as err:
        raise ConnectorError('{0}'.format(str(err)))


def check_response(result):
    if not result['message'] and result['result'] == 0:
        status = result['description']
        if status.lower() == 'success':
            logger.info('account enable successfully')
            return result
        else:
            raise ConnectorError('Failure: {0}'.format(str(result)))
    else:
        return result


def enable_user_account(config, params):
    result = perform_action(config, params, 'enable')
    return check_response(result)


def disable_user_account(config, params):
    result = perform_action(config, params, 'disable')
    return check_response(result)


def move_user_ou(config, params):
    result = perform_action(config, params, 'move')
    return check_response(result)


def enable_computer(config, params):
    result = perform_action(config, params, 'enable', object_type='computer')
    return check_response(result)


def disable_computer(config, params):
    result = perform_action(config, params, 'disable', object_type='computer')
    return check_response(result)


def perform_action(config, params, action, object_type=None):
    try:
        baseDN = config.get('baseDN')
        conn = server_connection(config)
        search_attr_name = SEARCH_ATTRIBUTES_DICT[params.get('search_attr_name')]
        search_attr_value = params.get('search_attr_value')
        json_data = get_attribute(conn, baseDN, search_attr_name, search_attr_value, object_type)
        entries = json_data.get('entries')
        if entries:
            dn = entries[0]['dn']
            userAccountControl = entries[0]['attributes']['userAccountControl']
            if action.lower() == 'enable':
                flag = userAccountControl & ~userADAccountControlFlag
            elif action.lower() == 'disable':
                flag = userAccountControl | userADAccountControlFlag
            elif action.lower() == 'move':
                destinationOU = params.get('destinationOU')
                return modify_dn(conn, dn, destinationOU=destinationOU)
            else:
                raise ConnectorError('Invalid action {}'.format(str(action)))
            mod_dict = {'userAccountControl': [(ldap3.MODIFY_REPLACE, flag)]}
            return modify(conn, dn, mod_dict)
        else:
            return {'message': 'Record not found in Active Directory'}

    except Exception as err:
        raise ConnectorError('{0}'.format(str(err)))


def modify(conn, dn, mod_dict):
    try:
        if mod_dict:
            conn.modify(dn, mod_dict)
            return conn.result
        else:
            raise ConnectorError('mod dict empty {0}'.format(mod_dict))
    except Exception as err:
        raise ConnectorError('{0}'.format(str(err)))


def modify_dn(conn, dn, destinationOU="", newCN=""):
    try:
        if destinationOU:
            conn.modify_dn(dn, dn.split(',', 1)[0], new_superior=destinationOU)
            return conn.result
        elif newCN:
            conn.modify_dn(dn, "cn=" + newCN)
            return conn.result
        else:
            raise ConnectorError('Destination OU or New common Name empty {0}'.format(destinationOU))
    except Exception as err:
        raise ConnectorError('{0}'.format(str(err)))


def decimal_to_ip_address(decimal_val):
    if decimal_val <= 0:
        decimal_val = limit + decimal_val
        return ipaddress.ip_address(decimal_val)
    else:
        return ipaddress.ip_address(decimal_val)


def formatting_data(json_data):
    if not json_data['entries']:
        json_data['message'] = 'Record not found in Active Directory'
    else:
        convert_ad_ts = ['accountExpires', 'badPasswordTime', 'dSCorePropagationData', 'lastLogoff', 'lastLogon',
                         'lastLogonTimestamp', 'lockoutTime', 'pwdLastSet', 'whenChanged', 'whenCreated',
                         'msExchWhenMailboxCreated']
        entries = json_data.get('entries')
        ip_details = ['msRADIUSFramedIPAddress', 'msRASSavedFramedIPAddress']

        for each_dict in entries:
            attributes = each_dict['attributes']
            for key, val in attributes.items():
                if key == 'userAccountControl':
                    attributes[key] = get_user_account_control_detail(val)
                if key == 'sAMAccountType':
                    hex_val = hex(int(val))
                    attributes[key] = SAM_ACCOUNT_TYPE_DICT[hex_val]
                if key in convert_ad_ts:
                    attributes[key] = convert_ad_timestamp(val)
                if key in ip_details:
                    attributes[key] = str(decimal_to_ip_address(int(val)))
                if key == 'groupType':
                    try:
                        attributes[key] = list(GROUP_TYPE.keys())[list(GROUP_TYPE.values()).index(val)]
                    except ValueError:
                        attributes[key] = val
    return json_data


def check_escape(search_attr_name, raw_string):
    if search_attr_name == 'distinguishedName':
        if isinstance(raw_string, bytes) or (', ' not in raw_string and ' ,' not in raw_string) or (
                        ' ,' not in raw_string and ', ' not in raw_string):
            return raw_string
        escaped = ''
        i = 0
        while i < len(raw_string):
            if raw_string[i] == ',' and raw_string[i + 1] == ' ' and i < len(raw_string) - 2:
                try:
                    value = int(raw_string[i])
                    escaped += chr(value)
                    i += 2
                except ValueError:
                    escaped += '\\,'
            elif raw_string[i] == ' ' and raw_string[i + 1] == ',' and i < len(raw_string) - 2:
                try:
                    value = int(raw_string[i])
                    escaped += chr(value)
                    i += 2
                except ValueError:
                    escaped += ' \\'
            else:
                escaped += raw_string[i]
            i += 1

        return escaped
    else:
        return raw_string


def global_search(config, params):
    try:
        baseDN = config.get('baseDN')
        conn = server_connection(config)
        search_object = SEARCH_OBJECT_CLASS_DICT[params.get('search_object')]
        search_attr_name = SEARCH_ATTRIBUTES_DICT[params.get('search_attr_name')]
        search_attr_value = params.get('search_attr_value')
        page_size = params.get('page_size')
        size_limit = params.get('size_limit')
        cookie = params.get('cookie')
        filter_str = '(&(objectCategory={0})(objectClass={0})'.format(str(search_object))
        if search_object:
            if search_object.lower() == 'computer' and search_attr_name == 'sAMAccountName':
                if search_attr_value and not search_attr_value.endswith('$') and not '*' in search_attr_value:
                    search_attr_value = search_attr_value.upper() + '$'
        if search_attr_name == 'userPrincipalName':
            query = '(|(userPrincipalName={0})(mail={0})))'.format(search_attr_value)
        else:
            query = '({0}={1}))'.format(search_attr_name, search_attr_value)
        filter_str += query
        logger.debug("LDAP Query: {}".format(filter_str))
        json_data = search(conn, baseDN, filter_str, size_limit, page_size, cookie)
        entries = formatting_data(json_data)
        conn.unbind()
        return entries
    except Exception as err:
        logger.exception('Failure: {0}'.format(str(err)))
        raise ConnectorError('{0}'.format(str(err)))


def get_all_object_details(config, params):
    try:
        baseDN = config.get('baseDN')
        conn = server_connection(config)
        search_object = SEARCH_OBJECT_CLASS_DICT[params.get('search_object')]
        page_size = params.get('page_size')
        size_limit = params.get('size_limit')
        cookie = params.get('cookie')
        if search_object == 'organizationalUnit':
            filter_str = '(&(objectClass={0})(objectCategory={0}))'.format(str(search_object))
        else:
            filter_str = '(&(objectClass={0})(objectCategory={0})(sAMAccountName=*))'.format(str(search_object))
        logger.debug("LDAP Query: {}".format(filter_str))
        json_data = search(conn, baseDN, filter_str, size_limit, page_size, cookie)
        conn.unbind()
        return formatting_data(json_data)
    except Exception as err:
        logger.exception('Failure: {0}'.format(str(err)))
        raise ConnectorError('{0}'.format(str(err)))


def get_specific_object_details(config, params):
    try:
        baseDN = config.get('baseDN')
        conn = server_connection(config)
        search_object = SEARCH_OBJECT_CLASS_DICT[params.get('search_object')]
        cn = params.get('cn')
        sn = params.get('sn')
        search_attr_value = params.get('search_attr_value')
        filter_str = '(&(objectCategory={0})(objectClass={0})'.format(str(search_object))
        if search_object.lower() == 'computer' and search_attr_value:
            if search_attr_value and not search_attr_value.endswith('$'):
                search_attr_value = search_attr_value.upper() + '$'
            query = '(sAMAccountName={0}))'.format(str(search_attr_value))
        elif search_object.lower() == 'person':
            if cn and sn:
                query = '(&(cn={0})(sn={1})))'.format(str(cn), str(sn.strip()))
            else:
                query = '(|(cn={0})(sn={1})))'.format(str(cn), str(sn.strip()))
        else:
            query = '(sAMAccountName={0}))'.format(str(search_attr_value))
        query_str = filter_str + query
        logger.debug("LDAP Query: {}".format(query_str))
        json_data = search(conn, baseDN, query_str)
        conn.unbind()
        return formatting_data(json_data)
    except Exception as err:
        logger.exception('Failure: {0}'.format(str(err)))
        raise ConnectorError('{0}'.format(str(err)))


def reset_password(config, params):
    try:
        baseDN = config.get('baseDN')
        new_password = params.get('new_password')
        conn = server_connection(config)
        search_attr_name = SEARCH_ATTRIBUTES_DICT[params.get('search_attr_name')]
        search_attr_value = params.get('search_attr_value')
        json_data = get_attribute(conn, baseDN, search_attr_name, search_attr_value)
        entries = json_data.get('entries')
        if entries:
            user_base_dn = entries[0]['dn']
            if user_base_dn:
                user_acc_ctrl = int(entries[0]['attributes']['userAccountControl'])
                if user_acc_ctrl & ACC_DONT_EXPIRE_PASSWORD > 0:
                    logger.info("Account has don't expire password property set, changed property to normal account")
                    mod_dict = {'userAccountControl': [(ldap3.MODIFY_REPLACE, NORMAL_ACCOUNT)]}
                    modify(conn, user_base_dn, mod_dict)
                mod_dict = {'pwdLastSet': [(ldap3.MODIFY_REPLACE, 0)]}
                result = modify(conn, user_base_dn, mod_dict)
                status = result['description']
                if status.lower() == 'success':
                    logger.info('Previous password clear successfully {}'.format(user_base_dn))
                    enc_pwd = '"{}"'.format(new_password).encode('utf-16-le')
                    mod_dict = {'unicodePwd': [(ldap3.MODIFY_REPLACE, [enc_pwd])]}
                    result = modify(conn, user_base_dn, mod_dict)
                    status = result['description']
                    if status.lower() == 'success':
                        logger.info('Password Reset successfully {}'.format(user_base_dn))
                    else:
                        result['message'] = 'password must meet the password policy requirements,' \
                                            'minimum password length and password complexity.'
                        logger.error('{0}'.format(status))
                conn.unbind()
                return result
        else:
            return {'message': 'Record not found in Active Directory'}
    except Exception as err:
        logger.exception('Failure: {0}'.format(str(err)))
        raise ConnectorError('{0}'.format(str(err)))


def advanced_search(config, params):
    try:
        conn = server_connection(config)
        custom_query = params.get('query')
        base_dn = config.get('baseDN')
        page_size = params.get('page_size')
        size_limit = params.get('size_limit')
        cookie = params.get('cookie')
        logger.debug("LDAP Query: {}".format(custom_query))
        json_data = search(conn, base_dn, custom_query, size_limit, page_size, cookie)
        conn.unbind()
        if json_data['entries']:
            return formatting_data(json_data)
        else:
            return {'message': 'Record not found in Active Directory'}
    except Exception as err:
        logger.error('Failure: {0}'.format(str(err)))
        raise ConnectorError('{0}'.format(str(err)))


def add_object(config, params):
    try:
        object_classes = ["top"]
        conn = server_connection(config)
        payload = build_payload(params)
        object_dn = payload.pop('object_dn', '')
        custom_attribute = params.pop('custom_attributes', {})
        object_class = params.get('object_class')
        if object_class:
            object_classes.append(SEARCH_OBJECT_CLASS_DICT.get(object_class))
        if custom_attribute:
            payload.update(custom_attribute)
        conn.add(object_dn, object_classes, payload)
        return build_response(conn, object_class, object_dn, action='added')
    except Exception as err:
        logger.error("{0}".format(err))
        raise ConnectorError(err)


def delete_object(config, params):
    try:
        conn = server_connection(config)
        base_dn = config.get('baseDN')
        object_class = params.pop('object_class')
        search_attr_name = SEARCH_ATTRIBUTES_DICT[params.get('search_attr_name')]
        search_attr_value = params.get('search_attr_value')
        if object_class.lower() == 'computer' and search_attr_name == 'sAMAccountName':
            if search_attr_value and not search_attr_value.endswith('$'):
                search_attr_value = search_attr_value.upper() + '$'
        json_data = get_attribute(conn, base_dn, search_attr_name, search_attr_value)
        entries = json_data.get('entries')
        if entries:
            object_dn = entries[0]['dn']
            if object_dn:
                conn.delete(object_dn)
                return build_response(conn, object_class, object_dn, action='deleted')
        else:
            conn.unbind()
            return {"message": "Record not found in Active Directory", "description": "failed"}

    except Exception as err:
        logger.error("{0}".format(err))
        raise ConnectorError(err)


def update_object(config, params):
    try:
        object_classes = ["top"]
        conn = server_connection(config)
        base_dn = config.get('baseDN')
        payload = build_payload(params)
        object_dn = payload.pop('object_dn', '')
        json_data = get_attribute(conn, base_dn, 'distinguishedName', object_dn)
        entries = json_data.get('entries')
        custom_attribute = params.pop('custom_attributes', {})
        object_class = params.get('object_class')
        if object_class:
            object_classes.append(SEARCH_OBJECT_CLASS_DICT.get(object_class))
        if custom_attribute:
            payload.update(custom_attribute)
        if entries:
            attributes = build_modify_payload(payload)
            conn.modify(object_dn, attributes)
            return build_response(conn, object_class, object_dn, action='updated')
        else:
            conn.unbind()
            return {"message": "Record not found in Active Directory", "description": "failed"}
    except Exception as err:
        logger.error("{0}".format(err))
        raise ConnectorError(err)


def add_group_members(config, params):
    try:
        conn = server_connection(config)
        object_class = params.get('object_class')
        object_dn = params.get('object_dn')
        if isinstance(object_dn, str):
            object_dn = [object_dn]
        group_dn = params.get('group_dn')
        if isinstance(group_dn, str):
            group_dn = [group_dn]
        conn.extend.microsoft.add_members_to_groups(object_dn, group_dn)
        return build_response(conn, object_class, object_dn, action='added into group', group_dn=group_dn)
    except Exception as err:
        logger.exception('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def remove_group_members(config, params):
    try:
        conn = server_connection(config)
        object_class = params.get('object_class')
        object_dn = params.get('object_dn')
        if isinstance(object_dn, str):
            object_dn = [object_dn]
        group_dn = params.get('group_dn')
        if isinstance(group_dn, str):
            group_dn = [group_dn]
        conn.extend.microsoft.remove_members_from_groups(object_dn, group_dn)
        return build_response(conn, object_class, object_dn, action='removed from group', group_dn=group_dn)
    except Exception as err:
        logger.exception('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def build_payload(params):
    payload = dict()
    object_class = params.get('object_class')

    object_dn = params.get('object_dn')
    if object_dn:
        payload.update({'object_dn': object_dn})

    enable_account = params.get('enable_account')
    if enable_account:
        payload.update({'userAccountControl': ENABLE_ACCOUNT})

    sam_account_name = params.get('sAMAccountName')
    if sam_account_name:
        payload.update({'sAMAccountName': sam_account_name})

    description = params.get('description')
    if description:
        payload.update({'description': description})

    display_name = params.get('displayName')
    if display_name:
        payload.update({'displayName': display_name})

    if object_class == 'User':

        mail = params.get('mail')
        if mail:
            payload.update({'mail': mail})

        user_principle_name = params.get('userPrincipalName')
        if user_principle_name:
            payload.update({'userPrincipalName': user_principle_name})

        title = params.get('title')
        if title:
            payload.update({'title': title})

    elif object_class == 'Computer':
        # https://social.technet.microsoft.com/Forums/en-US/eec574c0-5421-4d7a-a806-a3c5af3d29bf/why-in-samaccount-name-of-computer-account-in-active-directory?forum=winserverDS
        # All computer accounts in Active Directory have a dollar sign appended to the end of the name. That is a requirement for computer accounts.  It helps distinguish them from user accounts (when looking at some management consoles such as Computer Management).  So, it doesn't mean anything specific to sessions - only that it is a computer account.
        if sam_account_name and not sam_account_name.endswith('$'):
            payload.update({'sAMAccountName': sam_account_name.upper() + '$'})

    elif object_class == 'Group':

        group_type = params.get('GroupType', '')
        if group_type:
            payload['GroupType'] = GROUP_TYPE.get(group_type)
        payload.pop('displayName', '')
        payload.pop('userAccountControl', '')
        payload.pop('description', '')
    else:
        payload.pop('sAMAccountName', '')
        payload.pop('userAccountControl', '')
        payload.pop('displayName', '')

    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def build_modify_payload(params):
    payload = {}
    for k, v in params.items():
        payload.update({k: [(ldap3.MODIFY_REPLACE, [v])]})
    return payload


def build_response(conn, object_class, object_dn, action=None, group_dn=None):
    result = conn.result
    conn.unbind()
    if result:
        status = result.get('description')
        action_type = result.get('type')
        if status.lower() == 'success':
            if action_type in ACTION_TYPE:
                result.update({'message': '{0} successfully {1}'.format(object_class, action), 'dn': object_dn})
                if group_dn:
                    result.update({'group_dn': group_dn})
                return result
            else:
                result.update({'message': 'Something went wrong!'})
                return result
        else:
            raise ConnectorError(
                'Failure: {0}'.format(str(result['description'] if result['description'] else None)))
    else:
        raise ConnectorError('Failure: {0}'.format(str(result['description'])))


def force_password_reset_next_logon(config, params):
    try:
        baseDN = config.get('baseDN')
        conn = server_connection(config)
        search_attr_name = SEARCH_ATTRIBUTES_DICT[params.get('search_attr_name')]
        search_attr_value = params.get('search_attr_value')
        json_data = get_attribute(conn, baseDN, search_attr_name, search_attr_value)
        entries = json_data.get('entries')
        if entries:
            user_base_dn = entries[0]['dn']
            if user_base_dn:
                user_acc_ctrl = int(entries[0]['attributes']['userAccountControl'])
                if user_acc_ctrl & ACC_DONT_EXPIRE_PASSWORD > 0:
                    logger.info("Account has don't expire password property set, changed property to normal account")
                    mod_dict = {'userAccountControl': [(ldap3.MODIFY_REPLACE, NORMAL_ACCOUNT)]}
                    modify(conn, user_base_dn, mod_dict)
                mod_dict = {'pwdLastSet': [(ldap3.MODIFY_REPLACE, 0)]}
                result = modify(conn, user_base_dn, mod_dict)
                status = result['description']
                if status.lower() == 'success':
                    logger.info('Previous password clear successfully {}'.format(user_base_dn))
                else:
                    result['message'] = 'Something went wrong!'
                    logger.error('{0}'.format(status))
                conn.unbind()
                return result
        else:
            return {'message': 'Record not found in Active Directory'}
    except Exception as err:
        logger.exception('Failure: {0}'.format(str(err)))
        raise ConnectorError('{0}'.format(str(err)))


def move_computer_ou(config, params):
    try:
        conn = server_connection(config)
        computer_dn = params.get('computer_dn')
        target_dn = params.get('target_dn')
        computer_name = params.get('computer_name')
        # Search for the computer to move
        conn.search(computer_dn, '(objectClass=computer)', search_scope=ldap3.BASE)
        if len(conn.entries) != 1:
            return {'status': 'failed','message': 'Computer record not found or not unique', 'count': len(conn.entries)}
        # Move the computer to the target OU
        modification = {"distinguishedName": [(ldap3.MODIFY_REPLACE, [target_dn])]}
        conn.modify(computer_dn, modification)
        conn.modify_dn(computer_dn, "CN={}".format(computer_name), new_superior=target_dn)
        return {'status': 'success','message': f"Successfully moved computer '{computer_dn}' to '{target_dn}'"}
    except Exception as e:
        logger.exception(f"Failed to modifying computer OU: {e}")
        ConnectorError(f"Failed to modifying computer OU: {e}")


def _check_health(config):
    try:
        conn = server_connection(config)
        if conn.result:
            result = conn.result.get('description')
            if 'success' in result:
                return True
        else:
            if not conn.bind():
                logger.error('connector disconnected')
                raise Exception('Error in bind {0}'.format(str(conn.result.get('description'))))
    except Exception as err:
        logger.exception('Failure: {0}'.format(str(err)))
        raise ConnectorError(str(err))


operations = {
    'global_search': global_search,
    'get_all_object_details': get_all_object_details,
    'get_specific_object_details': get_specific_object_details,
    'enable_user_account': enable_user_account,
    'disable_user_account': disable_user_account,
    'move_user_ou': move_user_ou,
    'enable_computer': enable_computer,
    'disable_computer': disable_computer,
    'reset_password': reset_password,
    'advanced_search': advanced_search,
    'add_object': add_object,
    'delete_object': delete_object,
    'update_object': update_object,
    'add_group_members': add_group_members,
    'remove_group_members': remove_group_members,
    'force_password_reset_next_logon': force_password_reset_next_logon,
    'move_computer_ou': move_computer_ou

}
