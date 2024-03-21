"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

MACRO_LIST = ["User_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = "activedirectory"
userADAccountControlFlag = 2
PORT = 389
SSL_PORT = 636
limit = 4294967296
ACC_DONT_EXPIRE_PASSWORD = 65536
NORMAL_ACCOUNT = 512
ENABLE_ACCOUNT = 544
SAM_ACCOUNT_TYPE_DICT = {"0x0": "SAM_DOMAIN_OBJECT",
                         "0x10000000": "SAM_GROUP_OBJECT",
                         "0x10000001": "SAM_NON_SECURITY_GROUP_OBJECT",
                         "0x20000000": "SAM_ALIAS_OBJECT",
                         "0x20000001": "SAM_NON_SECURITY_ALIAS_OBJECT",
                         "0x30000000": "SAM_NORMAL_USER_ACCOUNT",
                         "0x30000001": "SAM_MACHINE_ACCOUNT",
                         "0x30000002": "SAM_TRUST_ACCOUNT ",
                         "0x40000000": "SAM_APP_BASIC_GROUP",
                         "0x40000001": "SAM_APP_QUERY_GROUP",
                         "0x7fffffff": "SAM_ACCOUNT_TYPE_MAX"
                         }

USER_ACCOUNT_CONTROL_DICT = {
    "0x00000001": "LOGON_SCRIPT_EXECUTED",
    "0x00000002": "ACCOUNT_DISABLED",
    "0x00000008": "HOME_DIRECTORY_REQUIRED",
    "0x00000010": "ACCOUNT_LOCKED_OUT",
    "0x00000020": "PASSWORD_NOT_REQUIRED",
    "0x00000040": "PASSWORD_CANT_CHANGE",
    "0x00000080": "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
    "0x00000100": "TEMP_DUPLICATE_ACCOUNT",
    "0x00000200": "NORMAL_ACCOUNT",
    "0x00000800": "INTERDOMAIN_TRUST_ACCOUNT",
    "0x00001000": "WORKSTATION_TRUST_ACCOUNT",
    "0x00002000": "SERVER_TRUST_ACCOUNT",
    "0x00004000": "N/A",
    "0x00008000": "N/A",
    "0x00010000": "DONT_EXPIRE_PASSWORD",
    "0x00020000": "MNS_LOGON_ACCOUNT",
    "0x00040000": "SMART_CARD_REQUIRED",
    "0x00080000": "TRUSTED_FOR_DELEGATION",
    "0x00100000": "NOT_DELEGATED",
    "0x00200000": "ONLY_DES_KEY_ALLOWED",
    "0x00400000": "PREAUTH_NOT_REQUIRED",
    "0x00800000": "PASSWORD_EXPIRED",
    "0x01000000": "TRUESTED_AUTHENTICATION_FOR_DELEGATION",
}

SEARCH_ATTRIBUTES_DICT = {
    "Name": "name",
    "SamAccount Name": "sAMAccountName",
    "Common Name": "cn",
    "Distinguished Name": "distinguishedName",
    "Object SID": "objectSid",
    "Surname": "sn",
    "Display Name": "displayName",
    "Given Name": "givenName",
    "Email": "userPrincipalName"

}
SEARCH_OBJECT_CLASS_DICT = {
    "User": "user",
    "Computer": "computer",
    "Group": "group",
    "Person": "person",
    "Organization Unit": "organizationalUnit"
}
ACTION_TYPE = ["addResponse", "modifyResponse", "delResponse"]
RESPONSE = {
    'entryAlreadyExists': 'The Record Already Exists in Active Directory',
    'insufficientAccessRights': 'Insufficient Access Rights'
}
GROUP_TYPE = {"Global Distribution Group": 2, "Domain Local Distribution Group": 4, "Universal Distribution Group": 8,
              "Global Security Group": -2147483646, "Domain Local Security Group": -2147483644,
              "Universal Security Group": -2147483640, "BuiltIn Group": 2147483643
              }



