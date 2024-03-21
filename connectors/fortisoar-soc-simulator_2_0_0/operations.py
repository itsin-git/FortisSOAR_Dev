import json, requests, os, random, re, arrow, secrets, base64, logging
from connectors.core.connector import get_logger, ConnectorError
from django.conf import settings
from connectors.cyops_utilities.builtins import upload_file_to_cyops
from docx import Document
from io import BytesIO 
from .constants import *
from .utils import *
from .fakemalware import *

logger = get_logger('FortiSOARSocSimulator')
logger.setLevel(logging.DEBUG)

def __threatdata_from_file(filename , params):
    """
    Returns an item from threat intel file
    """
    file_path = "{}/threat_intelligence/{}.txt".format(os.path.dirname(__file__), filename)
    lines = open(file_path).read().splitlines()
    if params and params.get('random') == False:
        return lines[0]            
    else:
        return(random.choice(lines))

def bad_ip(params):
    return __threatdata_from_file('malicious_ips', params)

def bad_url(params):
    return __threatdata_from_file('malicious_urls', params)

def bad_filehash(params):
    return __threatdata_from_file('malware_hashes', params)

def bad_domain(params):
    return __threatdata_from_file('malicious_domains', params)

def __replace_variables(input_string,params=None):
    """
    Parses alert record JSON and replaces tags with corresponding dynamic vlaues
    
    :param str input_string: the string to parse
    :param dict params: list of params defined in info.json
    :return: Host IP
    :rtype: str
    """      
    if isinstance(input_string, dict):
        input_string = json.dumps(input_string)
    
    tag_list = re.findall(r'<<(TR_[A-Z0-9_,.-]+)>>',input_string)
    logger.debug("Tags found [{}]".format(tag_list))
    try:
        if not tag_list:
            return json.loads(input_string)     #No tag to replace
        else:
            for tag in tag_list:
                if not tag:
                    continue
                if ',' in tag and len(tag.split(',')) > 1:
                    tr_tag = tag.split(',')
                    tr_function = tr_tag[0]
                    tr_params = tr_tag[1:]
                    tag_value = str(function_dictionary[tr_function](tr_params))
                    logger.debug("Tag: [{0}] replaced with [{1}]".format(tag,tag_value))
                    input_string = input_string.replace('<<'+tag+'>>',tag_value)
                else:
                    tag_value = str(function_dictionary[tag](params))
                    logger.debug("Tag: [{0}] replaced with [{1}]".format(tag,tag_value))
                    input_string = input_string.replace('<<'+tag+'>>',tag_value)
        return json.loads(input_string)

    except Exception as e:
        logger.exception(e)
        raise ConnectorError(str(e))

def replace_variables(params):
    """
    Parses alert record JSON and replaces tags with corresponding dynamic vlaues
    params here can be misleading, it is actually the value of input_string
    TODO: improve the implementation logic/naming when passing parameters
    """
    return __replace_variables(params.get('variables'),params)


def tr_get_random_integer(params):
    if params and isinstance(params, list) and len(params) == 2:
        return random.randint(int(params[0]), int(params[1]))
    else:
        return random.randint(1, 999999)

def tr_get_asset_ip(params):
    """
    return a random host IP, If params is defined as a network address returns an IP from that subnet
    
    :param str params: Network address of the subnet from which to return a host IP
    :return: Host IP
    :rtype: str
    """    
    try:
        if params and isinstance(params, list) and len(params) == 1:
            ip_address = params[0].split('.')
            ip_address[-1] =str(random.randint(2, 240))
            return '.'.join(ip_address)
        else:
            return "10.200.3." + str(random.randint(2, 240))

    except Exception as err:
        return "10.200.3." + str(random.randint(2, 240))

def malicious_file_indicator(params):
    """
    Using a predefined base64 encoded docx in constans.py, creates a new file with the possibility to embed a malicious URL/email
    
    :param str params['file_name']: Created file name
    :param str params['malicious_url']: URL to embed
    :param str params['malicious_email']: Email to embed
    :param str params['attachment_also']: also creates an attachment record in FortiSOAR
    :return: POST /api/3/files and POST /api/3/indicators response
    :rtype: dict
    """

    file_content = base64.b64decode(MALICIOUS_FILE_B64) + secrets.token_bytes(12)
    file_name = params.get('file_name') if params.get('file_name') else 'Password_reset_{}.docx'.format(arrow.utcnow())
    malicious_url = params.get('malicious_url') if params.get('malicious_url') else 'https://malicious_url.co.uk/maliciouspage.php'
    malicious_email = params.get('malicious_email') if params.get('malicious_email') else 'malicious_user@bad-domain.com'
    attachment_also = params.get('attachment_also') if params.get('attachment_also') else False
    custom_parameters = params.get('custom_parameters', None)
    try:
        path = os.path.join(settings.TMP_FILE_ROOT, file_name)
        logger.debug("Path: {0}".format(path))

        source_stream = BytesIO(file_content)
        document = Document(source_stream)
        document.add_paragraph(PHISHING_PHRASE.format(EMAIL=malicious_email,URL=malicious_url))
        document.save(path)
        source_stream.close()

        attach_response = upload_file_to_cyops(file_path=path, filename=file_name,
                                                name=file_name, create_attachment=attachment_also)

        file_iri = attach_response['file']['@id'] if attachment_also else attach_response['@id']
        INDICATOR_JSON_PAYLOAD.update({'file':file_iri})
        INDICATOR_JSON_PAYLOAD.update({'value':file_name})
        if custom_parameters:
            INDICATOR_JSON_PAYLOAD.update(custom_parameters)
        indicator_response = make_request('/api/3/indicators', 'POST', body=INDICATOR_JSON_PAYLOAD)        
        os.remove(path)
        return {'file':attach_response,'indicator':json.loads(indicator_response.content)}
        

    except Exception as e:
        os.remove(path)
        logger.exception(e)
        raise ConnectorError(str(e))


def create_simulated_alert(params):
    """
    Creates an alert record from its JSON definition after replacing variables (tags) with their values. this allows any user to copy the JSON definition of an alert from a browser dev tool, replace some of the static values with variables (tags) and use this action to create new dynamically populated alerts for demo/scenario purposes
    
    :param str params['alert_json']: Alert definition in JSON
    :return: POST /api/3/alerts response
    :rtype: dict
    """    
    json_payload = {}
    try:
        fields_to_ignore = params.get('fields_to_ignore').replace(' ','').split(',') if params.get('fields_to_ignore') else FIELDS_TO_IGNORE        
        alert_json = params.get('alert_json') if isinstance(params.get('alert_json'), dict) else json.loads(params.get('alert_json'))
        logger.debug('Ignoring input alert fields:{}'.format(fields_to_ignore))
        for k,v in alert_json.items():
            if k not in fields_to_ignore:
                json_payload.update({k:v})
        response = make_request('/api/3/alerts', 'POST', body=__replace_variables(json_payload))
        return response.json()

    except Exception as e:
        logger.exception(e)
        raise ConnectorError(str(e))        

def tr_get_my_public_ip(params):
    """
    Returns FortiSOAR public IP
    
    :return: Public IP address
    :rtype: str
    """     
    try:
        response = requests.get(url='https://api.ipify.org/?format=txt')
        if response.status_code != 200:
            logger.error('Public IP lookup Failed')
            raise ConnectorError('Public IP lookup Failed')
        return str(response.content, 'utf-8')        

    except requests.ConnectionError:
        logger.error("Public IP Lookup - Connection error")
        raise ConnectorError("Public IP Lookup - Connection error")
    except requests.ConnectTimeout:
        logger.error("Public IP Lookup - Connection timeout")
        raise ConnectorError("Public IP Lookup - Connection timeout")
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))        

def tr_get_username(params):
    usernames=['Sun.Tzu','Albert.Einstein','Isaac.Newton','Leonardo.Da.Vinci','Aristotle','Galileo.Galilei','Alexander.the.Great','Charles.Darwin','Plato','William.Shakespeare','Martin.Luther.Kin','Socrates','Mahatma.Gandhi','Abraham.Lincoln','George.Washington','Mose','Nikola.Tesla','Gautama.Buddha','Julius.Ceasar','Karl.Marx','Martin.Luther','Napoleon.Bonaparte','Johannes.Gutenberg']
    return random.choices(usernames)[0]

def tr_get_timestamp(params):
    if params and isinstance(params, list) and len(params) == 1:
        epoch_time = arrow.utcnow().shift(minutes=-params[0]).int_timestamp
        return str(epoch_time)
    else:
        epoch_time = arrow.utcnow().int_timestamp
        return str(epoch_time)


def tr_get_formatted_time(params):
    if params and isinstance(params, list) and len(params) == 1:
        formatted_time = arrow.utcnow().shift(minutes=-params[0]).format('ddd, DD MMM YYYY HH:mm:ss Z')
        return str(formatted_time)
    else:
        formatted_time = arrow.utcnow().format('ddd, DD MMM YYYY HH:mm:ss Z')
        return str(formatted_time)


def _check_health():
    return True

operations = {
    'bad_ip': bad_ip,
    'bad_url': bad_url,
    'bad_filehash': bad_filehash,
    'bad_domain': bad_domain,
    'replace_variables': replace_variables,
    'malicious_file_indicator': malicious_file_indicator,
    'create_simulated_alert': create_simulated_alert
}
function_dictionary={
    "TR_MALICIOUS_IP": bad_ip,
    "TR_MALICIOUS_DOMAIN": bad_domain,
    "TR_MALICIOUS_URL": bad_url,
    "TR_MALICIOUS_HASH": bad_filehash,
    "TR_RANDOM_INTEGER": tr_get_random_integer,
    "TR_PUBLIC_IP": tr_get_my_public_ip,
    "TR_USERNAME": tr_get_username,
    "TR_ASSET_IP":tr_get_asset_ip,    
    "TR_FORMATTED_TIME": tr_get_formatted_time,
    "TR_TIMESTAMP": tr_get_timestamp
}