import ast
import json
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.core.handlers.wsgi import WSGIRequest
from django.http import QueryDict
from django.urls import resolve
from connectors.core.connector import get_logger, SDK_VERSION
from integrations.crudhub import make_request
from .errors.error_constants import *
from .utils import maybe_json_or_raise, cyops_version
from .requests_auth import get_requests_auth

logger = get_logger("cyops_utilities.builtins.cyops_utilities-api")


def make_cyops_request(iri, method, body=None, *args, **kwargs):
    """
    This function facilitates using the crud hub api.

    It is for general purpose requests, but takes care of authentication
    automatically.

   :param str iri: An IRI that points to the location of the \
       crud hub collection (E.g. /api/3/events)
   :param str method: HTTP method
   :param dict body: An object to json encode and send to crud hub

   :return: the API response either as a json-like dict if possible or as bytes
   :rtype: dict/bytes
    """
    # account for relative iri
    if iri.startswith('/api/integration/') and kwargs.get('request'):
        local_iri = iri[4:]
        parsed_uri = urlparse(local_iri)
        path = parsed_uri.path
        view, args, resKwargs = resolve(path)
        local_request: WSGIRequest = kwargs.get('request')._request
        local_request.method = method
        local_request.path = path
        local_request._body = json.dumps(body).encode()
        # setting query params in the request object
        # making deep copy of GET object as this is immutable
        request_dict_copy: QueryDict = local_request.GET.copy()
        request_dict_copy.update(QueryDict(parsed_uri.query))
        local_request.GET = request_dict_copy
        resKwargs['request'] = local_request
        try:
            res = view(*args, **resKwargs)
            data = res.data
            return data
        except Exception as e:
            logger.warning('EError resolving view for the integration url. Making API call instead..')

    if int(cyops_version.replace('.', '')) < 641:
        return _make_cyops_request(iri, method, body=body, *args, **kwargs)

    return make_request(iri, method, body=body, *args, **kwargs)


def _make_cyops_request(iri, method, body=None, *args, **kwargs):
    """
    This function facilitates using the crud hub api for fortiSOAR version < 6.4.1.
    It is for general purpose requests, but takes care of authentication
    automatically.
    """
    # account for relative iri
    if not bool(urlparse(iri).netloc):
        url = settings.CRUD_HUB_URL + str(iri)
    else:
        url = iri

    # ctrl c/v
    # get rid of the body on GET/HEAD requests
    bodyless_methods = ['head', 'get']
    if method.lower() in bodyless_methods:
        body = None

    if type(body) == str:
        try:
            body = ast.literal_eval(body)
        except Exception:
            pass

    logger.info('Starting request: %s , %s', method, url)
    env = kwargs.get('env', {})

    # for default if no env HMAC method
    if not env or not env.get('auth_info', False):
        env['auth_info'] = {"auth_method": "CS HMAC"}

    # for public and private key in env
    if env.get('public_key', False) and env.get('private_key', False):
        env['auth_info'] = {"auth_method": "CS HMAC"}
        public_key = env.get('public_key')
        private_key = env.get('private_key')
    else:
        public_key = settings.APPLIANCE_PUBLIC_KEY
        private_key = settings.APPLIANCE_PRIVATE_KEY
    auth_info = env.get('auth_info')
    auth = get_requests_auth(auth_info, url, method,
                             public_key,
                             private_key,
                             json.dumps(body), *args, **kwargs)
    response = requests.request(method, url, auth=auth, json=body, verify=False)
    if not kwargs.get('validate_response', True):
        return response
    return maybe_json_or_raise(response)


def query_cyops_resource(resource, query, *args, **kwargs):
    """
    Performs a CrudHub search using the query api.

   :param str resource: A model to use as an IRI (e.g. events)
   :param dict query: A query object to send to the query api
   :return: search results
   :rtype: list
    """
    collection = '/api/query/{resource}'.format(resource=resource)
    result = make_cyops_request(collection, 'POST', query, *args, **kwargs)
    return result.get('hydra:member', [])


def update_cyops_records(data, iri, records, *args, **kwargs):
    """
    Trys to update the value of results.

   :param dict data: An object to json encode and send to crud hub
   :param str iri: An IRI that points to the location of the crud hub \
       collection (E.g. /api/3/events)
    :param arr records: Array of records to update (@id fields of the crud-hub records)
   :return: number of updated records
   :rtype: dict
    """
    if type(records) != list:
        records = [records]

    update_count = 0
    for record in records:
        if '@id' in record:
            iri = record['@id']
        try:
            result = make_cyops_request(iri, 'PUT', data, *args, **kwargs)
            if result:
                update_count += 1
        except Exception as e:
            logger.error(str(e))
    return {'updated': update_count}


def update_cyops_resource(iri, body, *args, **kwargs):
    """
    A task for updating crud hub data. Uses the PUT method.

   :param str iri: An IRI that points to the location of the crud hub \
       collection (E.g. /api/3/events)
   :param dict body: An object to json encode and send to crud hub

   :return: the API response either as a json-like dict if possible or as bytes
   :rtype: dict or bytes
    """
    logger.info('inserting new data into crud hub. Uses the PUT method.')
    resource_obj = make_cyops_request(iri, 'put', body, *args, **kwargs)
    return resource_obj


def insert_cyops_resource(iri, body, *args, **kwargs):
    """
    A task for inserting new data into crud hub. Uses the POST method.

   :param str iri: An IRI that points to the location of the crud hub \
       collection (E.g. /api/3/events)
   :param dict body: An object to json encode and send to crud hub

   :return: the API response either as a json-like dict if possible or as bytes
   :rtype: dict or bytes
    """
    logger.info('inserting new data into crud hub. Uses the POST method.')
    resource_obj = make_cyops_request(iri, 'post', body, *args, **kwargs)
    return resource_obj


def _fields_in_resource(fields, resource):
    unmatched_fields = []
    for field in fields:
        if field not in resource:
            unmatched_fields.append(field)
    return unmatched_fields


def _fields_in_schema(fields, module, *args, **kwargs):
    unmatched_fields = []
    env = kwargs.get('env', {})
    auth_info = env.get('auth_info')

    schema_collection = '/api/3/model_metadatas' \
                        '?type={collection}&$relationships=true' \
        .format(collection=module)
    logger.info("schema_collection %s" % schema_collection)
    module_schema = make_cyops_request(schema_collection, 'GET', *args, **kwargs).get('hydra:member', [])
    if module_schema:
        # logger.info("module_schema %s" %module_schema)
        attributes = module_schema[0]['attributes']
        # logger.info("attributes %s" % attributes)
        for attribute in attributes:
            logger.info("attribute name: %s" % attribute['name'])
        schema_fields = [attribute['name'] for attribute in attributes if
                         'name' in attribute]
        for field in fields:
            if field not in schema_fields and not field == '@id':
                unmatched_fields.append(field)
        return unmatched_fields
    else:
        raise IndexError(cs_connector_utility_16.format(
            module=module))


def upsert_cyops_resource(iri, resource, fields,
                          ignore_missing_fields=False, *args, **kwargs):
    """
    A task for upserting crud hub data.
     Uses the insert_data/updata_data methods

   :param str iri: An IRI that points to the location of the crud hub \
       collection (E.g. /api/3/events)
   :param dict resource: An object to json encode and send to crud hub
   :param list fields: a list of fields to check for uniqueness. \
        Default to ['@id']
   :param bool ignore_missing_fields: a boolean flag that indicates \
        whether or not to raise an error if user specifies a field \
        in fields that is not in the record. \
        Default False - i.e. raise an exception.

   :return: the API response either as a json-like dict if possible or as bytes
   :rtype: dict or bytes
    """
    if not iri:
        raise ValueError(cs_connector_utility_1.format('iri'))
    if not resource:
        raise ValueError(cs_connector_utility_1.format('resource'))

    matched_records = []
    if fields:
        # extract the module from iri.
        module = iri.split('/')[-1]
        if not module:
            # if there is a trailing slash
            module = iri.split('/')[-2]
        logger.info("module %s" % module)

        # Match the fields with schema and resources.
        if ignore_missing_fields:
            pass
        else:
            # Check for fields in resource object.
            unmatched_fields = _fields_in_resource(fields, resource)
            if unmatched_fields:
                raise ValueError(cs_connector_utility_13.format(
                    unmatched_fields))
            # Check for fields in model metadata schema for provided module.
            unmatched_fields = _fields_in_schema(fields, module,
                                                 *args, **kwargs)
            if unmatched_fields:
                raise ValueError(cs_connector_utility_14.format(
                    unmatched_fields, module))

        # formulate query object for fetching the data.
        filters = []
        for field in fields:
            if field in resource:
                filters \
                    .append({'field': field,
                             'operator': 'eq', 'value': resource[field]})
        logger.info("filters %s" % filters)
        matched_records = query_cyops_resource(
            module, {'logic': 'AND', 'filters': filters},
            *args, **kwargs)
    if not matched_records:
        return insert_cyops_resource(iri, resource, *args, **kwargs)
    elif len(matched_records) == 1:
        resource['@id'] = matched_records[0].get('@id')
        return update_cyops_resource(resource['@id'], resource, *args, **kwargs)
    else:
        raise ValueError(cs_connector_utility_15)


def attach_indicators(iri, indicators, source=None, related_field='indicators', *args, **kwargs):
    if not related_field:
        related_field = 'indicators'

    if len(indicators.keys()) == 0:
        return

    result = make_cyops_request('%s?$relationships=true' % iri, 'GET', None, *args, **kwargs)
    indicators_to_attach = [x['@id'] for x in result.get(related_field, [])]

    for indicator_type in indicators.keys():
        for indicator in indicators[indicator_type]:
            records = make_cyops_request('/api/3/indicators?value=%s' % indicator, 'GET', None, *args, **kwargs)
            records = records.get('hydra:member', [])
            if len(records) == 0:
                indicator_type_value = None
                picklists = make_cyops_request('/api/3/picklist_names?$relationships=true', 'get', None, *args,
                                               **kwargs).get(
                    'hydra:member', [])
                for picklist in picklists:
                    if 'IndicatorType' == picklist['name']:
                        for item in picklist['picklists']:
                            if indicator_type in item['itemValue']:
                                indicator_type_value = item
                if indicator_type_value:
                    data = make_cyops_request('/api/3/indicators', 'post',
                                              {'typeofindicator': indicator_type_value, 'value': indicator, 'sources': source},
                                              *args, **kwargs)
                    indicators_to_attach.append(data['@id'])
            else:
                data = records[0]
                indicators_to_attach.append(data['@id'])
    make_cyops_request(iri, 'put', {related_field: indicators_to_attach}, *args, **kwargs)
    return indicators_to_attach


attach_indicators.__str__ = lambda: 'Attach Indicators'


def setmacro(macro, value, *args, **kwargs):
    # check if macro already exist then update it else create it.
    response = _getmacro(macro)
    if response:
        return updatemacro(response[0].get('id'), macro, value)
    else:
        return createmacro(macro, value)


def get_macro_list(*args, **kwargs):
    args = {
        'iri': '/api/wf/api/dynamic-variable/?offset=0&limit=1000&format=json',
        'method': 'GET',
        'body': None
    }
    response = make_cyops_request(**args)["hydra:member"]
    return [obj.get('name') for obj in response]


def getmacro(macro, *args, **kwargs):
    response = _getmacro(macro)
    if response:
        return response[0].get('value')


def _getmacro(macro, *args, **kwargs):
    args = {
        'iri': '/api/wf/api/dynamic-variable/?name=%s&format=json' % macro,
        'method': 'GET',
        'body': None
    }
    return make_cyops_request(**args)["hydra:member"]


def updatemacro(macroid, macro, value, *args, **kwargs):
    args = {
        'iri': '/api/wf/api/dynamic-variable/%s/?format=json' % macroid,
        'method': 'PUT',
        'body': {'id': macroid, 'name': macro, 'value': value}
    }
    return make_cyops_request(**args)


def createmacro(macro, value):
    args = {
        'iri': '/api/wf/api/dynamic-variable/?format=json',
        'method': 'POST',
        'body': {"name": macro, "value": value}
    }
    return make_cyops_request(**args)
