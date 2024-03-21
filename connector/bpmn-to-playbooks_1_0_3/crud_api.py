import re, json
from connectors.core.connector import get_logger, ConnectorError
from integrations.crudhub import make_request
from integrations.crudhub import maybe_json_or_raise
from urllib.parse import urlparse

import requests
from cshmac.requests import HmacAuth
from django.conf import settings

logger = get_logger('bpmntoplybookss')



def findRecords(config, params, *args, **kwargs):

    filters = []
    for item in params.get('matchValue'):
        a = {
                "field": params.get('searchField'),
                "operator": "eq",
                "value": item
            }

        filters.append(a)

    query = {"logic": "OR", "filters": filters}
    test = json.dumps(query)

    queryUrl = "/api/query/{}".format(params.get('module'))

    return make_cyops_request(queryUrl, "POST", query, *args, **kwargs)

def _crudhubAuth(path, method, payload):
    public_key = settings.APPLIANCE_PUBLIC_KEY
    private_key = settings.APPLIANCE_PRIVATE_KEY
    return HmacAuth(path, method, public_key, private_key, payload)


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
    auth = _crudhubAuth(url, method, json.dumps(body))

    response = requests.request(method, url, auth=auth, json=body, verify=False)

    return maybe_json_or_raise(response)
