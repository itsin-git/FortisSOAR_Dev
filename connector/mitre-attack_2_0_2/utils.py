from datetime import datetime

from connectors.core.connector import get_logger, ConnectorError
from integrations.crudhub import make_request

logger = get_logger('Mitre')


def remove_rev_dep(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get('x_mitre_deprecated', False) is False and x.get('revoked', False) is False,
            stix_objects
        )
    )


def remove_rev_dep_relationships(relationships, mitre_ids):
    # Turns out the relationships dataset does not have a concept of revoked/deprecated.
    # We needed to improvise
    return list(
        filter(
            lambda x: x['source_ref'] in mitre_ids and x['target_ref'] in mitre_ids,
            relationships
        )
    )


def remove_rev_dep_list_only(stix_objects):
    ids = []
    for item in stix_objects:
        ids.append(item['id'])
    return ids


def query_source(memory_source, query_filter):
    result = memory_source.query(query_filter)
    result = remove_rev_dep(result)
    return result


def filter_techniques(techniques_all):
    # Sometimes techniques do not have the 'x_mitre_is_subtechnique' key that determines if they are subtechniques or not
    # These are actually still techniques but get dropped by our filters.
    # This function finds such techniques adds them back into our result
    techniques = []
    sub_techniques = []

    for technique in techniques_all:
        if 'x_mitre_is_subtechnique' not in technique:
            techniques.append(technique)
        else:
            if technique['x_mitre_is_subtechnique']:
                sub_techniques.append(technique)
            else:
                techniques.append(technique)

    return techniques, sub_techniques


def parse_datetime(value):
    if isinstance(value, str):
        value = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
    return value.timestamp()


def generate_records(collection, module_name):
    body_dict = {'data': []}

    for item in collection:
        item_dict = dict()
        # this seems to force bulkupsert to update only
        # item_dict['@id'] = '/api/3/{}/{}'.format(module_name, item['id'])
        item_dict['uuid'] = item['id'].split('--')[1]
        item_dict['name'] = item['name']
        # item_dict['description'] = '<p style="text-align: justify;">{}</p>'.format(item['description'])
        item_dict['description'] = item['description']
        item_dict['mitreId'] = item['external_references'][0]['external_id']
        item_dict['url'] = item['external_references'][0]['url']
        item_dict['version'] = item['x_mitre_version']
        item_dict['created'] = parse_datetime(item['created'])
        item_dict['lastModified'] = parse_datetime(item['modified'])

        if 'x_mitre_contributors' in item:
            item_dict['contributors'] = ', '.join(item['x_mitre_contributors'])
        if 'x_mitre_domains' in item:
            item_dict['domains'] = ', '.join(item['x_mitre_domains'])
        if 'aliases' in item:
            item_dict['aliases'] = ', '.join(item['aliases'])
        if 'x_mitre_platforms' in item:
            item_dict['platforms'] = ', '.join(item['x_mitre_platforms'])
        if 'x_mitre_data_sources' in item:
            item_dict['dataSources'] = ', '.join(item['x_mitre_data_sources'])
        if 'x_mitre_permissions_required' in item:
            item_dict['permissionsRequired'] = ', '.join(item['x_mitre_permissions_required'])
        if 'x_mitre_detection' in item:
            item_dict['detection'] = item['x_mitre_detection']
        if module_name == 'software':
            if 'malware' in item['id']:
                item_dict['type'] = '/api/3/picklists/525fae90-2293-497d-b4f6-c767796fe765'
            if 'tool' in item['id']:
                item_dict['type'] = '/api/3/picklists/7e9e1724-b852-4050-8774-3eed165123ed'

        body_dict['data'].append(item_dict)
        body_dict['__unique'] = ['uuid']

    make_request('/api/3/bulkupsert/{}'.format(module_name), 'POST', body=body_dict)

    return len(body_dict['data'])


def create_relationships(relationships, module_name):
    body_dict = {'data': []}
    source_ref_list = []
    relationship_dict = {}

    filter_dict = {
        'logic': 'AND',
        'filters': [],
        '__selectFields': [
            'uuid'
        ]
    }

    response = make_request('/api/query/{}?$limit=1000'.format(module_name), 'POST', body=filter_dict)

    for record in response['hydra:member']:
        source_ref_list.append(record['uuid'])
    count = 0
    for item in source_ref_list:
        relationship_dict[item] = []
        for relationship in relationships:
            if item == relationship['target_ref'].split('--')[1]:
                relationship_dict[item].append(relationship['source_ref'])

        count += len(relationship_dict[item])
    for key, value in relationship_dict.items():
        append_dict = {'uuid': key}
        tactics = []
        groups = []
        techniques = []
        mitigations = []
        software = []
        for relationship in value:
            if 'x-mitre-tactic' in relationship:
                tactics.append(relationship.split('--')[1])
            if 'intrusion-set' in relationship:
                groups.append(relationship.split('--')[1])
            if 'attack-pattern' in relationship:
                techniques.append(relationship.split('--')[1])
            if 'course-of-action' in relationship:
                mitigations.append(relationship.split('--')[1])
            if 'malware' in relationship or 'tool' in relationship:
                software.append(relationship.split('--')[1])
        if tactics:
            append_dict['tactics'] = tactics
        if groups:
            append_dict['groups'] = groups
        if techniques:
            append_dict['techniques'] = techniques
        if mitigations:
            append_dict['mitigations'] = mitigations
        if software:
            append_dict['software'] = software
        # does the uuid have anything available to link?
        # we don't want to pass them into the body if there's nothing to update
        if len(append_dict.keys()) > 1:
            body_dict['data'].append(append_dict)

    make_request('/api/3/update/{}'.format(module_name), 'PUT', body=body_dict)

    return count


def link_techniques_to_tactics(techniques, tactics):
    # we're doing this separately because tactics/techniques relationships are not listed in the relationships dataset
    body_dict = {'data': []}
    count = 0

    for tactic in tactics:
        relationship_dict = {'uuid': tactic['id'].split('--')[1], 'techniques': []}
        for technique in techniques:
            for kill_chain_phase in technique['kill_chain_phases']:
                if kill_chain_phase['phase_name'] == tactic['x_mitre_shortname']:
                    relationship_dict['techniques'].append(technique['id'].split('--')[1])
        count += len(relationship_dict['techniques'])
        # every tactic has at least one technique related so we currently don't need to check for emptiness
        body_dict['data'].append(relationship_dict)

    make_request('/api/3/update/mitre_tactics', 'PUT', body=body_dict)

    return count


def get_mitre_version():
    return make_request('/api/wf/api/dynamic-variable/?name=mitre_version', 'GET')


def create_mitre_version(version):
    return make_request('/api/wf/api/dynamic-variable/', 'POST', body={'name': 'mitre_version', 'value': version})


def update_mitre_version(variable_id, version):
    return make_request('/api/wf/api/dynamic-variable/{}/'.format(variable_id), 'PUT',
                        body={'name': 'mitre_version', 'value': version})


def get_mitre_modules(config):
    module_names = [
        'mitre_tactics',
        'mitre_groups',
        'mitre_techniques',
        'mitre_sub_techniques',
        'mitre_mitigations',
        'mitre_software'
    ]

    modules_not_exist = []

    for module in module_names:
        try:
            make_request('/api/3/{}'.format(module), 'GET')
        except Exception:
            modules_not_exist.append(module)

    if len(modules_not_exist) > 0:
        raise ConnectorError('The following modules are missing from the environment: '
                             '{}'.format(', '.join(modules_not_exist)))
    else:
        if config.get('upload_json'):
            if not config.get('enterprise_json') and not config.get('mobile_json') and not config.get('ics_json'):
                raise ConnectorError('It looks like you saved the connector configuration without uploading a file. '
                                     'Please upload at least one file and try again')
        return True


def get_file_content(file_field):
    return make_request(file_field['@id'], 'GET')
