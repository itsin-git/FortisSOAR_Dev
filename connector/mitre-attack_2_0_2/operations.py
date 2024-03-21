import requests
import arrow
import json
from stix2 import Filter, MemorySource

from connectors.core.connector import get_logger, ConnectorError
from .utils import query_source, generate_records, create_relationships, link_techniques_to_tactics
from .utils import remove_rev_dep_relationships, remove_rev_dep_list_only, filter_techniques
from .utils import get_mitre_version, create_mitre_version, update_mitre_version
from .utils import get_file_content

logger = get_logger('Mitre')


def get_mitre_data(config, params):
    response_enterprise = {'objects': []}
    response_mobile = {'objects': []}
    response_ics = {'objects': []}
    if config.get('upload_json'):
        if config.get('enterprise_json'):
            response_enterprise = get_file_content(config.get('enterprise_json'))
        if config.get('mobile_json'):
            response_mobile = get_file_content(config.get('mobile_json'))
        if config.get('ics_json'):
            response_ics = get_file_content(config.get('ics_json'))
    else:
        for matrix in config.get('matrices'):
            if matrix == 'Enterprise':
                response_enterprise = requests.get('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json').json()
            if matrix == 'Mobile':
                response_mobile = requests.get('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json').json()
            if matrix == 'ICS':
                response_ics = requests.get('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json').json()

    objects = response_enterprise['objects'] + response_mobile['objects'] + response_ics['objects']
    # missing bundle_id and spec_version does not affect our results
    # we just need to keep the dict structure for stix filters
    response = {'type': 'bundle', 'id': '', 'spec_version': '', 'objects': objects}

    mem_source = MemorySource(stix_data=response)

    collections_filter = [Filter('type', '=', 'x-mitre-collection')]
    # look back 4 months from today
    date_filter = [Filter('modified', '>=', '{}{}'.format(arrow.utcnow().shift(months=-4).format('YYYY-MM-DDTHH:mm:ss.SSS'), 'Z'))]
    tactics_filter = [Filter('type', '=', 'x-mitre-tactic')]
    groups_filter = [Filter('type', '=', 'intrusion-set')]
    techniques_all_filter = [Filter('type', '=', 'attack-pattern')]
    mitigations_filter = [Filter('type', '=', 'course-of-action')]
    malware_filter = [Filter('type', '=', 'malware')]
    tools_filter = [Filter('type', '=', 'tool')]
    relationships_filter = [Filter('type', '=', 'relationship')]

    mitre_collections = query_source(mem_source, collections_filter)
    mitre_version = mitre_collections[0]['x_mitre_version']
    # we don't need this anymore since health check handles if file upload exists
    # try:
    #     mitre_version = mitre_collections[0]['x_mitre_version']
    # except IndexError:
    #     raise ConnectorError('The connector did not ingest any data from MITRE. '
    #                          'Please make sure you have at least one file selected for ingestion')

    mitre_version_response = get_mitre_version()
    if len(mitre_version_response['hydra:member']) > 0:
        saved_mitre_version = mitre_version_response['hydra:member'][0]['value']
    else:
        saved_mitre_version = '0.0'

    if float(mitre_version) > float(saved_mitre_version) and not params.get('force_ingestion'):
        if saved_mitre_version == '0.0':
            # first ever run
            # will also go here if the mitre_version global variable is manually deleted by user
            create_mitre_version(mitre_version)
            tactics = query_source(mem_source, tactics_filter)
            groups = query_source(mem_source, groups_filter)
            techniques_all = query_source(mem_source, techniques_all_filter)
            mitigations = query_source(mem_source, mitigations_filter)
            software_malware = query_source(mem_source, malware_filter)
            software_tools = query_source(mem_source, tools_filter)
            relationships = query_source(mem_source, relationships_filter)
        else:
            # filter by new dates
            # when a record is first created, modified == created, so this should cover newly created records
            update_mitre_version(mitre_version_response['hydra:member'][0]['id'], mitre_version)
            tactics = query_source(mem_source, tactics_filter + date_filter)
            groups = query_source(mem_source, groups_filter + date_filter)
            techniques_all = query_source(mem_source, techniques_all_filter + date_filter)
            mitigations = query_source(mem_source, mitigations_filter + date_filter)
            software_malware = query_source(mem_source, malware_filter + date_filter)
            software_tools = query_source(mem_source, tools_filter + date_filter)
            relationships = query_source(mem_source, relationships_filter + date_filter)
    elif float(mitre_version) <= float(saved_mitre_version) and not params.get('force_ingestion'):
        # will go here if user manually changes the global variable to be larger than latest mitre version
        return 'Nothing new to add! ' \
               'Try rerunning the ingestion with force ingestion enabled if something is missing'
    else:
        # force ingest, disregard version
        tactics = query_source(mem_source, tactics_filter)
        groups = query_source(mem_source, groups_filter)
        techniques_all = query_source(mem_source, techniques_all_filter)
        mitigations = query_source(mem_source, mitigations_filter)
        software_malware = query_source(mem_source, malware_filter)
        software_tools = query_source(mem_source, tools_filter)
        relationships = query_source(mem_source, relationships_filter)

    techniques, sub_techniques = filter_techniques(techniques_all)

    tactics_ids = remove_rev_dep_list_only(tactics)
    groups_ids = remove_rev_dep_list_only(groups)
    techniques_ids = remove_rev_dep_list_only(techniques)
    sub_technique_ids = remove_rev_dep_list_only(sub_techniques)
    mitigations_ids = remove_rev_dep_list_only(mitigations)
    software_tools_ids = remove_rev_dep_list_only(software_tools)
    software_malware_ids = remove_rev_dep_list_only(software_malware)

    combined_list = tactics_ids + groups_ids + techniques_ids + sub_technique_ids + mitigations_ids + \
        software_malware_ids + software_tools_ids
    relationships = remove_rev_dep_relationships(relationships, combined_list)

    mapping = {
        'Tactics': (tactics, 'mitre_tactics'),
        'Groups': (groups, 'mitre_groups'),
        'Techniques': (techniques, 'mitre_techniques'),
        'Subtechniques': (sub_techniques, 'mitre_sub_techniques'),
        'Mitigations': (mitigations, 'mitre_mitigations'),
        'Software': ((software_malware, software_tools), 'mitre_software')
    }
    records_len = 0
    for module in params.get('modules'):
        if module != 'Software':
            records_len += generate_records(*mapping[module])
        else:
            records_len += generate_records(mapping[module][0][0], mapping[module][1])
            records_len += generate_records(mapping[module][0][1], mapping[module][1])

    relationships_len = 0
    error_flag = False
    for module in params.get('modules'):
        try:
            relationships_len += create_relationships(relationships, mapping[module][1])
        except Exception:
            logger.error('Could not add relationships to the {} module'.format(mapping[module][1]))
            error_flag = True

    try:
        tactics_techniques_len = link_techniques_to_tactics(techniques, tactics)
        relationships_len += tactics_techniques_len
    except Exception:
        logger.error('Could not link techniques to tactics. Make sure both modules are ingested.')
        error_flag = True

    if error_flag:
        return 'Partial success. Upserted {} records and {} relationships. There are missing relationships between ' \
               'modules and they cannot be added until all modules are ingested first'.format(records_len,
                                                                                              relationships_len)
    else:
        return 'Success! Upserted {} records and {} relationships'.format(records_len, relationships_len)


def get_mitre_data_sample(config, params):
    example_technique = '''{
            "id": "attack-pattern--9e80ddfb-ce32-4961-a778-ca6a10cfae72",
            "name": "Sudo",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1169",
                    "url": "https://attack.mitre.org/techniques/T1169"
                },
                {
                    "url": "https://blog.malwarebytes.com/threat-analysis/2017/04/new-osx-dok-malware-intercepts-web-traffic/",
                    "description": "Thomas Reed. (2017, July 7). New OSX.Dok malware intercepts web traffic. Retrieved July 10, 2017.",
                    "source_name": "OSX.Dok Malware"
                }
            ],
            "revoked": true,
            "type": "attack-pattern",
            "modified": "2020-02-05T20:11:12.593Z",
            "created": "2017-12-14T16:46:06.044Z",
            "spec_version": "2.1",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_version": "1.0"
        }'''
    example_group = '''{
            "created": "2018-01-16T16:13:52.465Z",
            "modified": "2021-04-25T22:34:23.617Z",
            "aliases": [
                "Magic Hound",
                "COBALT ILLUSION",
                "Charming Kitten",
                "ITG18",
                "Phosphorus",
                "Newscaster",
                "APT35"
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/groups/G0059",
                    "external_id": "G0059"
                },
                {
                    "source_name": "Magic Hound",
                    "description": "(Citation: Unit 42 Magic Hound Feb 2017)"
                },
                {
                    "source_name": "COBALT ILLUSION",
                    "description": "(Citation: Secureworks COBALT ILLUSION Threat Profile)"
                },
                {
                    "source_name": "Charming Kitten",
                    "description": "(Citation: ClearSky Charming Kitten Dec 2017)(Citation: Eweek Newscaster and Charming Kitten May 2014)(Citation: ClearSky Kittens Back 2 Oct 2019)(Citation: ClearSky Kittens Back 3 August 2020)"
                },
                {
                    "source_name": "ITG18",
                    "description": "(Citation: IBM ITG18 2020)"
                },
                {
                    "source_name": "Phosphorus",
                    "description": "(Citation: Microsoft Phosphorus Mar 2019)(Citation: Microsoft Phosphorus Oct 2020)(Citation: US District Court of DC Phosphorus Complaint 2019)"
                },
                {
                    "source_name": "Newscaster",
                    "description": "Link analysis of infrastructure and tools revealed a potential relationship between Magic Hound and the older attack campaign called Newscaster (aka Newscasters).(Citation: Unit 42 Magic Hound Feb 2017)(Citation: FireEye APT35 2018)"
                },
                {
                    "source_name": "APT35",
                    "description": "(Citation: FireEye APT35 2018)"
                },
                {
                    "source_name": "FireEye APT35 2018",
                    "description": "Mandiant. (2018). Mandiant M-Trends 2018. Retrieved July 9, 2018.",
                    "url": "https://www.fireeye.com/content/dam/collateral/en/mtrends-2018.pdf"
                },
                {
                    "source_name": "Unit 42 Magic Hound Feb 2017",
                    "description": "Lee, B. and Falcone, R. (2017, February 15). Magic Hound Campaign Attacks Saudi Targets. Retrieved December 27, 2017.",
                    "url": "https://researchcenter.paloaltonetworks.com/2017/02/unit42-magic-hound-campaign-attacks-saudi-targets/"
                },
                {
                    "source_name": "Secureworks COBALT ILLUSION Threat Profile",
                    "url": "https://www.secureworks.com/research/threat-profiles/cobalt-illusion",
                    "description": "Secureworks. (n.d.). COBALT ILLUSION Threat Profile. Retrieved April 14, 2021."
                },
                {
                    "source_name": "ClearSky Charming Kitten Dec 2017",
                    "description": "ClearSky Cyber Security. (2017, December). Charming Kitten. Retrieved December 27, 2017.",
                    "url": "http://www.clearskysec.com/wp-content/uploads/2017/12/Charming_Kitten_2017.pdf"
                },
                {
                    "source_name": "Eweek Newscaster and Charming Kitten May 2014",
                    "url": "https://www.eweek.com/security/newscaster-threat-uses-social-media-for-intelligence-gathering",
                    "description": "Kerner, S. (2014, May 29). Newscaster Threat Uses Social Media for Intelligence Gathering. Retrieved April 14, 2021."
                },
                {
                    "source_name": "ClearSky Kittens Back 2 Oct 2019",
                    "url": "https://www.clearskysec.com/wp-content/uploads/2019/10/The-Kittens-Are-Back-in-Town-2-1.pdf",
                    "description": "ClearSky Research Team. (2019, October 1). The Kittens Are Back in Town2 - Charming Kitten Campaign KeepsGoing on, Using New Impersonation Methods. Retrieved April 21, 2021."
                },
                {
                    "source_name": "ClearSky Kittens Back 3 August 2020",
                    "url": "https://www.clearskysec.com/wp-content/uploads/2020/08/The-Kittens-are-Back-in-Town-3.pdf",
                    "description": "ClearSky Research Team. (2020, August 1). The Kittens Are Back in Town 3 - Charming Kitten Campaign Evolved and Deploying Spear-Phishing link by WhatsApp. Retrieved April 21, 2021."
                },
                {
                    "source_name": "IBM ITG18 2020",
                    "url": "https://securityintelligence.com/posts/new-research-exposes-iranian-threat-group-operations/",
                    "description": "Wikoff, A. Emerson, R. (2020, July 16). New Research Exposes Iranian Threat Group Operations. Retrieved March 8, 2021."
                },
                {
                    "source_name": "Microsoft Phosphorus Mar 2019",
                    "url": "https://blogs.microsoft.com/on-the-issues/2019/03/27/new-steps-to-protect-customers-from-hacking/",
                    "description": "Burt, T.. (2019, March 27). New steps to protect customers from hacking. Retrieved May 27, 2020."
                },
                {
                    "source_name": "Microsoft Phosphorus Oct 2020",
                    "url": "https://blogs.microsoft.com/on-the-issues/2020/10/28/cyberattacks-phosphorus-t20-munich-security-conference/",
                    "description": "Burt, T. (2020, October 28). Cyberattacks target international conference attendees. Retrieved March 8, 2021."
                },
                {
                    "source_name": "US District Court of DC Phosphorus Complaint 2019",
                    "url": "https://noticeofpleadings.com/phosphorus/files/Complaint.pdf",
                    "description": "US District Court of DC. (2019, March 14). MICROSOFT CORPORATION v. JOHN DOES 1-2, CONTROLLING A COMPUTER NETWORK AND THEREBY INJURING PLAINTIFF AND ITS CUSTOMERS. Retrieved March 8, 2021."
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "description": "[Magic Hound](https://attack.mitre.org/groups/G0059) is an Iranian-sponsored threat group that conducts long term, resource-intensive cyber espionage operations, dating back as early as 2014. The group typically targets U.S. and Middle Eastern military organizations, as well as other government personnel, via complex social engineering campaigns.(Citation: FireEye APT35 2018)",
            "name": "Magic Hound",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "id": "intrusion-set--f9d6633a-55e6-4adc-9263-6ae080421a13",
            "type": "intrusion-set",
            "x_mitre_version": "3.0",
            "x_mitre_contributors": [
                "Anastasios Pingios",
                "Bryan Lee"
            ],
            "spec_version": "2.1",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
        }'''

    example_tactic = '''{
            "id": "x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "name": "Collection",
            "description": "The adversary is trying to gather data of interest to their goal. Collection consists of techniques adversaries may use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the data. Common target sources include various drive types, browsers, audio, video, and email. Common collection methods include capturing screenshots and keyboard input.",
            "external_references": [
                {
                    "external_id": "TA0009",
                    "url": "https://attack.mitre.org/tactics/TA0009",
                    "source_name": "mitre-attack"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_shortname": "collection",
            "type": "x-mitre-tactic",
            "modified": "2019-07-19T17:44:53.176Z",
            "created": "2018-10-17T00:14:20.652Z",
            "spec_version": "2.1",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_version": "1.0"
        }'''

    example_software = '''{
            "id": "tool--ff6caf67-ea1f-4895-b80e-4bb0fc31c6db",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "name": "PsExec",
            "description": "[PsExec](https://attack.mitre.org/software/S0029) is a free Microsoft tool that can be used to execute a program on another computer. It is used by IT administrators and attackers. (Citation: Russinovich Sysinternals) (Citation: SANS PsExec)",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/software/S0029",
                    "external_id": "S0029"
                },
                {
                    "url": "https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx",
                    "description": "Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.",
                    "source_name": "Russinovich Sysinternals"
                },
                {
                    "url": "https://digital-forensics.sans.org/blog/2012/12/17/protecting-privileged-domain-accounts-psexec-deep-dive",
                    "description": "Pilkington, M.. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.",
                    "source_name": "SANS PsExec"
                }
            ],
            "type": "tool",
            "modified": "2020-03-20T19:20:27.565Z",
            "created": "2017-05-31T21:32:21.771Z",
            "x_mitre_platforms": [
                "Windows"
            ],
            "x_mitre_aliases": [
                "PsExec"
            ],
            "x_mitre_version": "1.1",
            "spec_version": "2.1",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
        }'''

    return [json.loads(example_tactic),
            json.loads(example_group),
            json.loads(example_technique),
            json.loads(example_software)]


operations = {
    'get_mitre_data': get_mitre_data,
    'get_mitre_data_sample': get_mitre_data_sample
}
