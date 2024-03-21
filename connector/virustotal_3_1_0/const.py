""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

MACRO_LIST = ["IP_Enrichment_Playbooks_IRIs", "URL_Enrichment_Playbooks_IRIs", "Domain_Enrichment_Playbooks_IRIs",
              "FileHash_Enrichment_Playbooks_IRIs", "File_Enrichment_Playbooks_IRIs"]
CONNECTOR_NAME = 'virustotal'
TEMPLATE = {
    "meta": {
        "cursor": ""
    },
    "data": [
        {
            "type": "",
            "id": ""
        }
    ],
    "links": {
        "self": "",
        "related": "",
        "next": ""
    }
}

IP_TEMPLATE = {
    "attributes": {
        "regional_internet_registry": "",
        "jarm": "",
        "network": "",
        "last_https_certificate_date": "",
        "tags": [],
        "country": "",
        "as_owner": "",
        "last_analysis_stats": {
            "harmless": "",
            "malicious": "",
            "suspicious": "",
            "undetected": "",
            "timeout": ""
        },
        "asn": "",
        "whois_date": "",
        "last_analysis_results": {},
        "reputation": "",
        "last_modification_date": "",
        "total_votes": {
            "harmless": "",
            "malicious": ""
        },
        "last_https_certificate": {},
        "continent": "",
        "whois": {
            "raw": [],
            "data": ""
        }
    },
    "type": "",
    "id": "",
    "links": {
        "self": ""
    }
}

DOMAIN_TEMPLATE = {
    "attributes": {
        "last_dns_records": [],
        "jarm": "",
        "whois": {
            "raw": [],
            "data": ""
        },
        "last_https_certificate_date": "",
        "tags": [],
        "popularity_ranks": {},
        "last_dns_records_date": "",
        "last_analysis_stats": {
            "harmless": "",
            "malicious": "",
            "suspicious": "",
            "undetected": "",
            "timeout": ""
        },
        "whois_date": "",
        "reputation": "",
        "last_analysis_results": {},
        "last_modification_date": "",
        "last_https_certificate": {
            "public_key": {
                "rsa": {
                    "key_size": "",
                    "modulus": "",
                    "exponent": ""
                },
                "algorithm": ""
            },
            "thumbprint_sha256": "",
            "tags": [],
            "signature_algorithm": "",
            "subject": {
                "CN": ""
            },
            "validity": {
                "not_after": "",
                "not_before": ""
            },
            "version": "",
            "extensions": {
                "certificate_policies": [],
                "extended_key_usage": [],
                "tags": [],
                "subject_alternative_name": [],
                "authority_key_identifier": {
                    "keyid": ""
                },
                "ca_information_access": {
                    "CA Issuers": "",
                    "OCSP": ""
                },
                "subject_key_identifier": "",
                "key_usage": [],
                "1.3.6.1.4.1.11129.2.4.2": "",
                "CA": ""
            },
            "cert_signature": {
                "signature_algorithm": "",
                "signature": ""
            },
            "serial_number": "",
            "thumbprint": "",
            "issuer": {
                "C": "",
                "CN": "",
                "O": ""
            },
            "size": ""
        },
        "categories": {},
        "total_votes": {
            "harmless": "",
            "malicious": ""
        }
    },
    "type": "",
    "id": "",
    "links": {
        "self": ""
    }
}

URL_TEMPLATE = {
    "attributes": {
        "last_modification_date": "",
        "times_submitted": "",
        "total_votes": {
            "harmless": "",
            "malicious": ""
        },
        "threat_names": [],
        "redirection_chain": [],
        "last_submission_date": "",
        "last_http_response_content_length": "",
        "last_http_response_headers": {},
        "reputation": "",
        "tags": [],
        "last_analysis_date": "",
        "first_submission_date": "",
        "categories": {},
        "last_http_response_content_sha256": "",
        "last_http_response_code": "",
        "last_final_url": "",
        "trackers": {},
        "url": "",
        "title": "",
        "last_analysis_stats": {
            "harmless": "",
            "malicious": "",
            "suspicious": "",
            "undetected": "",
            "timeout": ""
        },
        "last_analysis_results": {},
        "html_meta": {
            "description": [],
            "viewport": []
        },
        "outgoing_links": []
    },
    "type": "",
    "id": "",
    "links": {
        "self": ""
    }
}

FILE_TEMPLATE = {
    "attributes": {
        "type_description": "",
        "bytehero_info": "",
        "vhash": "",
        "trid": [],
        "creation_date": "",
        "names": [],
        "last_modification_date": "",
        "type_tag": "",
        "times_submitted": "",
        "total_votes": {
            "harmless": "",
            "malicious": ""
        },
        "size": "",
        "popular_threat_classification": {
            "suggested_threat_label": "",
            "popular_threat_category": [],
            "popular_threat_name": []
        },
        "authentihash": "",
        "last_submission_date": "",
        "reputation": "",
        "sha256": "",
        "type_extension": "",
        "tags": [],
        "last_analysis_date": "",
        "unique_sources": "",
        "first_submission_date": "",
        "sha1": "",
        "ssdeep": "",
        "md5": "",
        "pe_info": {
            "timestamp": "",
            "overlay": {
                "entropy": "",
                "offset": "",
                "chi2": "",
                "filetype": "",
                "size": "",
                "md5": ""
            },
            "entry_point": "",
            "machine_type": "",
            "imphash": "",
            "sections": [
                {
                    "name": "",
                    "chi2": "",
                    "virtual_address": "",
                    "entropy": "",
                    "raw_size": "",
                    "flags": "",
                    "virtual_size": "",
                    "md5": ""
                }
            ],
            "import_list": []
        },
        "magic": "",
        "last_analysis_stats": {
            "harmless": "",
            "type-unsupported": "",
            "suspicious": "",
            "confirmed-timeout": "",
            "timeout": "",
            "failure": "",
            "malicious": "",
            "undetected": ""
        },
        "last_analysis_results": {}
    },
    "type": "",
    "id": "",
    "links": {
        "self": ""
    }
}
