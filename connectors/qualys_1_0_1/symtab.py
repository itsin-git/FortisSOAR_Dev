param_details_symtab = {
    "launch_remediation_report": [
        {
            "type": "text",
            "name": "template_id"
        },
        {
            "type": "text",
            "name": "report_title"
        },
        {
            "type": "select",
            "name": "output_format",
            "option": {
                "MHT": "mht",
                "CSV": "csv",
                "HTML": "html",
                "PDF": "pdf"
            },
            "onchange": {
                "CSV": [
                    {
                        "type": "checkbox",
                        "name": "hide_header",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    }
                ],
                "PDF": [
                    {
                        "type": "password",
                        "name": "pdf_password"
                    },
                    {
                        "type": "integer",
                        "name": "recipient_group_id"
                    },
                    {
                        "type": "text",
                        "name": "recipient_group"
                    }
                ],
                "MHT": [],
                "HTML": []
            }
        },
        {
            "type": "select",
            "name": "assignee_type",
            "option": {
                "All": "All",
                "User": "User"
            }
        },
        {
            "type": "select",
            "name": "use_tags",
            "option": {
                True: 1,
                False: 0
            },
            "onchange": {
                True: [
                    {
                        "type": "select",
                        "name": "tag_include_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_exclude_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_set_by",
                        "option": {
                            "ID": "id",
                            "Name": "name"
                        }
                    },
                    {
                        "type": "text",
                        "name": "tag_set_include"
                    },
                    {
                        "type": "text",
                        "name": "tag_set_exclude"
                    }
                ],
                False: [
                    {
                        "type": "text",
                        "name": "ips"
                    },
                    {
                        "type": "text",
                        "name": "asset_group_ids"
                    },
                ]
            }
        },

    ],
    "list_schedule_scan": [
        {
            "type": "text",
            "name": "id"
        },
        {
            "type": "select",
            "name": "active",
            "option": {
                "Show All Schedules": -9,
                "Show Deactivated Schedules": 0,
                "Show Active Schedules": 1
            }
        }
    ],
    "fetch_vm_scan": [
        {
            "type": "text",
            "name": "scan_ref"
        },
        {
            "type": "text",
            "name": "ips"
        },
        {
            "type": "select",
            "name": "mode",
            "option": {
                "Extended": "extended",
                "Brief": "brief"
            }
        }
    ],
    "launch_score_card": [
        {
            "type": "select",
            "name": "sc_type",
            "option": {
                "User Created Scorecard": "User Created Scorecard",
                "Service Provided Scorecard": "Service Provided Scorecard"
            },
            "onchange": {
                "User Created Scorecard": [
                    {
                        "type": "text",
                        "name": "name"
                    }
                ],
                "Service Provided Scorecard": [
                    {
                        "type": "select",
                        "name": "name",
                        "option": {
                            "Most Prevalent Vulnerabilities Report": "Most Prevalent Vulnerabilities Report",
                            "Most Vulnerable Hosts Report": "Most Vulnerable Hosts Report",
                            "Ignored Vulnerabilities Report": "Ignored Vulnerabilities Report",
                            "Vulnerability Scorecard Report": "Vulnerability Scorecard Report",
                            "Patch Report": "Patch Report"
                        }
                    }
                ]
            }
        },
        {
            "type": "text",
            "name": "report_title"
        },
        {
            "type": "select",
            "name": "output_format",
            "option": {
                "MHT": "mht",
                "CSV": "csv",
                "HTML": "html",
                "XML": "xml",
                "PDF": "pdf"
            },
            "onchange": {
                "CSV": [
                    {
                        "type": "checkbox",
                        "name": "hide_header",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    }
                ],
                "PDF": [
                    {
                        "type": "password",
                        "name": "pdf_password"
                    },
                    {
                        "type": "integer",
                        "name": "recipient_group_id"
                    },
                    {
                        "type": "text",
                        "name": "recipient_group"
                    }
                ],
                "MHT": [],
                "HTML": [],
                "XML": []
            }
        },
        {
            "type": "select",
            "name": "source",
            "option": {
                "Asset Groups": "asset_groups",
                "Business Unit": "business_unit"
            },
            "onchange": {
                "Asset Groups": [
                    {
                        "type": "text",
                        "name": "asset_groups"
                    },
                    {
                        "type": "checkbox",
                        "name": "all_asset_groups",
                        "option": {
                            "true": 1,
                            "false": -9
                        }
                    }
                ],
                "Business Unit": [
                    {
                        "type": "text",
                        "name": "business_unit"
                    },
                    {
                        "type": "text",
                        "name": "division"
                    },
                    {
                        "type": "text",
                        "name": "function"
                    },
                    {
                        "type": "text",
                        "name": "location"
                    }
                ]
            }
        },
        {
            "type": "text",
            "name": "patch_qids"
        },
        {
            "type": "text",
            "name": "missing_qids"
        }
    ],
    "list_vm_scan": [
        {
            "type": "text",
            "name": "scan_ref"
        },
        {
            "type": "multiselect",
            "name": "state",
            "option": {
                "Running": "Running",
                "Queued": "Queued",
                "Canceled": "Canceled",
                "Loading": "Loading",
                "Paused": "Paused",
                "Finished": "Finished",
                "Error": "Error"
            }
        },
        {
            "type": "select",
            "name": "type",
            "option": {
                None: -9,
                "Scheduled": "Scheduled",
                "On-Demand": "On-Demand",
                "API": "API"
            }
        },
        {
            "type": "text",
            "name": "target"
        },
        {
            "type": "text",
            "name": "user_login"
        },
        {
            "type": "datetime",
            "name": "launched_after_datetime"
        },
        {
            "type": "datetime",
            "name": "launched_before_datetime"
        },
        {
            "type": "select",
            "name": "processed",
            "option": {
                None: -9,
                "Show only Processed Scans": 1,
                "Show scans that are Not Processed": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_ags",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_op",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_status",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_last",
            "option": {
                "true": 1,
                "false": 0
            }
        }
    ],
    "manage_virtual_host": [
        {
            "type": "select",
            "name": "action",
            "option": {
                "Delete": "delete",
                "Add FQDN": "add_fqdn",
                "Delete FQDN": "delete_fqdn",
                "Create": "create",
                "Update": "update"
            }
        },
        {
            "type": "text",
            "name": "ip"
        },
        {
            "type": "text",
            "name": "port"
        },
        {
            "type": "text",
            "name": "fqdn"
        }
    ],
    "list_ip": [
        {
            "type": "text",
            "name": "ips"
        },
        {
            "type": "text",
            "name": "network_id"
        },
        {
            "type": "select",
            "name": "tracking_method",
            "option": {
                None: -9,
                "IP": "IP",
                "NETBIOS": "NETBIOS",
                "DNS": "DNS"
            }
        },
        {
            "type": "checkbox",
            "name": "compliance_enabled",
            "option": {
                "true": 1,
                "false": 0
            }
        }
    ],
    "cancel_report": [
        {
            "type": "integer",
            "name": "id"
        }
    ],
    "vm_scan_action": [
        {
            "type": "select",
            "name": "action",
            "option": {
                "Pause": "pause",
                "Resume": "resume",
                "Cancel": "cancel",
                "Delete": "delete"
            }
        },
        {
            "type": "text",
            "name": "scan_ref"
        }
    ],
    "launch_vm_scan": [
        {
            "type": "text",
            "name": "scan_title"
        },
        {
            "type": "text",
            "name": "runtime_http_header"
        },
        {
            "type": "select",
            "name": "priority",
            "option": {
                "0 - No Priority": 0,
                "9 - Low": 9,
                "8 - Minor": 8,
                "7 - Medium": 7,
                "6 - Standard": 6,
                "5 - High": 5,
                "4 - Major": 4,
                "3 - Critical": 3,
                "2 - Ultimate": 2,
                "1 - Emergency": 1
            }
        },
        {
            "type": "select",
            "name": "opt_pro",
            "option": {
                "Option ID": "option_id",
                "Option Title": "option_title"
            },
            "onchange": {
                "Option ID": [
                    {
                        "type": "integer",
                        "name": "option_id"
                    }
                ],
                "Option Title": [
                    {
                        "type": "text",
                        "name": "option_title"
                    }
                ]
            }
        },
        {
            "type": "select",
            "name": "scan_app",
            "option": {
                "Scanner ID": "iscanner_id",
                "Scanner Name": "iscanner_name"
            },
            "onchange": {
                "Scanner ID": [
                    {
                        "type": "text",
                        "name": "iscanner_id"
                    }
                ],
                "Scanner Name": [
                    {
                        "type": "text",
                        "name": "iscanner_name"
                    }
                ]
            }
        },
        {
            "type": "select",
            "name": "target_from",
            "option": {
                "Tags": "tags",
                "Assets": "assets"
            },
            "onchange": {
                "Assets": [
                    {
                        "type": "text",
                        "name": "ip"
                    },
                    {
                        "type": "text",
                        "name": "asset_group_ids"
                    },
                    {
                        "type": "text",
                        "name": "asset_groups"
                    },
                    {
                        "type": "text",
                        "name": "exclude_ip_per_scan"
                    },
                    {
                        "type": "checkbox",
                        "name": "scanners_in_ag",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    }
                ],
                "Tags": [
                    {
                        "type": "select",
                        "name": "tag_include_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_exclude_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_set_by",
                        "option": {
                            "Name": "name",
                            "Id": "id"
                        }
                    },
                    {
                        "type": "text",
                        "name": "tag_set_include"
                    },
                    {
                        "type": "text",
                        "name": "tag_set_exclude"
                    },
                    {
                        "type": "checkbox",
                        "name": "use_ip_nt_range_tags",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    },
                    {
                        "type": "checkbox",
                        "name": "scanners_in_tagset",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    }
                ]
            }
        },
        {
            "type": "checkbox",
            "name": "default_scanner",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "text",
            "name": "ip_network_id"
        }
    ],
    "launch_patch_report": [
        {
            "type": "text",
            "name": "template_id"
        },
        {
            "type": "text",
            "name": "report_title"
        },
        {
            "type": "select",
            "name": "output_format",
            "option": {
                "CSV": "csv",
                "Online": "online",
                "PDF": "pdf"
            },
            "onchange": {
                "CSV": [
                    {"type": "checkbox",
                     "name": "hide_header",
                     "option": {
                         "true": 1,
                         "false": 0
                     }
                     }
                ],
                "PDF": [
                    {
                        "type": "password",
                        "name": "pdf_password"
                    },
                    {
                        "type": "integer",
                        "name": "recipient_group_id"
                    },
                    {
                        "type": "text",
                        "name": "recipient_group"
                    }
                ],
                "MHT": [],
                "HTML": [],
                "Docx": [],
                "XML": []
            }
        },
        {
            "type": "select",
            "name": "use_tags",
            "option": {
                True: 1,
                False: 0
            },
            "onchange": {
                True: [
                    {
                        "type": "select",
                        "name": "tag_include_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_exclude_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_set_by",
                        "option": {
                            "ID": "id",
                            "Name": "name"
                        }
                    },
                    {
                        "type": "text",
                        "name": "tag_set_include"
                    },
                    {
                        "type": "text",
                        "name": "tag_set_exclude"
                    }
                ],
                False: [
                    {
                        "type": "text",
                        "name": "ips"
                    },
                    {
                        "type": "text",
                        "name": "asset_group_ids"
                    },
                ]
            }
        },
    ],
    "manage_pc_scan": [
        {
            "type": "select",
            "name": "action",
            "option": {
                "Pause": "pause",
                "Resume": "resume",
                "Cancel": "cancel",
                "Delete": "delete"
            }
        },
        {
            "type": "text",
            "name": "scan_ref"
        }
    ],
    "list_vulnerability": [
        {
            "type": "select",
            "name": "details",
            "option": {
                "All": "All",
                "Basic": "Basic",
                "None": "None"
            }
        },
        {
            "type": "text",
            "name": "ids"
        },
        {
            "type": "text",
            "name": "id_min"
        },
        {
            "type": "text",
            "name": "id_max"
        },
        {
            "type": "select",
            "name": "is_patchable",
            "option": {
                None: -9,
                "Show Vulnerabilities that are Patchable": 1,
                "Show Vulnerabilities that are Not Patchable": 0
            }
        },
        {
            "type": "datetime",
            "name": "last_modified_after"
        },
        {
            "type": "datetime",
            "name": "last_modified_before"
        },
        {
            "type": "datetime",
            "name": "last_modified_by_user_after"
        },
        {
            "type": "datetime",
            "name": "last_modified_by_user_before"
        },
        {
            "type": "datetime",
            "name": "last_modified_by_service_after"
        },
        {
            "type": "datetime",
            "name": "last_modified_by_service_before"
        },
        {
            "type": "datetime",
            "name": "published_after"
        },
        {
            "type": "datetime",
            "name": "published_before"
        },
        {
            "type": "select",
            "name": "discovery_method",
            "option": {
                "Authenticated": "Authenticated",
                "Remote And Authenticated": "RemoteAndAuthenticated",
                "Authenticated Only": "AuthenticatedOnly",
                "Remote": "Remote",
                "Remote Only": "RemoteOnly"
            }
        },
        {
            "type": "multiselect",
            "name": "discovery_auth_types",
            "option": {
                "DB2": "DB2",
                "HTTP": "HTTP",
                "Windows": "Windows",
                "VMware": "VMware",
                "MySQL": "MySQL",
                "SNMP": "SNMP",
                "Unix": "Unix",
                "Oracle": "Oracle"
            }
        },
        {
            "type": "checkbox",
            "name": "show_pci_reasons",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_supported_modules_info",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_disabled_flag",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_qid_change_log",
            "option": {
                "true": 1,
                "false": 0
            }
        }
    ],
    "list_group": [
        {
            "type": "text",
            "name": "ids"
        },
        {
            "type": "text",
            "name": "id_min"
        },
        {
            "type": "text",
            "name": "id_max"
        },
        {
            "type": "text",
            "name": "truncation_limit"
        },
        {
            "type": "text",
            "name": "network_ids"
        },
        {
            "type": "integer",
            "name": "unit_id"
        },
        {
            "type": "integer",
            "name": "user_id"
        },
        {
            "type": "text",
            "name": "title"
        },
        {
            "type": "multiselect",
            "name": "show_attributes",
            "option": {
                "All": "ALL",
                "ID": "ID",
                "Title": "TITLE",
                "Owner User Name": "OWNER_USER_NAME",
                "Owner User ID": "OWNER_USER_ID",
                "Owner Unit ID": "OWNER_UNIT_NAME",
                "Last Update": "LAST_UPDATE",
                "IP Set": "IP_SET",
                "Appliance List": "APPLIANCE_LIST",
                "Domain List": "DOMAIN_LIST",
                "Host IDs": "HOST_IDS",
                "Assigned User IDs": "ASSIGNED_USER_IDS",
                "Assigned Unit IDs": "ASSIGNED_UNIT_IDS",
                "Business Impact": "BUSINESS_IMPACT",
                "Comments": "COMMENTS"
            }
        }
    ],
    "launch_scheduled_report": [
        {
            "type": "integer",
            "name": "id"
        }
    ],
    "launch_compliance_policy_report": [
        {
            "type": "text",
            "name": "template_id"
        },
        {
            "type": "text",
            "name": "report_title"
        },
        {
            "type": "select",
            "name": "output_format",
            "option": {
                "MHT": "mht",
                "CSV": "csv",
                "HTML": "html",
                "XML": "xml",
                "PDF": "pdf"
            },
            "onchange": {
                "CSV": [
                    {"type": "checkbox",
                     "name": "hide_header",
                     "option": {
                         "true": 1,
                         "false": 0
                     }
                     }
                ],
                "PDF": [
                    {
                        "type": "password",
                        "name": "pdf_password"
                    },
                    {
                        "type": "integer",
                        "name": "recipient_group_id"
                    },
                    {
                        "type": "text",
                        "name": "recipient_group"
                    }
                ],
                "MHT": [],
                "HTML": [],
                "XML": []
            }
        },
        {
            "type": "text",
            "name": "policy_id"
        },
        {
            "type": "text",
            "name": "host_id"
        },
        {
            "type": "text",
            "name": "instance_string"
        },
        {
            "type": "select",
            "name": "use_tags",
            "option": {
                True: 1,
                False: 0
            },
            "onchange": {
                True: [
                    {
                        "type": "select",
                        "name": "tag_include_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_exclude_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_set_by",
                        "option": {
                            "ID": "id",
                            "Name": "name"
                        }
                    },
                    {
                        "type": "text",
                        "name": "tag_set_include"
                    },
                    {
                        "type": "text",
                        "name": "tag_set_exclude"
                    }
                ],
                False: [
                    {
                        "type": "text",
                        "name": "ips"
                    },
                    {
                        "type": "text",
                        "name": "asset_group_ids"
                    },
                ]
            }
        },
    ],
    "list_virtual_host": [
        {
            "type": "text",
            "name": "port"
        },
        {
            "type": "text",
            "name": "ip"
        }
    ],
    "list_excluded_host": [
        {
            "type": "text",
            "name": "ips"
        },
        {
            "type": "text",
            "name": "network_id"
        }
    ],
    "list_report_template": [],
    "list_option_profile": [],
    "add_ip": [
        {
            "type": "text",
            "name": "ips"
        },
        {
            "type": "select",
            "name": "tracking_method",
            "option": {
                "IP": "IP",
                "NETBIOS": "NETBIOS",
                "DNS": "DNS"
            }
        },
        {
            "type": "checkbox",
            "name": "enable_vm",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "enable_pc",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "text",
            "name": "owner"
        },
        {
            "type": "text",
            "name": "ud1"
        },
        {
            "type": "text",
            "name": "ud2"
        },
        {
            "type": "text",
            "name": "ud3"
        },
        {
            "type": "text",
            "name": "comment"
        },
        {
            "type": "text",
            "name": "ag_title"
        }
    ],
    "list_host": [
        {
            "type": "text",
            "name": "truncation_limit"
        },
        {
            "type": "select",
            "name": "details",
            "option": {
                "Basic": "Basic",
                "Basic/AGs": "Basic/AGs",
                "All": "All",
                "All/AGs": "All/AGs",
                "None": "None"
            }
        },
        {
            "type": "text",
            "name": "ips"
        },
        {
            "type": "text",
            "name": "ids"
        },
        {
            "type": "text",
            "name": "ag_ids"
        },
        {
            "type": "text",
            "name": "ag_titles"
        },
        {
            "type": "text",
            "name": "id_min"
        },
        {
            "type": "text",
            "name": "id_max"
        },
        {
            "type": "text",
            "name": "network_ids"
        },
        {
            "type": "datetime",
            "name": "no_vm_scan_since"
        },
        {
            "type": "datetime",
            "name": "no_compliance_scan_since"
        },
        {
            "type": "datetime",
            "name": "vm_scan_since"
        },
        {
            "type": "datetime",
            "name": "compliance_scan_since"
        },
        {
            "type": "datetime",
            "name": "vm_processed_before"
        },
        {
            "type": "datetime",
            "name": "vm_processed_after"
        },
        {
            "type": "datetime",
            "name": "vm_scan_date_before"
        },
        {
            "type": "datetime",
            "name": "vm_scan_date_after"
        },
        {
            "type": "text",
            "name": "os_pattern"
        }
    ],
    "update_ip": [
        {
            "type": "text",
            "name": "ips"
        },
        {
            "type": "select",
            "name": "tracking_method",
            "option": {
                "IP": "IP",
                "NETBIOS": "NETBIOS",
                "DNS": "DNS"
            }
        },
        {
            "type": "text",
            "name": "host_dns"
        },
        {
            "type": "text",
            "name": "host_netbios"
        },
        {
            "type": "text",
            "name": "owner"
        },
        {
            "type": "text",
            "name": "ud1"
        },
        {
            "type": "text",
            "name": "ud2"
        },
        {
            "type": "text",
            "name": "ud3"
        },
        {
            "type": "text",
            "name": "comment"
        }
    ],
    "list_pc_scan": [
        {
            "type": "text",
            "name": "scan_id"
        },
        {
            "type": "text",
            "name": "scan_ref"
        },
        {
            "type": "multiselect",
            "name": "state",
            "option": {
                "Running": "Running",
                "Queued": "Queued",
                "Canceled": "Canceled",
                "Loading": "Loading",
                "Paused": "Paused",
                "Finished": "Finished",
                "Error": "Error"
            }
        },
        {
            "type": "select",
            "name": "type",
            "option": {
                None: -9,
                "Scheduled": "Scheduled",
                "On-Demand": "On-Demand",
                "API": "API"
            }
        },
        {
            "type": "text",
            "name": "target"
        },
        {
            "type": "text",
            "name": "user_login"
        },
        {
            "type": "datetime",
            "name": "launched_after_datetime"
        },
        {
            "type": "datetime",
            "name": "launched_before_datetime"
        },
        {
            "type": "select",
            "name": "processed",
            "option": {
                None: -9,
                "Show only Processed Scans": 1,
                "Show scans that are Not Processed": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_ags",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_op",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_status",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_last",
            "option": {
                "true": 1,
                "false": 0
            }
        }
    ],
    "launch_scan_based_findings_report": [
        {
            "type": "text",
            "name": "template_id"
        },
        {
            "type": "text",
            "name": "report_title"
        },
        {
            "type": "select",
            "name": "output_format",
            "option": {
                "MHT": "mht",
                "CSV": "csv",
                "HTML": "html",
                "Docx": "docx",
                "XML": "xml",
                "PDF": "pdf"
            },
            "onchange": {
                "CSV": [
                    {"type": "checkbox",
                     "name": "hide_header",
                     "option": {
                         "true": 1,
                         "false": 0
                     }
                     }
                ],
                "PDF": [
                    {
                        "type": "password",
                        "name": "pdf_password"
                    },
                    {
                        "type": "integer",
                        "name": "recipient_group_id"
                    },
                    {
                        "type": "text",
                        "name": "recipient_group"
                    }
                ],
                "MHT": [],
                "HTML": [],
                "Docx": [],
                "XML": []
            }
        },
        {
            "type": "text",
            "name": "ip_restriction"
        },
        {
            "type": "text",
            "name": "report_refs"
        },
        {
            "type": "select",
            "name": "use_tags",
            "option": {
                True: 1,
                False: 0
            },
            "onchange": {
                True: [
                    {
                        "type": "select",
                        "name": "tag_include_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_exclude_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_set_by",
                        "option": {
                            "ID": "id",
                            "Name": "name"
                        }
                    },
                    {
                        "type": "text",
                        "name": "tag_set_include"
                    },
                    {
                        "type": "text",
                        "name": "tag_set_exclude"
                    }
                ],
                False: [
                ]
            }
        }
    ],
    "list_report": [
        {
            "type": "integer",
            "name": "id"
        },
        {
            "type": "select",
            "name": "state",
            "option": {
                None: -9,
                "Errors": "Errors",
                "Submitted": "Submitted",
                "Canceled": "Canceled",
                "Finished": "Finished",
                "Running": "Running"
            }
        },
        {
            "type": "text",
            "name": "user_login"
        },
        {
            "type": "datetime",
            "name": "expires_before_datetime"
        }
    ],
    "fetch_pc_scan": [
        {
            "type": "text",
            "name": "scan_ref"
        }
    ],
    "launch_pc_scan": [
        {
            "type": "text",
            "name": "scan_title"
        },
        {
            "type": "select",
            "name": "opt_pro",
            "option": {
                "Option ID": "option_id",
                "Option Title": "option_title"
            },
            "onchange": {
                "Option ID": [
                    {
                        "type": "integer",
                        "name": "option_id"
                    }
                ],
                "Option Title": [
                    {
                        "type": "text",
                        "name": "option_title"
                    }
                ]
            }
        },
        {
            "type": "select",
            "name": "scan_app",
            "option": {
                "Scanner ID": "iscanner_id",
                "Scanner Name": "iscanner_name"
            },
            "onchange": {
                "Scanner ID": [
                    {
                        "type": "text",
                        "name": "iscanner_id"
                    }
                ],
                "Scanner Name": [
                    {
                        "type": "text",
                        "name": "iscanner_name"
                    }
                ]
            }
        },
        {
            "type": "text",
            "name": "runtime_http_header"
        },
        {
            "type": "checkbox",
            "name": "default_scanner",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "text",
            "name": "ip_network_id"
        },
        {
            "type": "select",
            "name": "target_from",
            "option": {
                "Tags": "tags",
                "Assets": "assets"
            },
            "onchange": {
                "Assets": [
                    {
                        "type": "text",
                        "name": "ip"
                    },
                    {
                        "type": "text",
                        "name": "asset_group_ids"
                    },
                    {
                        "type": "text",
                        "name": "asset_groups"
                    },
                    {
                        "type": "text",
                        "name": "exclude_ip_per_scan"
                    },
                    {
                        "type": "checkbox",
                        "name": "scanners_in_ag",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    },
                ],
                "Tags": [
                    {
                        "type": "select",
                        "name": "tag_include_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_exclude_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_set_by",
                        "option": {
                            "Name": "name",
                            "ID": "id"
                        }
                    },
                    {
                        "type": "text",
                        "name": "tag_set_include"
                    },
                    {
                        "type": "checkbox",
                        "name": "use_ip_nt_range_tags",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    },
                    {
                        "type": "checkbox",
                        "name": "scanners_in_tagset",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    }
                ]
            }
        }
    ],
    "list_scheduled_report": [
        {
            "type": "integer",
            "name": "id"
        },
        {
            "type": "select",
            "name": "is_active",
            "option": {
                None: -9,
                "List Active Scheduled Reports only": 1,
                "List Inactive Scheduled Reports only": 0
            }
        }
    ],
    "delete_report": [
        {
            "type": "integer",
            "name": "id"
        }
    ],
    "manage_excluded_host": [
        {
            "type": "select",
            "name": "action",
            "option": {
                "Add": "add",
                "Remove All": "remove_all",
                "Remove": "remove"
            },
            "onchange": {
                "Add": [
                    {
                        "type": "text",
                        "name": "ips"
                    },
                    {
                        "type": "text",
                        "name": "comment"
                    },
                    {
                        "type": "integer",
                        "name": "expiry_days"

                    },
                    {
                        "type": "text",
                        "name": "dg_names"

                    },
                    {
                        "type": "text",
                        "name": "network_id"
                    }
                ],
                "Remove": [
                    {
                        "type": "text",
                        "name": "ips"
                    },
                    {
                        "type": "text",
                        "name": "comment"
                    },
                    {
                        "type": "text",
                        "name": "network_id"
                    }
                ],
                "Remove All": [
                    {
                        "type": "text",
                        "name": "comment"
                    },
                    {
                        "type": "text",
                        "name": "network_id"
                    }
                ]
            }
        },
        {
            "type": "text",
            "name": "ips"
        },
        {
            "type": "text",
            "name": "comment"
        },
        {
            "type": "text",
            "name": "network_id"
        }
    ],
    "fetch_report": [
        {
            "type": "integer",
            "name": "id"
        }
    ],
    "list_restricted_ip": [],
    "launch_map_report": [
        {
            "type": "text",
            "name": "template_id"
        },
        {
            "type": "text",
            "name": "report_title"
        },
        {
            "type": "select",
            "name": "output_format",
            "option": {
                "MHT": "mht",
                "CSV": "csv",
                "XML": "xml",
                "HTML": "html",
                "PDF": "pdf"
            }
        },
        {
            "type": "checkbox",
            "name": "hide_header",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "password",
            "name": "pdf_password"
        },
        {
            "type": "integer",
            "name": "recipient_group_id"
        },
        {
            "type": "text",
            "name": "recipient_group"
        },
        {
            "type": "text",
            "name": "domain"
        },
        {
            "type": "text",
            "name": "ip_restriction"
        },
        {
            "type": "text",
            "name": "report_refs"
        },
        {
            "type": "checkbox",
            "name": "use_tags",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "select",
            "name": "tag_include_selector",
            "option": {
                "All": "All",
                "Any": "Any"
            }
        },
        {
            "type": "select",
            "name": "tag_exclude_selector",
            "option": {
                "All": "All",
                "Any": "Any"
            }
        },
        {
            "type": "select",
            "name": "tag_set_by",
            "option": {
                "ID": "ID",
                "Name": "Name"
            }
        },
        {
            "type": "text",
            "name": "tag_set_include"
        },
        {
            "type": "text",
            "name": "tag_set_exclude"
        }
    ],
    "list_scap_scan": [
        {
            "type": "text",
            "name": "scan_ref"
        },
        {
            "type": "multiselect",
            "name": "state",
            "option": {
                "Running": "Running",
                "Queued": "Queued",
                "Canceled": "Canceled",
                "Loading": "Loading",
                "Paused": "Paused",
                "Finished": "Finished",
                "Error": "Error"
            }
        },
        {
            "type": "select",
            "name": "type",
            "option": {
                "Scheduled": "Scheduled",
                "On-Demand": "On-Demand",
                "API": "API"
            }
        },
        {
            "type": "text",
            "name": "target"
        },
        {
            "type": "text",
            "name": "user_login"
        },
        {
            "type": "datetime",
            "name": "launched_after_datetime"
        },
        {
            "type": "datetime",
            "name": "launched_before_datetime"
        },
        {
            "type": "checkbox",
            "name": "processed",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_ags",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_op",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_status",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "type": "checkbox",
            "name": "show_last",
            "option": {
                "true": 1,
                "false": 0
            }
        }
    ],
    "launch_host_based_findings_report": [
        {
            "type": "text",
            "name": "template_id"
        },
        {
            "type": "text",
            "name": "report_title"
        },
        {
            "type": "select",
            "name": "output_format",
            "option": {
                "MHT": "mht",
                "CSV": "csv",
                "HTML": "html",
                "Docx": "docx",
                "XML": "xml",
                "PDF": "pdf"
            },
            "onchange": {
                "CSV": [
                    {"type": "checkbox",
                     "name": "hide_header",
                     "option": {
                         "true": 1,
                         "false": 0
                     }
                     }
                ],
                "PDF": [
                    {
                        "type": "password",
                        "name": "pdf_password"
                    },
                    {
                        "type": "integer",
                        "name": "recipient_group_id"
                    },
                    {
                        "type": "text",
                        "name": "recipient_group"
                    }
                ],
                "MHT": [],
                "HTML": [],
                "Docx": [],
                "XML": []
            }
        },
        {
            "type": "text",
            "name": "ips_network_id"
        },
        {
            "type": "select",
            "name": "use_tags",
            "option": {
                True: 1,
                False: 0
            },
            "onchange": {
                True: [
                    {
                        "type": "select",
                        "name": "tag_include_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_exclude_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_set_by",
                        "option": {
                            "ID": "id",
                            "Name": "name"
                        }
                    },
                    {
                        "type": "text",
                        "name": "tag_set_include"
                    },
                    {
                        "type": "text",
                        "name": "tag_set_exclude"
                    }
                ],
                False: [
                    {
                        "type": "text",
                        "name": "ips"
                    },
                    {
                        "type": "text",
                        "name": "asset_group_ids"
                    },
                ]
            }
        }
    ],
    "launch_compliance_report": [
        {
            "type": "text",
            "name": "template_id"
        },
        {
            "type": "text",
            "name": "report_title"
        },
        {
            "type": "select",
            "name": "output_format",
            "option": {
                "HTML": "html",
                "PDF": "pdf",
                "MHT": "mht"
            },
            "onchange": {
                "CSV": [
                    {"type": "checkbox",
                     "name": "hide_header",
                     "option": {
                         "true": 1,
                         "false": 0
                     }
                     }
                ],
                "PDF": [
                    {
                        "type": "password",
                        "name": "pdf_password"
                    },
                    {
                        "type": "integer",
                        "name": "recipient_group_id"
                    },
                    {
                        "type": "text",
                        "name": "recipient_group"
                    }
                ],
                "MHT": [],
                "HTML": []
            }
        },
        {
            "type": "text",
            "name": "report_refs"
        },
        {
            "type": "text",
            "name": "ips"
        },
        {
            "type": "integer",
            "name": "asset_group_ids"
        }
    ],
    "list_scanner_appliance": [
        {
            "name": "output_mode",
            "type": "select",
            "option": {
                "Brief": "brief",
                "Full": "full"
            },
            "onchange": {
                "Full": [
                    {
                        "type": "checkbox",
                        "name": "show_tags",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    },
                    {
                        "type": "checkbox",
                        "name": "include_cloud_info",
                        "option": {
                            "true": 1,
                            "false": 0
                        }
                    },
                    {
                        "name": "type",
                        "type": "select",
                        "option": {
                            None: -9,
                            "Physical": "physical",
                            "Offline": "offline",
                            "Virtual": "virtual"
                        }

                    }
                ],
                "Brief": []
            },
        },
        {
            "name": "scan_detail",
            "type": "checkbox",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "name": "busy",
            "type": "select",
            "option": {
                "(Default) Show appliances which are currently running scan": 1,
                "Show appliances which are not currently running scans": 0,
                None: -9
            }
        },
        {
            "type": "text",
            "name": "scan_ref"
        },
        {
            "type": "text",
            "name": "name"
        },
        {
            "type": "text",
            "name": "ids"
        },
        {
            "type": "checkbox",
            "name": "include_license_info",
            "option": {
                "true": 1,
                "false": 0
            }
        }
    ],
    "list_host_detection": [
        {
            "name": "ids",
            "type": "text"
        },
        {
            "name": "id_min",
            "type": "integer"
        },
        {
            "name": "id_max",
            "type": "integer"
        },
        {
            "type": "select",
            "name": "use_tags",
            "option": {
                True: 1,
                False: 0
            },
            "onchange": {
                True: [
                    {
                        "type": "select",
                        "name": "tag_include_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_exclude_selector",
                        "option": {
                            "All": "all",
                            "Any": "any"
                        }
                    },
                    {
                        "type": "select",
                        "name": "tag_set_by",
                        "option": {
                            "ID": "id",
                            "Name": "name"
                        }
                    },
                    {
                        "type": "text",
                        "name": "tag_set_include"
                    },
                    {
                        "type": "text",
                        "name": "tag_set_exclude"
                    }
                ],
                False: [
                    {
                        "type": "text",
                        "name": "ips"
                    },
                    {
                        "type": "text",
                        "name": "asset_group_ids"
                    },
                ]
            }
        },
        {
            "name": "network_ids",
            "type": "text"
        },
        {
            "name": "vm_scan_since",
            "type": "datetime"
        },
        {
            "name": "no_vm_scan_since",
            "type": "datetime"
        },
        {
            "name": "max_days_since_last_vm_scan",
            "type": "integer"
        },
        {
            "name": "vm_processed_before",
            "type": "datetime"
        },
        {
            "name": "vm_processed_after",
            "type": "datetime"
        },
        {
            "name": "vm_scan_date_before",
            "type": "datetime"
        },
        {
            "name": "vm_scan_date_after",
            "type": "datetime"
        },
        {
            "name": "vm_auth_scan_date_before",
            "type": "datetime"
        },
        {
            "name": "vm_auth_scan_date_after",
            "type": "datetime"
        },
        {
            "name": "status",
            "type": "multiselect",
            "option": {
                "New": "New",
                "Active": "Active",
                "Re-Opened": "Re-Opened",
                "Fixed": "Fixed"
            },
        },
        {
            "name": "compliance_enabled",
            "type": "select",
            "option": {
                None: -9,
                "List hosts which are assigned to Policy Compliance Module": 1,
                "List hosts which are not assigned to Policy Compliance Module": 0
            },
        },
        {
            "name": "os_pattern",
            "type": "text"
        },
        {
            "name": "qids",
            "type": "text"
        },
        {
            "name": "severities",
            "type": "multiselect",
            "option": {
                "5-Urgent": 5,
                "2-Medium": 2,
                "4-Critical- Standard": 4,
                "1-Minimal": 1,
                "3-Serious": 3
            },
        },
        {
            "name": "show_igs",
            "type": "select",
            "option": {
                None: -9,
                "Hide Detection Records Information Gathered": 0,
                "Show Detection Records with Information Gathered": 1
            },
        },
        {
            "name": "search_list",
            "type": "select",
            "option": {
                "Titles": "Titles",
                "IDs": "IDs"
            },
            "onchange": {
                "Titles": [
                    {
                        "name": "include_search_list_titles",
                        "type": "text"
                    },
                    {
                        "name": "exclude_search_list_titles",
                        "type": "text"
                    }
                ],
                "IDs": [
                    {
                        "name": "include_search_list_ids",
                        "type": "text"
                    },
                    {
                        "name": "exclude_search_list_ids",
                        "type": "text"
                    }
                ]
            },
        },
        {
            "name": "show_results",
            "type": "checkbox",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "name": "show_reopened_info",
            "type": "checkbox",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "name": "arf_kernel_filter",
            "type": "select",
            "option": {
                "0-Vulnerabilities are not filtered based on kernel activity": 0,
                "1-Exclude kernel related vulnerabilities that are not exploitable (found on non-running kernels)": 1,
                "2-Include kernel related vulnerabilities that are not exploitable (found on non-running kernels)": 2,
                "3-Include kernel related vulnerabilities that are exploitable (found on running kernels)": 3,
                "4-Include kernel related vulnerabilities": 4,
            },
        },
        {
            "name": "arf_service_filter",
            "type": "select",
            "option": {
                "0-Vulnerabilities are not filtered based on running ports/services": 0,
                "1-Exclude ervice related vulnerabilities that are not exploitable (found on non-running ports/services)": 1,
                "2-Include service related vulnerabilities that are not exploitable (found on non-running ports/services)": 2,
                "3-Include exploitable service related vulnerabilities (found on running ports/services)": 3,
                "4-Include service related vulnerabilities": 4,
            },
        },
        {
            "name": "arf_config_filter",
            "type": "select",
            "option": {
                "0- Vulnerabilities are not filtered based on host configuration": 0,
                "4-Include config related vulnerabilities": 4,
                "1-Exclude vulnerabilities not exploitable due to host configuration": 1,
                "3-Include config related vulnerabilities that are exploitable": 3,
                "2-Include config related vulnerabilities that are not exploitable": 2
            },
        },
        {
            "name": "output_format",
            "type": "select",
            "option": {
                "XML(default)": "xml",
                "CSV": "CSV",
                "CSV No Metadata": "CSV_NO_METADATA"
            },
        },
        {
            "name": "suppress_duplicated_data_from_csv",
            "type": "checkbox",
            "option": {
                "true": 1,
                "false": 0
            }
        },
        {
            "name": "truncation_limit",
            "type": "text"
        },
        {
            "name": "max_days_since_detection_updated",
            "type": "integer"
        },
        {
            "name": "detection_updated_since",
            "type": "datetime"
        },
        {
            "name": "detection_updated_before",
            "type": "datetime"
        },
        {
            "name": "dectection_processed_before",
            "type": "datetime"
        },
        {
            "name": "dectection_processed_after",
            "type": "datetime"
        },
        {
            "name": "add_vuln_as_attachment",
            "type": "checkbox",
            "option": {
                "true": 1,
                "false": 0
            }
        }
    ]
}
