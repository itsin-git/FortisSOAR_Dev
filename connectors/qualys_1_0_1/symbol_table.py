api_symtab = {
    # report
    "list_report": "/api/2.0/fo/report/",
    "cancel_report": "/api/2.0/fo/report/",
    "delete_report": "/api/2.0/fo/report/",
    "fetch_report": "/api/2.0/fo/report/",
    "launch_map_report": "/api/2.0/fo/report/",
    "launch_scan_based_findings_report": "/api/2.0/fo/report/",
    "launch_host_based_findings_report": "/api/2.0/fo/report/",
    "launch_patch_report": "/api/2.0/fo/report/",
    "launch_remediation_report": "/api/2.0/fo/report/",
    "launch_compliance_report": "/api/2.0/fo/report/",
    "launch_compliance_policy_report": "/api/2.0/fo/report/",
    "launch_score_card": "/api/2.0/fo/report/scorecard/",
    # scan
    "list_vm_scan": "/api/2.0/fo/scan/",
    "launch_vm_scan": "/api/2.0/fo/scan/",
    "vm_scan_action": "/api/2.0/fo/scan/",
    "fetch_vm_scan": "/api/2.0/fo/scan/",
    "list_scap_scan": "/api/2.0/fo/scan/scap/",
    "list_pc_scan": "/api/2.0/fo/scan/compliance/",
    "manage_pc_scan": "/api/2.0/fo/scan/compliance/",
    "launch_pc_scan": "/api/2.0/fo/scan/compliance/",
    "fetch_pc_scan": "/api/2.0/fo/scan/compliance/",
    "list_schedule_scan": "/api/2.0/fo/schedule/scan/",
    "list_restricted_ip": "/api/2.0/fo/setup/restricted_ips/",
    # assets
    "list_group": "/api/2.0/fo/asset/group/",
    "list_ip": "/api/2.0/fo/asset/ip/",
    "add_ip": "/api/2.0/fo/asset/ip/",
    "update_ip": "/api/2.0/fo/asset/ip/",
    "list_host": "/api/2.0/fo/asset/host/",
    "list_virtual_host": "/api/2.0/fo/asset/vhost/",
    "manage_virtual_host": "/api/2.0/fo/asset/vhost/",
    "list_excluded_host": "/api/2.0/fo/asset/excluded_ip/",
    "manage_excluded_host": "/api/2.0/fo/asset/excluded_ip/",
    "list_scheduled_report": "/api/2.0/fo/schedule/report/",
    "launch_scheduled_report": "/api/2.0/fo/schedule/report/",
    "list_vulnerability": "/api/2.0/fo/knowledge_base/vuln/",
    "list_report_template": "/msp/report_template_list.php",
    "list_option_profile": "/api/2.0/fo/subscription/option_profile/",
    "list_scanner_appliance": "/api/2.0/fo/appliance/",
    "list_host_detection": "/api/2.0/fo/asset/host/vm/detection"
}

optional_param_symtab = {
    "launch_score_card": ["name", "report_title", "output_format", "hide_header", "pdf_password", "recipient_group",
                          "recipient_group_id", "source", "asset_groups", "all_asset_groups", "business_unit",
                          "division", "function", "location", "patch_qids", "missing_qids"],
    "launch_pc_scan": ["scan_title", "option_id", "option_title", "iscanner_id", "iscanner_name", "ip",
                       "asset_group_ids", "asset_groups",
                       "runtime_http_header", "exclude_ip_per_scan", "default_scanner", "scanners_in_ag", "target_from",
                       "tag_include_selector", "tag_exclude_selector", "tag_set_by", "tag_set_include",
                       "tag_set_exclude", "use_ip_nt_range_tags", "ip_network_id", "scanners_in_tagset"],
    "launch_vm_scan": ["scan_title", "option_id", "option_title", "iscanner_id", "iscanner_name", "ip", "priority",
                       "asset_group_ids", "asset_groups",
                       "runtime_http_header", "exclude_ip_per_scan", "default_scanner", "scanners_in_ag", "target_from",
                       "tag_include_selector", "tag_exclude_selector", "tag_set_by", "tag_set_include",
                       "tag_set_exclude", "use_ip_nt_range_tags", "ip_network_id", "scanners_in_tagset"],
    "launch_remediation_report": ["template_id", "report_title", "output_format", "hide_header", "ips",
                                  "asset_group_ids", "assignee_type", "recipient_group_id", "pdf_password",
                                  "recipient_group", "use_tags", "tag_include_selector", "tag_exclude_selector",
                                  "tag_set_by", "tag_set_include", "tag_set_exclude"],
    "launch_scan_based_findings_report": ["template_id", "report_title", "output_format", "hide_header",
                                          "recipient_group_id", "pdf_password", "recipient_group", "ip_restriction",
                                          "report_refs", "use_tags", "tag_include_selector", "tag_exclude_selector",
                                          "tag_set_by", "tag_set_include", "tag_set_exclude"],
    "launch_host_based_findings_report": ["template_id", "report_title", "output_format", "hide_header",
                                          "recipient_group_id", "pdf_password", "recipient_group", "ips",
                                          "asset_group_ids", "ips_network_id", "ips_network_id", "use_tags",
                                          "tag_include_selector", "tag_exclude_selector", "tag_set_by",
                                          "tag_set_include", "tag_set_exclude"],
    "launch_patch_report": ["template_id", "report_title", "output_format", "hide_header", "ips", "asset_group_ids",
                            "recipient_group_id", "pdf_password", "recipient_group", "use_tags", "tag_include_selector",
                            "tag_exclude_selector", "tag_set_by", "tag_set_include", "tag_set_exclude"],
    "launch_compliance_report": ["template_id", "report_title", "output_format", "hide_header", "ips",
                                 "asset_group_ids", "report_refs", "recipient_group_id", "pdf_password",
                                 "recipient_group", "use_tags", "tag_include_selector", "tag_exclude_selector",
                                 "tag_set_by", "tag_set_include", "tag_set_exclude"],
    "launch_compliance_policy_report": ["template_id", "report_title", "output_format", "hide_header",
                                        "recipient_group_id", "pdf_password", "recipient_group", "policy_id",
                                        "asset_group_ids", "ips", "host_id", "instance_string", "use_tags",
                                        "tag_include_selector", "tag_exclude_selector", "tag_set_by", "tag_set_include",
                                        "tag_set_exclude"],
    "manage_excluded_host": ["action", "ips", "comment", "network_id"],
    "list_scanner_appliance": ["output_mode", "scan_detail", "show_tags", "include_cloud_info", "busy", "scan_ref",
                               "name", "ids", "include_license_info", "type"],
    "list_host_detection": ["ids", "id_min", "id_max", "ips", "ag_ids", "ag_titles", "network_ids", "vm_scan_since",
                            "no_vm_scan_since", "max_days_since_last_vm_scan", "vm_processed_before",
                            "vm_processed_after", "vm_scan_date_before", "vm_scan_date_after", "vm_auth_scan_date_before",
                            "vm_auth_scan_date_after", "status", "compliance_enabled", "os_pattern" , "qids",
                            "severities", "show_igs" , "include_search_list_titles","exclude_search_list_titles",
                            "include_search_list_ids" , "exclude_search_list_ids", "use_tags","tag_include_selector",
                            "tag_exclude_selector", "tag_set_by", "tag_set_include", "show_results", "show_reopened_info",
                            "arf_kernel_filter", "arf_service_filter", "arf_config_filter", "active_kernels_only",
                            "output_format", "suppress_duplicated_data_from_csv", "truncation_limit",
                            "max_days_since_detection_updated","detection_updated_since", "detection_updated_before",
                            "dectection_processed_before", "dectection_processed_after"],
    "list_group": ["ids", "id_min", "id_max", "truncation_limit", "network_i1ds", "unit_id", "user_id", "title",
                   "show_attributes"]

}

required_param_symtab = {
    "list_report": [
        ["action", "list"]
    ],
    "cancel_report": [
        ["action", "cancel"]
    ],
    "delete_report": [
        ["action", "delete"]
    ],
    "fetch_report": [
        ["action", "fetch"]
    ],
    "launch_map_report": [
        ["action", "launch"],
        ["report_type", "Map"]
    ],
    "launch_scan_based_findings_report": [
        ["action", "launch"],
        ["report_type", "Scan"]
    ],
    "launch_host_based_findings_report": [
        ["action", "launch"],
        ["report_type", "Scan"]
    ],
    "launch_patch_report": [
        ["action", "launch"],
        ["report_type", "Patch"]
    ],
    "launch_remediation_report": [
        ["action", "launch"],
        ["report_type", "Remediation"]
    ],
    "launch_compliance_report": [
        ["action", "launch"],
        ["report_type", "Compliance"],
        ["use_tags", 0]
    ],
    "launch_compliance_policy_report": [
        ["action", "launch"],
        ["report_type", "Policy"]
    ],
    "launch_score_card": [
        ["action", "launch"]
    ],
    "list_pc_scan": [
        ["action", "list"]
    ],
    "list_vm_scan": [
        ["action", "list"]
    ],
    "launch_vm_scan": [
        ["action", "launch"]
    ],
    "fetch_vm_scan": [
        ["action", "fetch"],
        ["output_format", "json"]
    ],
    "list_scap_scan": [
        ["action", "list"]
    ],
    "launch_pc_scan": [
        ["action", "launch"]
    ],
    "fetch_pc_scan": [
        ["action", "fetch"]
    ],
    "list_schedule_scan": [
        ["action", "list"]
    ],
    "list_restricted_ip": [
        ["action", "list"]
    ],
    "list_group": [
        ["action", "list"]
    ],
    "list_ip": [
        ["action", "list"]
    ],
    "add_ip": [
        ["action", "add"]
    ],
    "update_ip": [
        ["action", "update"]
    ],
    "list_host": [
        ["action", "list"]
    ],
    "list_virtual_host": [
        ["action", "list"]
    ],
    "list_excluded_host": [
        ["action", "list"]
    ],
    "list_scheduled_report": [
        ["action", "list"]
    ],
    "launch_scheduled_report": [
        ["action", "launch_now"]
    ],
    "list_vulnerability": [
        ["action", "list"]
    ],
    "list_option_profile": [
        ["action", "export"]
    ],
    "list_scanner_appliance": [
        ["action", "list"]
    ],
    "list_host_detection": [
        ["action", "list"]
    ]
}

http_method_symtab = {
    "list_report": "GET",
    "cancel_report": "POST",
    "delete_report": "POST",
    "fetch_report": "POST",
    "launch_map_report": "POST",
    "launch_scan_based_findings_report": "POST",
    "launch_host_based_findings_report": "POST",
    "launch_patch_report": "POST",
    "launch_remediation_report": "POST",
    "launch_compliance_report": "POST",
    "launch_compliance_policy_report": "POST",
    "launch_score_card": "POST",
    "list_pc_scan": "POST",
    "list_vm_scan": "POST",
    "launch_vm_scan": "POST",
    "vm_scan_action": "POST",
    "fetch_vm_scan": "POST",
    "list_scap_scan": "GET",
    "manage_pc_scan": "POST",
    "launch_pc_scan": "POST",
    "fetch_pc_scan": "GET",
    "list_schedule_scan": "GET",
    "list_restricted_ip": "GET",
    "list_group": "GET",
    "list_ip": "GET",
    "add_ip": "POST",
    "update_ip": "POST",
    "list_host": "POST",
    "list_virtual_host": "GET",
    "manage_virtual_host": "POST",
    "list_excluded_host": "GET",
    "manage_excluded_host": "POST",
    "list_scheduled_report": "GET",
    "launch_scheduled_report": "POST",
    "list_vulnerability": "POST",
    "list_report_template": "GET",
    "list_option_profile": "GET",
    "list_scanner_appliance": "GET",
    "list_host_detection": "GET"
}

content_symtab = {
    "list_report": ["RESPONSE"],
    "cancel_report": ["RESPONSE"],
    "delete_report": ["RESPONSE"],
    "fetch_report": [],
    "launch_map_report": ["RESPONSE"],
    "launch_scan_based_findings_report": ["RESPONSE"],
    "launch_host_based_findings_report": ["RESPONSE"],
    "launch_patch_report": ["RESPONSE"],
    "launch_remediation_report": ["RESPONSE"],
    "launch_compliance_report": ["RESPONSE"],
    "launch_compliance_policy_report": ["RESPONSE"],
    "launch_score_card": ["RESPONSE"],
    "list_pc_scan": ["RESPONSE"],
    "list_vm_scan": ["RESPONSE"],
    "launch_vm_scan": ["RESPONSE"],
    "vm_scan_action": ["RESPONSE"],
    "fetch_vm_scan": [],
    "list_scap_scan": ["RESPONSE"],
    "manage_pc_scan": ["RESPONSE"],
    "launch_pc_scan": ["RESPONSE"],
    "fetch_pc_scan": ["RESPONSE", "COMPLIANCE_SCAN"],
    "list_schedule_scan": ["RESPONSE"],
    "list_restricted_ip": [],
    "list_group": ["RESPONSE"],
    "list_ip": ["RESPONSE"],
    "add_ip": ["RESPONSE"],
    "update_ip": ["RESPONSE"],
    "list_host": ["RESPONSE"],
    "list_host_detection": ["RESPONSE"],
    "list_virtual_host": ["RESPONSE"],
    "manage_virtual_host": ["RESPONSE"],
    "list_excluded_host": ["RESPONSE", ],
    "manage_excluded_host": ["RESPONSE"],
    "list_scheduled_report": ["RESPONSE"],
    "launch_scheduled_report": ["RESPONSE"],
    "list_vulnerability": ["RESPONSE"],
    "list_report_template": [],
    "list_option_profile": [],
    "list_scanner_appliance": ["RESPONSE"]
}


output_symtab = {
    "list_report": [
        ["REPORT_LIST", "REPORT"]
    ],
    "cancel_report": [],
    "delete_report": [],
    "fetch_report": [],
    "launch_map_report": [],
    "launch_scan_based_findings_report": [],
    "launch_host_based_findings_report": [],
    "launch_patch_report": [],
    "launch_remediation_report": [],
    "launch_compliance_report": [],
    "launch_compliance_policy_report": [],
    "launch_score_card": [],
    "list_pc_scan": [["SCAN_LIST", "SCAN"]],
    "list_vm_scan": [["SCAN_LIST", "SCAN"]],
    "launch_vm_scan": [],
    "vm_scan_action": [],
    "fetch_vm_scan": [],
    "list_scap_scan": [["SCAN_LIST", "SCAN"]],
    "manage_pc_scan": [],
    "launch_pc_scan": [],
    "fetch_pc_scan": [],
    "list_schedule_scan": [["SCHEDULE_SCAN_LIST", "SCAN"]],
    "list_restricted_ip": [],
    "list_group": [["ASSET_GROUP_LIST", "ASSET_GROUP"]],
    "list_ip": [],
    "add_ip": [],
    "update_ip": [],
    "list_host": [
        ["HOST_LIST", "HOST"],
        ["GLOSSARY", "ASSET_GROUP_LIST", "ASSET_GROUP"]
    ],
    "list_host_detection": [["HOST_LIST", "HOST"]],
    "list_virtual_host": [["VIRTUAL_HOST_LIST", "VIRTUAL_HOST"]],
    "manage_virtual_host": [],
    "list_excluded_host": [["IP_SET", "IP"]],
    "manage_excluded_host": [["ITEM_LIST", "ITEM"]],
    "list_scheduled_report": [["SCHEDULE_REPORT_LIST", "REPORT"]],
    "launch_scheduled_report": [],
    "list_vulnerability": [["VULN_LIST", "VULN"]],
    "list_report_template": [],
    "list_option_profile": [],
    "list_scanner_appliance": [["APPLIANCE_LIST", "APPLIANCE"]]
}