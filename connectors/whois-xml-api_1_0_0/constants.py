True_False_Map = {
    "True": 1,
    "False": 0
}
Domain_Availability_Map = {
    "0 - No Check": 0,
    "1 - Quick Check": 1,
    "2- Thorough Check": 2
}
WHOISXML_WHOIS_HISTORY_SEARCH_ENDPOINT = 'https://whois-history.whoisxmlapi.com/api/v1'
WHOISXML_WHOIS_SEARCH_ENDPOINT = 'https://www.whoisxmlapi.com/whoisserver/WhoisService'
WHOISXML_REVERSE_WHOIS_SEARCH_ENDPOINT = 'https://reverse-whois.whoisxmlapi.com/api/v2'
WHOISXML_REVERSE_DNS_SEARCH_ENDPOINT = {'IPv4 Address': 'https://dns-history.whoisxmlapi.com/api/v1',
                                        'Mail Server': 'https://reverse-mx.whoisxmlapi.com/api/v1',
                                        'Name Server': 'https://reverse-ns.whoisxmlapi.com/api/v1'}
WHOISXML_DNS_LOOKUP_ENDPOINT = 'https://www.whoisxmlapi.com/whoisserver/DNSService?apiKey={}&domainName={}&outputFormat=JSON&type={}'
WHOISXML_DOMAIN_SUBDOMAIN_DISCOVERY_ENDPOINT = 'https://domains-subdomains-discovery.whoisxmlapi.com/api/v1'
WHOISXML_API_TOKEN_ENDPOINT = 'https://reverse-ip.whoisxmlapi.com/api/v1/?apiKey={}&ip=8.8.8.8'
WHOISXML_BRAND_MONITOR_ENDPOINT = 'https://brand-alert.whoisxmlapi.com/api/v2'
WHOISXML_SSL_CERTIFICATES_ENDPOINT = 'https://ssl-certificates.whoisxmlapi.com/api/v1'
