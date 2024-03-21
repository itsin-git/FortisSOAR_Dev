#### Following enhancements have been made to the Fortinet FortiGuard Threat Intelligence Connector in version 3.1.2:

- Added a new configuration input to turn off SSL verification. This is for scenarios where a TLS inspection in firewalls changes the certificate.
- Fixed ingestion failure for certain URL feeds with special characters in the URL.
- Handled the following error when downloading feeds:
    TypeError: traceback traceback or none
- Corrected the formatting of the Description in the ingested feed records.
