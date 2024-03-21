#### What's Fixed
- Updated the data ingestion playbook to fix a bug while fetching a single incident using 'By Sample incident ID' in the Fetch mode step of Data ingestion wizard. 
- Fixed an issue response conversion correction for all lookup table actions.

> **Notes**
>
> - Only FortiSIEM releases 6.4.0 and later are supported by this connector.
> - The FortiSIEM API does not support filtering incidents in the "List Incident" action based on severity and sub-category.
> - Post-upgrade, you must reconfigure data ingestion for this version of the connector.

