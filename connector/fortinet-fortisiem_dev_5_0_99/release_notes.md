#### What's Fixed in 5.0.3
- With the progress change triggered by FortiSIEM 6.7.5 and later, following connector actions were updated: 
    - Run Advanced Search Query
    - Get Events Data By Query ID
    - Search Events
    - Get Event Details
- Removed redundant filters from data ingestion wizard 

> **Notes**
> - Only FortiSIEM releases 6.7.0 and later are supported by this connector.
> - The FortiSIEM API no longer supports filtering incidents based on severity and sub-category in the List Incidents action.
> - Reconfigure Data Ingestion after upgrading the connector.
> - Get Event Details action is experiencing issues working with FortiSIEM 6.7.5 
> - With FortiSIEM 6.7.5, ensure that actions Search Events and Run Advanced Search Query pass the attributes list in the parameter Event Fields To Show In Response to function properly.
