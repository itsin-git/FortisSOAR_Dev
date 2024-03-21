#### What's Fixed in 5.1.1
- Updated data ingestion to fix tenant field mapping in the 'Create Record' step of the 'FortiSIEM > Ingest' playbook. 

> **Notes**
> - Only FortiSIEM versions 6.7.0 and later are supported by versions 5.1.0 and later of this connector.
> - The FortiSIEM API no longer supports filtering incidents based on sub-categories in the List Incidents action.
> - Reconfigure Data Ingestion after upgrading the connector. For more information, see the Reconfiguring FortiSIEM Data Ingestion section. IMPORTANT: You must reconfigure data ingestion after upgrading the connector even if your connector is on version 5.1.0 and you are upgrading the connector to version 5.1.1 (or later).
> - The 'Time From' and 'Time To' parameters in the 'Get Events For Incident' action are supported only in the FortiSIEM 6.7.6 version.
