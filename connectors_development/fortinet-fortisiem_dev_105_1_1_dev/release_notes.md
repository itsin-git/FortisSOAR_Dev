#### What's Fixed in 5.2.0
Added the following actions:
- Get IP Context
- Get Host Context
- Get User Context

Deprecated the following actions:
- Get All Resource Lists
- Get Resource List Entries
- Add Entries To Resource List
- Remove Entries From Resource List

Updated output schema for following actions:
- List Incidents
- Get Incident Details

> **Notes**
> - Only FortiSIEM versions 7.1.0 and later are supported by this connector version.
> - The FortiSIEM API no longer supports filtering incidents based on sub-categories in the List Incidents action.
> - The Time From and Time To parameters in the Get Events For Incident action are supported only in the FortiSIEM v6.7.6.
