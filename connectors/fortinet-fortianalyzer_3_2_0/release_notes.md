#### What's Improved
- Added mappings in Alerts module for fields Source IP, Destination IP, Rule and Computer Name using data ingestion.
- Added Ingestion support for Device from FAZ in the FortiSOAR Asset's module and correlated it to the corresponding alerts/events.
- Added a new actions and playbooks named "Add Incident Attachment" and "Start bulk device log Search Request".
- Renamed the parameters and actions: On the connector configurations page, ADOM Name parameter is now ADOM Name(s), the action 'Get User Info' is now 'Get User Information', the action 'Get Endpoint Info' is now 'Get Endpoint Information', the action 'Add a Master Device' is now 'Add a Primary Device', the action 'Add a Slave Device' is now 'Add a Secondary Device'.
- Removed parameters 'Device ID' and 'Device Name' from actions 'Get Event for Multiple ADOMs' and 'Get Event'.
- Updated Output Schema for several actions: Get Incident Attachments, Get Event For Multiple ADOMs, Get Incident For Multiple ADOMs, Get ADOMs, Get Devices, Get Device Information, Get Report Schedule List, Get Executed Report List, Get Report File, Get Log-file State, List Log Fields, Get Log Status, Get Log File Content, Log Search Over Log-file, Get Incident Assets, Get Events For Incident, Add A New Device, Add A Primary Device, Authorize Device, Get Event, Get Incident, Create Incident, Update Incident.
- Enhanced actions "Get User Information" and "Get Endpoint Information" to either fetch all the records or based on specified IDs.


#### What's Fixed
- Fixed issue where connector showed a successful configuration even when the password for super user was incorrect.
- Incorporated fixes issued by Fortinet FortiAnalyzer in their API for actions Get Endpoint Information and Get User Information where these actions were failing for optional inputs. 

