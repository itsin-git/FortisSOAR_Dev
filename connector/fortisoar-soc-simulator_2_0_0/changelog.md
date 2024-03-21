# 1.0.9 Change log:

## New Action: Create Malicious File Indicator:

- Creates a Zero day Docx file as a file indicator
- Zero day means each run the resulting file has a unique hash code
- The action accepts email and URL parameters to be embedded within the file, users can then extract it via **File Content Extraction connector**

## New Action: Create Simulated Alert

- A dynamically generated Alert based on alert JSON definition, users can copy an alert defintion from FortiSOAR WebUI such as a response of 'GET /api/3/alerts/387dc349-b0c6-4317-a44c-0a83f7637cb5', replace some static entries such as timestamps, IP addresses, usernames ...etc with variables (Tags) so the action would replace these variables and then creates a new simulated alert

## New Indicators source: Moved all indicartor downloads to AlienVault OTX

## Variables (Tags) now accept parameters

- Variables such as TR_RANDOM_INTEGER, can now be written as: TR_RANDOM_INTEGER,10,20 so the value of the variable will be a random # between 10 and 20, similarily TR_ASSET_IP can now take a network address so its value will be a random IP from that subnet, exp: TR_ASSET_IP, would yield: 192.168.100.X, X between 2,240
