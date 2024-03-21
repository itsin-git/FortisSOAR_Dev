#### Following enhancements have been made to the Azure Log Analytics Connector in version 2.0.0:

- This connector version is now certified.
- Added new parameters in Configuration section:
    - Subscription ID
    - Workspace ID
    - Workspace Name
    - Resource Group Name
- Removed "Server URL", "Authorization Code" and "Redirect URL" parameters from the Configuration section.
- Removed "Workspace ID" and "Workspace Name" parameter from the "Execute Query" operation.
- Removed "ETag" parameter from the "Update Saved Searches" operation.
- Removed "Workspace Resource Group", "Workspace Subscription ID", and "Workspace Name" from following operations:
    - Create Saved Searches
    - Update Saved Searches
    - List Saved Searches
    - Get Saved Searches
    - Delete Saved Search