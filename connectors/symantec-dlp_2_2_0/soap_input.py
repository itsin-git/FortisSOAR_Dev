""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

LIST_INCIDENT_STATUS = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header/>
   <soapenv:Body/>
</soapenv:Envelope>
'''


INCIDENT_LIST = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sch="http://www.vontu.com/v2011/enforce/webservice/incident/schema">
   <soapenv:Header/>
   <soapenv:Body>
      <sch:incidentListRequest>
         <sch:savedReportId>{}</sch:savedReportId>
         <sch:incidentCreationDateLaterThan>{}</sch:incidentCreationDateLaterThan>
      </sch:incidentListRequest>
   </soapenv:Body>
</soapenv:Envelope>'''


INCIDENT_LONG_ID = '<sch:incidentLongId>{}</sch:incidentLongId>'


INCIDENT_DETAIL = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sch="http://www.vontu.com/v2011/enforce/webservice/incident/schema">
   <soapenv:Header/>
   <soapenv:Body>
      <sch:incidentDetailRequest>
         <sch:includeViolations>{}</sch:includeViolations>
         <sch:includeHistory>{}</sch:includeHistory>
         {}
         <sch:includeImageViolations>false</sch:includeImageViolations>
      </sch:incidentDetailRequest>
   </soapenv:Body>
</soapenv:Envelope>
'''


INCIDENT_ATTACHMENT = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sch="http://www.vontu.com/v2011/enforce/webservice/incident/schema">
   <soapenv:Header/>
   <soapenv:Body>
      <sch:incidentBinariesRequest>
         <sch:incidentId>{incident_id}</sch:incidentId>
         <sch:includeOriginalMessage>{includeOriginalMessage}</sch:includeOriginalMessage>
         <sch:includeAllComponents>{includeAllComponents}</sch:includeAllComponents>
      </sch:incidentBinariesRequest>
   </soapenv:Body>
</soapenv:Envelope>
'''



LIST_CUSTOM_ATTRIB = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header/>
   <soapenv:Body/>
</soapenv:Envelope>
'''


INCIDENT_VIOLATIONS = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sch="http://www.vontu.com/v2011/enforce/webservice/incident/schema">
   <soapenv:Header/>
   <soapenv:Body>
      <sch:incidentViolationsRequest>
         <sch:incidentLongId>{}</sch:incidentLongId>
         <sch:includeImageViolations>{}</sch:includeImageViolations>
      </sch:incidentViolationsRequest>
   </soapenv:Body>
</soapenv:Envelope>
'''


INCIDENT_SEVERITY = '<severity>{}</severity>'
INCIDENT_STATUS = '<status>{}</status>'
REMEDIATION_LOCATIONS = '<remediationLocation>{}</remediationLocation>'
REMEDIATION_STATUS= '<remediationStatus>{}</remediationStatus>'
NOTES = '''
<note>
  <dateAndTime>{}</dateAndTime>
  <note>{}</note>
</note>
'''

CUSTOM_ATTRIB = '''
<customAttribute>
  <sch1:name>{}</sch1:name>
  <sch1:value>{}</sch1:value>
</customAttribute>
'''

UPDATE_INCIDENT = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sch="http://www.vontu.com/v2011/enforce/webservice/incident/schema" xmlns:sch1="http://www.vontu.com/v2011/enforce/webservice/incident/common/schema">
   <soapenv:Header/>
   <soapenv:Body>
      <sch:incidentUpdateRequest>
         <updateBatch>
            <batchId>1</batchId>
            <incidentAttributes>
               {severity}
               {status}
               {notes}
               {custom_attrib_str}
               {remediation_status}
               {remediation_location}
            </incidentAttributes>
            <incidentLongId>{incident_long_id}</incidentLongId>
         </updateBatch>
      </sch:incidentUpdateRequest>
   </soapenv:Body>
</soapenv:Envelope>
'''