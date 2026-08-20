---
navigation_title: "Google threat intelligence"
type: reference
description: "Use the Google threat intelligence connector to retrieve file sandbox behaviour reports, MITRE ATT&CK technique mappings, and IP address and domain reputation and relationship data from Google Threat Intelligence."
applies_to:
  stack: preview 9.6
  serverless: preview
---

# Google threat intelligence connector [google-threat-intelligence-action-type]

The Google threat intelligence connector communicates with the [Google Threat Intelligence (GTI) API](https://gtidocs.virustotal.com/reference/api-overview) to retrieve file sandbox behaviour reports and MITRE ATT&CK technique mappings for a file hash, and reputation reports and related objects for an IP address or domain name.

## Create connectors in {{kib}} [define-google-threat-intelligence-ui]

You can create connectors in **{{stack-manage-app}} > {{connectors-ui}}**. For example:

### Connector configuration [google-threat-intelligence-connector-configuration]

Google threat intelligence connectors have the following configuration properties:

API Key
:   The Google Threat Intelligence API key for authentication. The key must belong to an account with the GTI Enterprise subscription tier; a key without that entitlement fails the connector's **Test connector** check.

## Test connectors [google-threat-intelligence-action-configuration]

You can test connectors as you're creating or editing the connector in {{kib}}.

## Connector actions [google-threat-intelligence-connector-actions]

The Google threat intelligence connector has the following actions:

Get File Behaviours
:   Retrieve sandbox detonation reports for a file by hash. Each report covers one sandbox run: process tree, files, registry keys and network activity it touched, plus the verdict. Returns an empty collection when the hash is known to GTI but has not been sandboxed.
    - **File hash** (required): SHA-256, SHA-1, or MD5 hash identifying the file.
    - **Limit** (optional): Maximum number of behaviour reports to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted.
    - **Cursor** (optional): Continuation cursor from a previous response, used to retrieve the next page of results.

Get File MITRE ATT&CK Techniques
:   Retrieve the MITRE ATT&CK tactics and techniques observed for a file by hash, grouped by the sandbox that observed them. Each technique lists the signatures that triggered it and their severity.
    - **File hash** (required): SHA-256, SHA-1, or MD5 hash identifying the file.

Get IP Report
:   Retrieve the Google Threat Intelligence reputation and detection report for an IP address, including the GTI assessment, last analysis statistics, network ownership and geolocation where available, and WHOIS data. Has not been observed to fail for a well-formed IP address, even a private or reserved one with no real internet presence.
    - **IP address** (required): IPv4 or IPv6 address to look up.

Get IP Relationship
:   Retrieve objects related to an IP address by relationship type, for example files that communicate with it, URLs hosted on it, or its historical DNS resolutions. Refer to the [IP address object relationships](https://gtidocs.virustotal.com/reference/ip-object#relationships) reference for the full set of supported relationship types.
    - **IP address** (required): IPv4 or IPv6 address to look up.
    - **Relationship** (required): A relationship type published for IP address objects (for example `communicating_files`, `resolutions`, `urls`).
    - **Limit** (optional): Maximum number of related objects to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted.
    - **Cursor** (optional): Continuation cursor from a previous response, used to retrieve the next page of results.

Get Domain Report
:   Retrieve the Google Threat Intelligence reputation and detection report for a domain name, including the GTI assessment, last analysis statistics, categorisation, and WHOIS data. Throws when GTI has no record of the domain at all.
    - **Domain** (required): Domain name to look up.

Get Domain Relationship
:   Retrieve objects related to a domain name by relationship type, for example its DNS resolutions, subdomains, or the files that communicate with it. Refer to the [domain object relationships](https://gtidocs.virustotal.com/reference/domains-object#relationships) reference for the full set of supported relationship types.
    - **Domain** (required): Domain name to look up.
    - **Relationship** (required): A relationship type published for domain objects (for example `resolutions`, `subdomains`, `communicating_files`).
    - **Limit** (optional): Maximum number of related objects to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted.
    - **Cursor** (optional): Continuation cursor from a previous response, used to retrieve the next page of results.

Get File Behaviours and Get File MITRE ATT&CK Techniques both throw an error when GTI has no record of the hash at all, rather than returning empty data, so a genuinely unknown hash can be distinguished from a known hash with no sandbox activity. Get IP Report has not been observed to have an equivalent "unknown" case: in testing against several IP addresses, including private, reserved, and IPv6 addresses, GTI always returned a populated report. Get Domain Report, by contrast, does throw for a domain GTI has no record of at all, the same as the file actions. Get IP Relationship and Get Domain Relationship both throw when the relationship type is not one GTI currently recognizes for that object type.

## Connector networking configuration [google-threat-intelligence-connector-networking-configuration]

Use the [Action configuration settings](/reference/configuration-reference/alerting-settings.md#action-settings) to customize connector networking configurations, such as proxies, certificates, or TLS settings.

## Get API credentials [google-threat-intelligence-api-credentials]

To use the Google threat intelligence connector, you need a Google Threat Intelligence API key from an account with the GTI Enterprise subscription tier. Refer to the [Google Threat Intelligence API documentation](https://gtidocs.virustotal.com/reference/api-overview) for details on obtaining a key, then paste it into the **API Key** field when configuring the connector.
