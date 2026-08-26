---
navigation_title: "Google threat intelligence"
type: reference
description: "Use the Google threat intelligence connector to retrieve file sandbox behaviour reports, MITRE ATT&CK technique mappings, IP address, domain, URL, and file reputation and relationship data, and to submit URLs for public or private scanning, with Google Threat Intelligence."
applies_to:
  stack: preview 9.6
  serverless: preview
---

# Google threat intelligence connector [google-threat-intelligence-action-type]

The Google threat intelligence connector communicates with the [Google Threat Intelligence (GTI) API](https://gtidocs.virustotal.com/reference/api-overview) to retrieve file sandbox behaviour reports and MITRE ATT&CK technique mappings for a file hash, reputation reports and related objects for an IP address, domain name, URL, or file hash, and to submit URLs for public or private scanning.

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

Get URL Report
:   Retrieve the Google Threat Intelligence reputation and detection report for a URL, including the GTI assessment, last analysis statistics, categorisation, and the final resolved destination after any redirects. Supply the URL in its natural form; the action derives the identifier GTI uses internally. Throws when GTI has no record of the URL at all.
    - **URL** (required): URL to look up.

Get URL Relationship
:   Retrieve objects related to a URL by relationship type, for example the files downloaded from it, the domains and IP addresses it contacts, or the URLs it redirects to. Refer to the [URL object relationships](https://gtidocs.virustotal.com/reference/url-object#relationships) reference for the full set of supported relationship types.
    - **URL** (required): URL to look up, in its natural form, the same as for Get URL Report.
    - **Relationship** (required): A relationship type published for URL objects (for example `downloaded_files`, `contacted_domains`, `redirects_to`).
    - **Limit** (optional): Maximum number of related objects to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted.
    - **Cursor** (optional): Continuation cursor from a previous response, used to retrieve the next page of results.

Get File Report
:   Retrieve the Google Threat Intelligence reputation and detection report for a file by hash, including the GTI assessment, last analysis statistics, file type metadata, and popular threat classification. This is a different action from Get File Behaviours, which returns sandbox detonation reports rather than the reputation report. Throws when GTI has no record of the hash at all.
    - **File hash** (required): SHA-256, SHA-1, or MD5 hash identifying the file.

Get File Relationship
:   Retrieve objects related to a file by hash by relationship type, for example the domains and IP addresses contacted during detonation, dropped files, or similar files. Refer to the [file object relationships](https://gtidocs.virustotal.com/reference/file-object#relationships) reference for the full set of supported relationship types.
    - **File hash** (required): SHA-256, SHA-1, or MD5 hash identifying the file.
    - **Relationship** (required): A relationship type published for file objects (for example `contacted_domains`, `dropped_files`, `similar_files`).
    - **Limit** (optional): Maximum number of related objects to retrieve. Minimum 0, maximum 40. Defaults to 10 if omitted.
    - **Cursor** (optional): Continuation cursor from a previous response, used to retrieve the next page of results.

Scan URL
:   Submit a URL to Google Threat Intelligence for a fresh public analysis. Returns an analysis identifier; pass it to Get Analysis to poll for completion, then to Get URL Scan Report to retrieve the full report once the analysis finishes.
    - **URL** (required): URL to submit for analysis, in its natural form, the same as for Get URL Report.

Get Analysis
:   Retrieve the status and statistics of a public URL analysis submitted by Scan URL. The response also carries the URL identifier needed by Get URL Scan Report once the analysis reaches a completed state.
    - **Analysis ID** (required): Analysis identifier returned by Scan URL.

Get URL Scan Report
:   Retrieve the Google Threat Intelligence reputation and detection report for a URL that was submitted through Scan URL, using the URL identifier from Get Analysis rather than the URL itself. Wraps the same endpoint as Get URL Report, kept as a separate action because its input is an identifier rather than a URL to derive one from.
    - **URL ID** (required): URL identifier taken from the `meta.url_info.id` field of the Get Analysis response. Not derived by this action.

Scan Private URL
:   Submit a URL to Google Threat Intelligence for a private analysis. Behaves like Scan URL, but neither the submitted URL nor the resulting analysis is shared with the wider Google Threat Intelligence community. Returns an analysis identifier; pass it to Get Private Analysis to poll for completion, then to Get Private URL Report to retrieve the full report once the analysis finishes.
    - **URL** (required): URL to submit for private analysis.
    - **User agent** (optional): User-Agent string to present when retrieving the URL.
    - **Sandboxes** (optional): Comma separated list of sandboxes to detonate in, for example `chrome_headless_linux`, `cape_win`, or `zenbox_windows`.
    - **Retention period days** (optional): Number of days the analysis is retained. Minimum 1, maximum 28. Defaults to 1 if omitted.
    - **Storage region** (optional): Region in which the analysis is stored, for example `US`, `CA`, `EU`, or `GB`.
    - **Interaction sandbox** (optional): Sandbox used for interactive analysis, for example `cape_win`. Defaults to `cape_win` if omitted.
    - **Interaction timeout** (optional): Interactive analysis duration in seconds. Minimum 60, maximum 1800. Defaults to 60 if omitted.

Get Private Analysis
:   Retrieve the status and statistics of a private URL analysis submitted by Scan Private URL. Once the analysis reaches a completed state, retrieve the full report with Get Private URL Report.
    - **Analysis ID** (required): Analysis identifier returned by Scan Private URL.

Get Private URL Report
:   Retrieve the Google Threat Intelligence reputation and detection report for a URL that was submitted through Scan Private URL, using the URL identifier from Get Private Analysis rather than the URL itself.
    - **URL ID** (required): URL identifier taken from the `meta.url_info.id` field of the Get Private Analysis response. Not derived by this action.

Get File Behaviours, Get File MITRE ATT&CK Techniques, and Get File Report all throw an error when GTI has no record of the hash at all, rather than returning empty data, so a genuinely unknown hash can be distinguished from a known hash with no sandbox activity. Get IP Report has not been observed to have an equivalent "unknown" case: in testing against several IP addresses, including private, reserved, and IPv6 addresses, GTI always returned a populated report. Get Domain Report and Get URL Report, by contrast, do throw for a domain or URL GTI has no record of at all, the same as the file actions. Get IP Relationship, Get Domain Relationship, Get URL Relationship, and Get File Relationship all throw when the relationship type is not one GTI currently recognizes for that object type. Get Analysis, Get URL Scan Report, Get Private Analysis, and Get Private URL Report throw when the analysis or URL identifier is not one GTI recognizes.

Scanning a URL, public or private, is asynchronous: submit it with Scan URL or Scan Private URL, then re-invoke Get Analysis or Get Private Analysis at an interval until its status is completed, before calling Get URL Scan Report or Get Private URL Report. The connector does not poll on its own; the calling workflow or agent is responsible for the retry loop.

## Connector networking configuration [google-threat-intelligence-connector-networking-configuration]

Use the [Action configuration settings](/reference/configuration-reference/alerting-settings.md#action-settings) to customize connector networking configurations, such as proxies, certificates, or TLS settings.

## Get API credentials [google-threat-intelligence-api-credentials]

To use the Google threat intelligence connector, you need a Google Threat Intelligence API key from an account with the GTI Enterprise subscription tier. Refer to the [Google Threat Intelligence API documentation](https://gtidocs.virustotal.com/reference/api-overview) for details on obtaining a key, then paste it into the **API Key** field when configuring the connector.
