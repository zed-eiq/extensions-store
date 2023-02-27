Incoming feed - |transport_type|
***********************************

..  |provider| replace:: FireEye
..  |transport_type| replace:: |provider| iSIGHT Intelligence Report API
..  |transport_type_bold| replace:: **FireEye iSIGHT Intelligence Report API**
..  |content_type| replace:: |provider| Report JSON|
..  |content_type_bold| replace:: **FireEye Report JSON**

..  list-table::
    :header-rows: 1
    :stub-columns: 1

    * -
      - Specifications

    * - Transport type
      - |transport_type|

    * - Content type
      - |content_type|

    * - Ingested data
      - |provider| iSIGHT intelligence reports.

    * - Processed data
      - STIX reports on vulnerabilities, malware,
        and threats such as threat actors, strategies,
        tactics, and techniques.

Requirements
================

- |provider| public API key.
- |provider| private API key.

Configuration options
==============================

..  csv-table::
    :align: left
    :header-rows: 1
    :stub-columns: 1

    "title","name","type","required","description","default"
    "API URL","api_url","string","True","The URL pointing to the API endpoint to access the incoming feed.","https://api.isightpartners.com"
    "API key (public)","public_key","string","True","API public key to authorize your account.","***"
    "API key (private)","private_key","string","True","API private key to authorize your account.","***"
    "Include Threat intelligence type","include_threats","boolean","True","Include Threat intelligence type","True"
    "Include Malware intelligence type","include_malwares","boolean","True","Include Malware intelligence type","True"
    "Include Vulnerability intelligence type","include_vulnerabilities","boolean","True","Include Vulnerability intelligence type","True"
    "Include Overview intelligence type","include_overviews","boolean","True","Include Overview intelligence type","True"
    "Download and attach PDF version of reports","download_pdf","boolean","True","Download and attach PDF version of reports","True"

Ingestion results
========================

Retrieved reports are ingested as Report entitites on the platform,
with the following attached entitites where available:

..  list-table::
    :header-rows: 1
    :stub-columns: 1
    :align: left

    * - Ingested report
      - Resulting entities

    * - Malware intelligence report
      - * Indicators
        * TTPs, where available:

          - Malware family
          - Malware variant
          - Targeted victim
          - Targeted systems
          - Targeted information

        * Relationships from indicators to indicated TTPs

    * - Threat intelligence report
      - * Indicators
        * Threat actors

          - Motivations
          - Intended effects

        * TTPs

          - Malware
          - Targeted victim

        * Relationships from the report to
          related indicators, threat actors, and TTPs

    * - Vulnerability intelligence report
      - * Exploit targets

          - Vendor of the vulnerable/affected software product
          - Vulnerable/Affected software product
          - Vulnerable/Affected software product version
          - CVE-ID
          - CVSS scores

        * Courses of action
        * Relationships from exploit targets to courses of action

API version
=============================

This extension uses version 2.5 of the FireEye iSIGHT API.
