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

..  list-table::
    :header-rows: 1
    :stub-columns: 1

    * - Field
      - Description

    * - Transport type\*
      - Select |transport_type_bold| from the drop-down menu.

    * - Content type\*
      - Select |content_type_bold| from the drop-down menu.

    * - API URL\*
      - Set this to the |provider| iSIGHT API endpoint.

        By default, this is set to
        ``https://api.isightpartners.com/``

    * - API key (public)\*
      - Set this to your |provider| public API key.

    * - API key (private)\*
      - Set this to your |provider| private API key.

    * - SSL verification
      - Selected by default.
        Select this option to enable SSL for this feed.

    * - SSL Cert
      - Used when connecting to a feed
        source that uses a custom CA.
        Set this as the path to the SSL certificate
        to use when authenticating the feed source.

    * - Include Threat intelligence type
      - Enable to retrieve threat intelligence reports
        when you run the feed.

        Selected by default.

    * - Include Malware intelligence type
      - Enable to retrieve malware intelligence reports
        when you run the feed.

        Selected by default.

    * - Include Vulnerability intelligence type
      - Enable to retrieve vulnerability intelligence reports
        when you run the feed.

        Selected by default.

    * - Include Overview intelligence type
      - Enable to retrieve 'Malware Overview' and
        'Actor Overview' intelligence reports
        when you run the feed.

        Selected by default.

    * - Download and attach PDF version of reports
      - When the feed runs, it downloads and attaches
        a PDF version for each report it receives from
        the feed source.

        Selected by default.

        ..  CAUTION::

            Enabling this makes an additional API call to
            |provider| for every report retrieved.
            Disable if the feed consumes your
            `Daily Query Quota`_ too quickly.

    * - Start ingesting from\*
      - Ingest data from the feed source
        starting from this date and time.
        Use the drop-down calendar to select the date
        and time you want to start ingesting feed data from.


.. _Daily Query Quota: https://docs.fireeye.com/iSight/index.html#/query_quota


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
