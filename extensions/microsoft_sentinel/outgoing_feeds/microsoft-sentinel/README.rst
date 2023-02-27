Outgoing feed - |transport_type|
***********************************

.. |provider| replace:: Microsoft Azure
.. |transport_type| replace:: **Microsoft Azure Sentinel Outgoing Feed**
.. |content_type| replace:: **Microsoft Azure Sentinel JSON model**

..  list-table::
    :header-rows: 1
    :stub-columns: 1

    * -
      - Specifications

    * - Transport type
      - |transport_type|

    * - Content type
      - |content_type|

    * - Published data
      - See `Map EclecticIQ Platform entities to Microsoft Azure Sentinel Indicators`_.

Requirements
================

- Your |provider| `tenant ID`_.
- A Microsoft Azure user
  to set up
  the service application.
  This use should have one of these roles:

  * Global Administrator
  * Application Administrator
  * Cloud Application Administrator
- A service application.

  This provides you with a ``client_id``
  and ``client_secret`` for setting up the outgoing feed.
  See `Set up service application on Azure`_.


.. _tenant ID: https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-create-new-tenant#use-an-existing-tenant

Set up service application on Azure
=======================================

Before setting up an outgoing feed
with the |transport_type| transport type,
you must:

#.  Register a service application in Azure.

    The outgoing feed connects to your Azure Sentinel workspace
    using this service application.
#.  Obtain ``client_id`` and ``client_secret``
    from your new service application.

    You need the ``client_id`` and ``client_secret``
    to `Configuration options`_.
#.  Assign ``ThreatIndicators.ReadWrite.OwnedBy`` permisisons
    to your service application.
#.  Grant the service application tenant-wide admin consent.
#.  (Optional) Assign user or group to service application.

These steps are documented in the
`official Microsoft Azure Sentinel documentation`_.

Use ``client_id`` and ``client_secret`` in `Configuration options`_.

.. _official Microsoft Azure Sentinel documentation : https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence#connect-azure-sentinel-to-your-threat-intelligence-platform

Configuration options
==============================

..  csv-table::
    :align: left
    :header-rows: 1
    :stub-columns: 1

    "title","name","type","required","description","default"
    "API URL","api_url","string","True","The URL pointing to the API endpoint exposing the service.","https://graph.microsoft.com/beta/"
    "Client id","client_id","string","True","Client id","*********"
    "Tenant id","tenant_id","string","True","tenant id",""
    "Client secret","client_secret","string","True","Client secret","**********"



Map EclecticIQ Platform entities to Microsoft Azure Sentinel Indicators
==================================================================================

When the outgoing feed runs, it looks through the selected dataset(s)
and collects entities that have one or more of the selected observable types
attached to them.
These entities are then translated into `tiIndicator objects`_
that we send to the target Azure Sentinel instance.

.. _tiIndicator objects: https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta

Each tiIndicators object only allows
an indicator to represent one observable.
This means that entities which have more than one attached
observable creates one indicator per observable
found in the dataset(s).

The following table describes how data from EclecticIQ Platform
is translated into a format that
the Azure Sentinel instance can ingest:

..  csv-table::
    :header-rows: 1
    :stub-columns: 1
    :delim: ;

    Field name;JSON field; From EclecticIQ JSON; Description; Example
    Action;``action``; N/A; Default for tiIndicator object. ; ``alert``
    Target Product;``targetProduct``; N/A; Default for tiIndicator object.; ``Azure Sentinel``
    External ID;``externalId``; ``data.id``; ID of EclecticIQ entity. ; ``{http://example.com/}Indicator-611935aa-4db5-4b63-88ac-ac651634f09b``
    Description;``description``;``Entity from EclecticIQ Platform. <data.title>``;Indicator description containing title of packaged EclecticIQ entity. ; ``Entity from EclecticIQ Platform. example.com``
    TLP Level;``tlpLevel``; See `TLP mapping table <#table-tlp>`_.;"--";``amber``
    Confidence;``confidence``; See `Confidence mapping table <#table-confidence>`_.;"--";``100``
    Severity;``severity``; See `Maliciousness mapping table <#table-maliciousness>`_.;"--";``5``
    Threat Type;``threatType``; See `Indicator type mapping table <#table-indicator-type>`_.;"--"; ``Proxy``
    Expiration;``expirationDateTime``; ``meta.estimated_threat_start_time + meta.half_life``; Date and time when entity or observable half-life expires. ; ``2020-04-29T07:41:21.9273279Z``
    Last Reported;``lastReportedDateTime``; ``meta.estimated_observed_time``; Date and time indicator was observed. ; ``2020-04-29T07:41:21.9273279Z``
    Tags;``tags``; ``meta.tags[n]``; See `Tag mapping table <#table-tag>`_. ;"``['tag name 1','tag name 2','tag name 3']``"
    Kill Chain;``killChain``; ``if meta.taxonomy_paths[n][n] contains 'Kill chain -'``;"Derive kill chain phase name from tags; See also `Tag mapping table <#table-tag>`_.";"Reconnaissance"
    File Hash Type;``fileHashType``; See `File hash type table <#table-hash-type>`_.;"If indicator has a file hash, get type of file hash here."; ``md5``
    Network Source ASN;``networkSourceAsn``; ``extracts[n].value if extracts[n].kind=='asn'``;"If indicator has an ASN, set ASN value here."; ``3265``
    Domain Name;``domainName``; ``extracts[n].value if extracts[n].kind=='domain'``;"If indicator has a domain, set domain name here."; ``example.com``
    Email Sender Address;``emailSenderAddress``; ``extracts[n].value if extracts[n].kind=='email'``;"If indicator has an email address, set email address name here."; ``user@mail.example.com``
    Email Source Domain;``emailSourceDomain``; Extract domain from ``emailSenderAddress``;"If indicator has an email address, derive domain from email address."; ``mail.example.com``
    Email Subject;``emailSubject``; ``extracts[n].value if extracts[n].kind=='email-subject'``;"If indicator has an email subject, set email subject."; ``RE: FWD: Example email subject``
    File Name;``fileName``; ``extracts[n].value if extracts[n].kind=='file'``;"If indicator has a file, set file name here."; ``example.docx.exe``
    File Hash Value;``fileHashValue``;"``extracts[n].value`` if ``extracts[n].kind`` has a `file hash type <#table-hash-type>`_";"If indicator has a file hash type, set value of file hash here."; ``0c089b611e8a72f025164c29ddef09e2905cf3c8``
    Network IPv4;``networkIPv4``; ``extracts[n].value if extracts[n].kind=='ipv4'``;"If indicator has an IPv4 address, set value of IPv4 address here."; ``127.0.0.1``
    Network IPv6;``networkIPv6``; ``extracts[n].value if extracts[n].kind=='ipv6'``;"If indicator has an IPv6 address, set value of IPv6 address here."; ``::1``
    File Mutex Name;``fileMutexName``; ``extracts[n].value if extracts[n].kind=='mutex'``;"If indicator has a named mutex, set name of mutex here."; ``FwtSqmSession123456789_S-1-5-20``
    Network Port;``networkPort``; ``extracts[n].value if extracts[n].kind=='port'``;"If indicator has a port, set value of port here."; ``8080``
    URL;``url``; ``extracts[n].value if extracts[n].kind=='uri'``;"If indicator has a URL or URI, set value of URL/URI here."; ``https://example.com/resource/path/here.html?=query``
    Is Active;``isActive``; N/A; Default for tiIndicator object. ; ``true``



Example outgoing feed JSON submission
--------------------------------------

Where:

- ``EIQ_ENTITY_ID`` is an EclecticIQ Platform entity identifier
  in the format: ``<EclecticIQ_Platform_URL><entity_type>-<uuid>``

  For example: ``{https://tip.example.com}indicator-14975dea-86cd-4211-a5f8-9c2e4daab69a``
- ``EIQ_OBSERVABLE_ID`` is an EclecticIQ Platform observable identifier
  in the format ``<observable_type>:<observable_value>``

  For example: ``email:user@example.com``


..  code-block::

    $EIQ_ENTITY_ID: {
      $EIQ_OBSERVABLE_ID: {
        'action': 'value',
        'targetProduct': 'value',
        'externalId': 'value',
        'description': 'value',
        'tlpLevel': 'value',
        'confidence': 0,
        'severity': 0,
        'threatType': 'value',
        'expirationDateTime': 'value',
        'lastReportedDateTime': 'value',
        'tags': ['tag name', 'tag name 2'],
        'killChain': ['tag name', 'tag name 2'],
        'fileHashType': 'value',
        'networkSourceAsn': 'value',
        'domainName': 'value',
        'emailSenderAddress': 'value',
        'emailSourceDomain': 'value',
        'emailSubject': 'value',
        'fileName': 'value',
        'fileHashValue': 'value',
        'networkIPv4': 'value',
        'networkIPv6': 'value',
        'fileMutexName': 'value',
        'networkPort': 'value',
        'url': 'value',
        'isActive': true
      }
    }

Mapping tables
----------------------------------------------------------------------

Some field values in EclecticIQ Platform must be
translated to match the values that Azure Sentinel expects
when we submit an indicator using the outgoing feed.

For example, a `confidence value <#table-confidence>`_
of ``High`` in
an EclecticIQ Platform entity
is translated to ``100``
when the entity is submitted as a
Microsoft Azure Sentinel indicator.


..  contents:: List of mapping tables:
    :local:

.. |eiq| replace:: EclecticIQ
.. |sentinel| replace:: Azure Sentinel


.. _table-tlp:

Map |eiq| entity TLP values to |sentinel| indicator TLP values
________________________________________________________________________

..  csv-table::
    :header-rows: 1

    "", |eiq| Platform field, |sentinel| field
    Field name, """TLP Color""", """TLP Level"""
    JSON field, ``meta.tlp_color``, ``value[n].tlpLevel``

..  csv-table::
    :header-rows: 1

    Description, |eiq| TLP, |sentinel| indicator TLP
    TLP White,``White``, ``white``
    TLP Green,``Green``,	``green``
    TLP Amber,``Amber``, ``amber``
    TLP Red,``Red``,	``red``

..
    specs show default of tlp unknown, but doesn't seem
    to be the case in the code?
    TLP Unknown (default),``Unknown``, ``unknown``

.. _table-confidence:

Map |eiq| entity confidence values to |sentinel| indicator confidence values
________________________________________________________________________________

..  csv-table::
    :header-rows: 1

    "", |eiq| Platform field, |sentinel| field
    Field name, """Confidence""", """Confidence"""
    JSON field, ``data.confidence.value``, ``value[n].confidence``

..  csv-table::
    :header-rows: 1

    Description, |eiq| confidence, |sentinel| indicator confidence
    No set confidence level (default), ``None``, ``0``
    Low confidence, ``Low``, ``33``
    Medium confidence, ``Medium``, ``66``
    High confidence, ``High``, ``100``

.. _table-maliciousness:

Map |eiq| observable maliciousness values to |sentinel| indicator maliciousness values
___________________________________________________________________________________________________

..  csv-table::
    :header-rows: 1

    "", |eiq| Platform field, |sentinel| field
    Field name, """Maliciousness""", """Severity"""
    JSON field, "``extracts[n]meta.classification`` and ``extracts[n].meta.confidence``", ``value[n].severity``

..  csv-table::
    :header-rows: 1

    Description, |eiq| maliciousness, |sentinel| indicator maliciousness
    Safe (default), Safe, ``0``
    Low maliciousness, Low, ``1``
    Medium maliciousness, Medium, ``3``
    High maliciousness, High, ``5``

.. _table-indicator-type:

Map |eiq| indicator type values to |sentinel| indicator type values
________________________________________________________________________

..  csv-table::
    :header-rows: 1

    "", |eiq| Platform field, |sentinel| field
    Field name, """Types""", """Threat Type"""
    JSON field, ``data.types[n].value``, ``value[n].threatType``

..  csv-table::
    :header-rows: 1

    Description, |eiq| indicator types, |sentinel| indicator types
    Malicious E-mail,``Malicious E-mail``, ``Phishing``
    IP Watchlist,``IP Watchlist``, ``WatchList``
    File Hash Watchlist,``File Hash Watchlist``, ``WatchList``
    Domain Watchlist,``Domain Watchlist``, ``WatchList``
    URL Watchlist,``URL Watchlist``, ``WatchList``
    Malware Artifacts,``Malware Artifacts``, ``Malware``
    C2,``C2``, ``C2``
    Anonymization,``Anonymization``, ``Proxy``
    Exfiltration,``Exfiltration``, ``WatchList``
    Host Characteristics,``Host Characteristics``, ``WatchList``
    Compromised PKI Certificate,``Compromised PKI Certificate``, ``WatchList``
    Login Name,``Login Name``, ``WatchList``
    IMEI Watchlist,``IMEI Watchlist``, ``WatchList``
    IMSI Watchlist,``IMSI Watchlist``, ``WatchList``

.. _table-hash-type:

Map |eiq| observable type (hash) to |sentinel| indicator hash type
________________________________________________________________________

..  csv-table::
    :header-rows: 1

    "", |eiq| Platform field, |sentinel| field
    Field name, """Type""", """File Hash Type"""
    JSON field, ``extracts[n].kind``, ``value[n].fileHashType``

..  csv-table:: 
    :header-rows: 1

    Description, |eiq| hash type, |sentinel| indicator hash type
    MD5 hash,``hash-md5``, ``md5``
    SHA1 hash,``hash-sha1``, ``sha1``
    SHA256 hash,``hash-sha256``, ``sha256``

.. _table-tag:

Map |eiq| tag name to |sentinel| indicator tag name
________________________________________________________________________

..  csv-table::
    :header-rows: 1

    "", |eiq| Platform field, |sentinel| field
    Field name, """Tags""", """Tags"""
    JSON field, ``extracts[n].tags[n]``, ``value[n].tags[n]``

..  csv-table::
    :header-rows: 1

    Description, |eiq| indicator tag name, |sentinel| indicator tag name
    Actions on Objectives, ``Actions on Objectives``, ``Actions``
    Command and Control, ``Command and Control``, ``C2``
    Delivery, ``Delivery``, ``Delivery``
    Exploitation, ``Exploitation``, ``Exploitation``
    Installation, ``Installation``, ``Installation``
    Reconnaissance Artifacts, ``Reconnaissance Artifacts``, ``Reconnaissance``
    Weaponization, ``Weaponization``, ``Weaponization``

Supported observable types
============================

This outgoing feed supports the following observable types:

- ``email``
- ``email-subject``
- ``sha1``
- ``sha256``
- ``md5``
- ``mutex``
- ``file``
- ``domain``
- ``ipv4``
- ``ipv6``
- ``uri``
- ``port``
- ``asn``

Update strategies for Microsoft Azure Sentinel
===============================================================

The update strategy you set for the outgoing feed
determines how the extension updates indicators
that originate from that going feed
on your Azure Sentinel instance.

..  NOTE::

    Each observable type in the dataset
    creates one indicator
    for Azure Sentinel.

    If an observable is updated
    on EclecticIQ Platform,
    it is treated as a new indicator.

:REPLACE:
  The **REPLACE** update strategy removes
  all indicators that have been
  previously sent by the outgoing feed.
  Then, it uploads all indicators, old and new,
  to the Azure Sentinel instance.

  The feed does the following:

  #.  Gets all indicator IDs of
      entities with supported observables
      in the selected dataset(s).
  #.  Determines the indicator IDs that
      have been previously sent
      to the Azure Sentinel instance
      up to the last time the feed
      was run.
  #.  Deletes those indicators on
      the Azure Sentinel instance.
  #.  Updates the Azure Sentinel instance
      with all indicators from the dataset(s).


:APPEND:
  The **APPEND** update strategy only
  updates the Azure Sentinel instance
  with indicators that have been
  added to the dataset(s) since the
  last time the feed was run.

  It does not remove indicators
  from Azure Sentinel when entities
  or observables are removed from
  the selected dataset(s).

  The feed does the following:

  #.  Determines the indicator IDs
      for entities and observables
      that have been added to the
      dataset(s) since the last time
      the feed was run.
  #.  Updates the Azure Sentinel instance
      with the new indicators.

:DIFF:
  The **DIFF** update strategy
  determines the indicators
  that have been added and removed
  to the dataset(s)
  since the last time the feed was
  run. Then, on the Azure Sentinel instance,
  the feed adds the new indicators
  and deletes indicators that have
  been removed from the dataset(s).

  The feed does the following:

  #.  a.  Determines the indicator IDs
          for entities and observables
          that have been removed
          from the dataset(s)
          or have expired
          since the last time the feed was run.
      b.  Determines the indicator IDs
          of entities and observables
          that have been added to the
          dataset(s) since the last run.
  #.  Updates the Azure Sentinel instance
      with the new indicators.
  #.  Deletes indicators that have been
      removed from the dataset(s),
      or have expired.
