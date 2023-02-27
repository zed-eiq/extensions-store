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


