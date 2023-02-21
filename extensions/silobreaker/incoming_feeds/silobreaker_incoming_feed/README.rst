Incoming feed - |provider|
***********************************

.. |provider| replace:: Silobreaker
.. |transport_type| replace:: |provider| API
.. |content_type| replace:: |provider| document JSON

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
      - This extension retrieves and ingests
        documents from your Silobreaker Online
        account that match the query you provide here.

    * - Processed data
      - Documents from your Silobreaker Online account are ingested
        as Collective Threat Intelligence reports on the platform.
    
    * - Description
      - Silobreaker is a threat intelligence platform
        that gathers documents from a variety of open sources,
        and allows you to query this data to organize
        this into intelligence you can use.
        
        This extension allows you to query the Silobreaker
        API and ingest the result as reports on the EclecticIQ Platform.

Requirements
================

- Silobreaker Online account
- Silobreaker API key and Shared key


Configuration options
==============================


..  list-table::
    :header-rows: 1
    :stub-columns: 1

    * - Field
      - Description
    
    * - Transport type\*
      - Select **Silobreaker API** from the drop-down menu.

    * - Content type\*
      - Select **Silobreaker document JSON** from the drop-down menu.

    * - API URL\*
      - Set this to the Silobreaker API endpoint.

        By default, this is set to
        ``https://api.silobreaker.com/search/documents``

    * - API key\*
      - Set this to your Silobreaker API key.

    * - Shared key\*
      - Set this to your Silobreaker Shared key.

    * - SSL verification
      - Selected by default.
        Select this option to enable SSL for this feed.

    * - Path to SSL certificate file.
      - Used when connecting to a feed
        source that uses a custom CA.
        Set this as the path to the SSL certificate
        to use when authenticating the feed source.

    * - Query\*
      - Enter a query to retrieve documents from
        your Silobreaker Online account.

        For more information on the Silobreaker query syntax,
        see the official `Silobreaker search documentation`_.

    * - Start ingesting from\*
      - Ingest data from the feed source
        starting from this date and time.
        Use the drop-down calendar to select the date
        and time you want to start ingesting feed data from.

.. _Silobreaker search documentation: https://my.silobreaker.com/Help-v2/basics/searching/
