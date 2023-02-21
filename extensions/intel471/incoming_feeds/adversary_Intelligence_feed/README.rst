Incoming feed - |transport_type|
*******************************************************

.. |provider| replace:: Intel 471
.. |transport_type| replace:: |provider| Adversary Intelligence Feed
.. |content_type| replace:: |provider|

..  list-table::
    :header-rows: 1
    :stub-columns: 1
    :align: left

    * -
      - Specifications
    
    * - Transport types
      - |transport_type|

    * - Content type
      - |content_type|
    
    * - Ingested data
      - Ingests threat actor reports from Intel 471
        and their associated indicators and TTPs
        (Tactics, Techniques, and Procedures).
    
    * - Processed data
      - * The reports from Intel 471 are ingested
          on the platform as
          Report entities of "Threat Report" type,
          along with associated observables.
        * Where specific threat actor profiles
          are available, they are ingested
          as Threat Actor entities along with
          associated observables.

Requirements
================

- Email address registered with |provider|.
- |provider| API key.

Configuration options
==============================

..  list-table::
    :header-rows: 1
    :stub-columns: 1
    :align: left

    * - Field
      - Description
    
    * - Transport type\*
      - Select |transport_type| from the drop-down menu.

    * - Content type\*
      - Select |content_type| from the drop-down menu.

    * - API URL\*
      - Set this to the Intel 471 REST API endpoint.

        By default, this is set to
        ``https://api.intel471.com/v1/``.

    * - API key\*
      - Set this to your Intel 471 API key.

    * - Email\*
      - Set this to the email address associated
        with your Intel 471 account. 

    * - SSL verification
      - Selected by default.
        Select this option to enable SSL for this feed.

    * - Path to SSL certificate file.
      - Used when connecting to a feed
        source that uses a custom CA.
        Set this as the path to the SSL certificate
        to use when authenticating the feed source.

    * - Start ingesting from\*
      - Ingest data from the feed source
        starting from this date and time.
        Use the drop-down calendar to select the date
        and time you want to start ingesting feed data from.

