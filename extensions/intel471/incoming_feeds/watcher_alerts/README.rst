Incoming feed - |transport_type|
*******************************************************

.. |provider| replace:: Intel 471
.. |transport_type| replace:: |provider| Watcher Alerts
.. |content_type| replace:: |provider| Alert

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
      - Ingests alerts published by Watchers
        set up for the Intel 471 account.
    
    * - Processed data
      - Alerts are ingested as Report entitites
        on the platform, along with
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
      - Set this to the |provider| REST API endpoint.

        By default, this is set to
        ``https://api.intel471.com/v1``.

    * - API key\*
      - Set this to your |provider| API key.

    * - Email\*
      - Set this to the email address associated
        with your |provider| account. 

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
