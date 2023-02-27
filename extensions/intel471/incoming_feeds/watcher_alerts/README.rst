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


..  csv-table::
    :align: left
    :header-rows: 1
    :stub-columns: 1

    "title","name","type","required","description","default"
    "API URL","api_url","string","True","The URL pointing to the API endpoint exposing the service that makes the data available for retrieval through the feed.","https://api.intel471.com/v1/"
    "API Key","api_key","string","True","API Key","***"
    "email","email","string","True","email","***@***.****"


