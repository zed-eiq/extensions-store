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

..  csv-table::
    :align: left
    :header-rows: 1
    :stub-columns: 1

    "title","name","type","required","description","default"
    "API URL","api_url","string","True","The URL pointing to the API endpoint exposing the service that makes the data available for retrieval through the feed.","https://api.intel471.com/v1/"
    "API Key","api_key","password","True","API Key","***"
    "email","email","string","True","email","***@***.****"


