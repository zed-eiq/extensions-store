Enricher - |enricher_name|
****************************

.. |provider| replace:: Intel 471
.. |enricher_name| replace:: |provider| Posts Enricher

..  list-table::
    :header-rows: 1
    :stub-columns: 1
    :align: left

    * -
      - Specifications

    * - Enricher name
      - |enricher_name|

    * - Supported observable types
      - * ``actor-id``
        * ``name``

    * - Output
      - Report entity named "Intel 471 Forum Posts - <enriched_observable>",
        with associated observables.

    * - API endpoint
      - * ``https://api.intel471.com/v1/posts``
        * ``https://api.intel471.com/v1/posts?actor=<actor_handle>```

    * - Description
      - This enricher looks up forum posts associated with
        the enriched observable using the |provider| ``posts``
        endpoint.

Requirements
================

- Email address registered with |provider|.
- |provider| API key.


Configuration options
============================================

..  csv-table::
    :align: left
    :header-rows: 1
    :stub-columns: 1

    "title","name","type","required","description","default"
    "API URL","api_url","string","True","The URL pointing to the API endpoint exposing the service that makes the data available for retrieval through the feed.","https://api.intel471.com/v1/"
    "API Key","api_key","string","True","API access key provided by Intel 471.","***"
    "email","email","string","True","A valid email address to be granted access to the Intel 471 API endpoint.","***@***.****"
    "Actor","actor","string","False","Place value here to lookup forum posts the actor has written.",""

Enrichment result
======================

When the |provider| enricher is applied to an
observable, it attaches a **Intel 471 Forum Post**
Report entity to the enriched observable.

Attached to the Report entity are associated observables
extracted from the retrieved forum posts.


