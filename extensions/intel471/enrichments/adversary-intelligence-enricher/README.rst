Enricher - |enricher_name|
****************************

.. |provider| replace:: Intel 471
.. |enricher_name| replace:: |provider| Adversary Intelligence Enricher

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
        * ``handle``
        * ``name``

    * - Output
      - Enriching an obervable looks up information
        associated with the ``actor-id``, ``handle``,
        or ``name`` being enriched and attaches that
        information to the enriched observable
        as new observables.

    * - API endpoint
      - * ``https://api.intel471.com/v1/actors?actor=<enriched_observable>```

    * - Description
      - This enricher looks up information associated with threat actors
        on the |provider| Adversary Intelligence database.

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


Enrichment result
======================

When the |provider| enricher is applied to an
observable, it attaches new observables
extracted from the results returned from the
|provider| Adversary Intelligence database, such as:

- ``domain``
- ``email``
- ``forum-name``
- ``actor-id``
- ``handle``
- If the results include contact information
  for the threat actor, the following observables
  are created:

  ..  list-table::
      :header-rows: 1
      :stub-columns: 1
      :align: left

      * - Type
        - Ingested result

      * - ICQ handles
        - ``handle`` observables named: ``icq|<handle_name>``
      * - Jabber handles
        - ``handle`` observables named: ``jabber|<handle_name>``
      * - MSN handles
        - Treated as ``email`` observables.
      * - YahooIM handles
        - ``handle`` observables named: ``yahoo|<handle_name>``
      * - AIM handles
        - ``handle`` observables named: ``aim|<handle_name>``
      * - Skype handles
        - ``handle`` observables named: ``skype|<handle_name>``
      * - BitcoinWalletID handles
        - Treated as ``bank-account`` observables.
