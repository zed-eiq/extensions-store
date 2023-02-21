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


..  list-table::
    :header-rows: 1
    :stub-columns: 1

    * - Field
      - Description

    * - API key\*
      - Set this to your |provider| API key.

    * - Email\*
      - Set this to the email address associated
        with your |provider| account.



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
