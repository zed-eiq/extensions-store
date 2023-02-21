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

..  list-table::
    :header-rows: 1
    :stub-columns: 1
    :align: left

    * - Field
      - Description

    * - API key\*
      - Set this to your |provider| API key.

    * - Email\*
      - Set this to the email address associated
        with your |provider| account.

    * - Actor
      - Enter a known ``handle``
        of an actor to retrieve only records of forum posts
        associated with that handle.


Enrichment result
======================

When the |provider| enricher is applied to an
observable, it attaches a **Intel 471 Forum Post**
Report entity to the enriched observable.

Attached to the Report entity are associated observables
extracted from the retrieved forum posts.


