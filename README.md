# EclecticIQ Extensions Store

## Overview

This repo contains Extensions created by EclecticIQ, our partners and customer to collect, enrich and dissemenate threat intelligence.

All Extensions in this repository are designed to be executed and run on the EclecticIQ Extensions Developer Kit.

The EclecticIQ Extensions Developer Kit is not tied to any EclecticIQ product and therefore extensions in this repository can be used with any upstream or downstream tools (SIEM's, SOAR's, TIP's, etc.).

## Structure of this repository

The Extensions in this repository are organised in the following directory structure:

* extensions
  * `<VENDOR NAME>`
    * incoming_feeds
      * `<EXTENSION NAME>`
        * `<EXTENSION FILES / DOCS>`
    * outgoing_feeds
      * `...`
    * enrichments
      * `...`

## Types of Extensions

There are three types of Extensions in this repository:

* Incoming Feeds: ingest cyber threat intelligence made available in multiple formats.
You can configure incoming feeds to retrieve cyber threat data from many different sources.
* Outgoing Feeds: used to publish cyber threat intelligence to instrument external tools and devices, and to share intelligence with selected recipients within the organization, as well as with external third-parties. Outgoing feeds are a powerful tool to disseminate intelligence and to promote constructive collaboration, as well as to programmatically act on intelligence by automating tasks in your security toolchain.
* Enrichers: Enrichment augments existing cyber threat intelligence value by adding contextual information.
Enrichers use rules and tasks to automatically enrich data, so that you can explore a broader and more granular cyber threat intelligence landscape.

## Support of Extensions

Inside the root of each Extensions you will find a `manifest.json` document.

This documents the following three properties that define who to contact for support of the Extension;

* `support_name`: this field is a name of the developer responsible for supporting the Extension. For EclecticIQ supported Extensions this will be equal to `EclecticIQ`
* `support_email`: this field is an email address of the developer responsible for supporting the Extension. For EclecticIQ supported Extensions this will be equal to `support@eclecticiq.com`.
* `eclecticiq_verified` (boolean): if set to `TRUE`, this means EclecticIQ have tested the Extension against our security and performace standards. It DOES NOT mean that is is supported by EIQ (see `support_*` fields).

## Documentation

If you wish to learn more about how to develop Extensions, please read our EDK Guide.

## Submission of new Extensions

### Suggestions for new Extensions

If you would like to suggest a new Extension to be built by the EclecticIQ team, you can raise a new Issue here](https://github.com/eclecticiq/edk-extensions).

Please include a detailed overview of what the Extension will do, how it will work, any authentication requirements to access or send data, and how to map the data into STIX 2.1 (if required).

Each submitted Extension will be periodically reviewed, however, not all submissions are guaranteed to ever make the roadmap. In which case, you also have the option to build it yourself.

### Build your own

In addition to EclecticIQ contributions we welcome submissions of new Extensions from our partners and developers.

For instructions about adding/modifying content please see our Extensions Contribution Guide.

## License

All Extensions, including user contributed Extensions, are made available under an [MIT license](/LICENSE).
