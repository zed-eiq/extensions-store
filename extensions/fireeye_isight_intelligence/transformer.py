import datetime
import re
import uuid
import xml.sax.saxutils  # nosec
from typing import List, Optional
from marshmallow import ValidationError
from dev_kit.eiq_edk.schemas.entities import ExtractType
from eiq_edk.schemas.entities import (ProducerSchema,IndicatorDataSchema,
                                      ReportDataSchema,ThreatActorDataSchema,
                                      TTPDataSchema, ExtractSchema, EntitySchema,
                                      ObservableObjectSchema, ObservableSchema)


BAD_FILENAMES = ["unavailable", "unknown", "(none)"]
INDICATOR_DESCRIPTION = {
    "Attacker": "This indicator has been confirmed hosting malicious content "
    "and has functioned as a command and control (C2) server, "
    "and/or otherwise acted as a source of malicious activity.",
    "Compromised": "This indicator has been confirmed to host malicious "
    "content due to compromise or abuse. The exact time and "
    "length of compromise is unknown unless disclosed within the report.",
    "Related": "This indicator is likely related to an attack but has only "
    "been partially confirmed. It has been detailed by one or "
    "more methods, like passive DNS, geo-location and connectivity detection.",
}

"""
Transformer for FireEye Report version 2.5
https://docs.fireeye.com/iSight/index.html#/report_index
"""


def transform_reports(report: dict) -> dict:
    entities = []
    relations = []

    if report["intelligenceType"] == "vulnerability":
        entities.append(create_vulnerability_report(report))

    elif report["intelligenceType"] == "overview":
        process_overview(report, entities, relations)

    elif report["intelligenceType"] in ["malware", "threat"]:
        main_section = process_malware_main_section(report)

        if report["intelligenceType"] == "malware":
            entities.append(
                create_malware_report(
                    report,
                    main_section["extracts"],
                    main_section["tags"] + main_section["report_tags"],
                    main_section["countries_block"],
                )
            )

        else:
            entities.append(
                create_threat_report(
                    report,
                    main_section["extracts"],
                    main_section["tags"] + main_section["report_tags"],
                    main_section["countries_block"],
                )
            )
            process_threat_actors(report, entities, relations, main_section["tags"])

        for fun in [
            process_malware_files,
            process_malware_networks,
            process_malware_emails,
        ]:

            fun(report, entities, relations, main_section["tags"])

    return {"type": "linked-entities", "entities": entities, "relations": relations}


# VULNERABILITY


def create_vulnerability_report(report: dict) -> dict:
    publish_date = parse_published_date(report)
    discovered_date = (
        datetime.datetime.strptime(
            report["dateOfDisclosure"], "%B %d, %Y %I:%M:%S %p"
        ).isoformat()
        if "dateOfDisclosure" in report
        else publish_date
    )

    references = []
    for source in report.get("sourceSection", dict()).get("source", []):
        for url in source["urls"].get("url", []):
            if url:
                references.append(url)

    extracts = report.get("extracts", [])
    for item in report.get("cveIds", dict()).get("cveId", []):
        add_extract(
            extracts, ExtractType.CVE.value, item.replace("CVE-", ""), classification="safe"
        )

    recomendations = report.get("mitigationDetails", "") + report.get("vendorFix", "")
    for item in report.get("vendorFixUrls", dict()).get("vendorFixUrl", []):
        if item.get("name"):
            if item.get("url"):
                recomendations += f"<p><a href=\"{item['url']}\">{item['name']}</a></p>"
            else:
                recomendations += f"<p>{item['name']}</p>"
        if item.get("url"):
            references.append(item["url"])
    if recomendations:
        recomendations = (
            f'<section itemscope itemtype="http://eclecticiq.com/microdata/section">'
            f'<h1 itemprop="title">Recommendations</h1>'
            f'<div itemprop="content">{recomendations}</div>'
            f"</section>"
        )
    description = (
        f"{report.get('summary', '')}"
        f"<br>>{report.get('vulnerableProducts', '')}<br>{recomendations}"
    )
    tags = [
        f"Mitigation - {item}"
        for item in report.get("mitigations", dict()).get("mitigation", [])
    ]
    return create_report(
        create_fireeye_report_uuid(report),
        report.get("title") or "Untitled",
        timestamp=publish_date,
        description=description,
        information_source=create_fireeye_info_source(
            references=references, role="Aggregator"
        ),
        summary=report.get("execSummary", ""),
        tags=tags,
        extracts=extracts,
        threat_start_time=publish_date,
        observed_time=discovered_date,
        attachments=[report["attachment"]] if report.get("attachment") else [],
    )

def parse_published_date(report: dict) -> str:
    # just in case sometimes we don't receive publishDate,
    # set the default date to today (it actually never happened before)
    publish_date = datetime.datetime.utcnow().isoformat()
    if report.get("publishDate"):
        publish_date = datetime.datetime.strptime(
            report["publishDate"], "%B %d, %Y %I:%M:%S %p"
        ).isoformat()
    return publish_date


def add_extract(extracts, kind, value, classification='unknown', maliciousness=None):
    try:
        extract = ExtractSchema().load({
            'kind' : kind,
            'value' : value,
        })
        extract['classification'] = classification
        if extract:
            extracts.append(extract)
    except:
        pass


def create_fireeye_report_uuid(report: dict) -> str:
    return "{{https://api.isightpartners.com/}}Report-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, report.get("reportId")))
    )


def create_fireeye_info_source(references: list = [], role: str = '') -> dict:
    role = role or "Initial Author"

    producer = ProducerSchema().load({
        'identity' :"FireEye iSIGHT Intelligence Report API",
        'description' : "https://api.isightpartners.com",
        'references' : references,
        'roles' : [role]
    })
    return  producer

def create_report(stix_id: str,
    title: str,
    description: str = '',
    short_description: str = None,
    information_source: dict = {},
    observed_time: str = '',
    threat_start_time: str = '',
    threat_end_time: str = '',
    timestamp: str = '',
    extracts: list = [],
    tags: list = [],
    summary: str = '',
    intents: list = [],
    extraction_ignore_paths: list = [],
    attachments: list = [],
    tlp_color: str = 'NONE',
    half_life: int = 1,
    observable: list = None,
    taxonomy: list = [],
    taxonomy_paths: list = None,
    relationship: str = None,
    attacks: list = []):

    meta_part = {
    'estimated_observed_time' : observed_time,
    'estimated_threat_start_time' : threat_start_time,
    'estimated_threat_end_time' : threat_end_time,
    'half_life' : half_life,
    'tags' : tags,
    'taxonomy' : taxonomy,
    'attack' : attacks,
    'tlp_color' : tlp_color,
    'bundled_extracts' : extracts,
    'extraction_ignore_paths' : extraction_ignore_paths
    }

    report_part = {
        "id": stix_id,
        "title": title,
        "type": "report",
        'description': description,
        'short_description': summary,
        'producer': information_source,
        'timestamp': timestamp,
        'intents' : intents
    }


    retrun_data = EntitySchema().load({
        'data' : report_part,
        'meta' : meta_part,
        'attachments' : attachments
    })

    return retrun_data


#Overview

def process_overview(report: dict, entities: List[dict], relations: List[dict]):
    publish_date = parse_published_date(report)

    if report.get("reportType") == "Malware Overview":
        main_section = report.get("tagSection", dict()).get("main", dict())
        operating_systems = main_section.get("operatingSystems", dict()).get(
            "operatingSystem", []
        )
        oss = [f"Operating System - {os}" for os in operating_systems if os]
        roles = [
            OVERVIEW_MALWARE_TYPES.get(item, item)
            for item in main_section.get("roles", dict()).get("role", [])
        ]
        tags = oss + roles

        entities.append(create_malware_overview_report(report, publish_date, tags))

    elif report.get("reportType") == "Actor Overview":
        entities.append(create_actor_overview_report(report, publish_date))
        actors = create_actor_overview_actors(report, publish_date)
        for index, actor in enumerate(actors):
            entities.append(actor)
            relations.append(
                {
                    "data": {
                        "source": 0,
                        "target": index + 1,
                        "key": "ttps",
                        "source_type": "report",
                        "target_type": "ttp",
                        "type": "relation",
                    }
                }
            )

def create_malware_overview_report(
        report: dict, publish_date: str, tags: List[str]
) -> dict:
    return create_report(
        create_fireeye_report_uuid(report),
        report.get("title") or "Untitled",
        description=report.get("threatDescription"),
        timestamp=publish_date,
        information_source=create_fireeye_info_source(),
        tags=[item for item in tags if item],
        observed_time=publish_date,
        threat_start_time=publish_date,
        extracts=report.get("extracts", []),
        attachments=[report["attachment"]] if report.get("attachment") else [],
    )

def create_actor_overview_report(report: dict, publish_date: str) -> dict:
    return create_report(
        create_fireeye_report_uuid(report),
        report.get("title") or "Untitled",
        description=report.get("threatDescription"),
        timestamp=publish_date,
        information_source=create_fireeye_info_source(),
        observed_time=publish_date,
        threat_start_time=publish_date,
        extracts=report.get("extracts", []),
        attachments=[report["attachment"]] if report.get("attachment") else [],
    )

def create_actor_overview_actors(report: dict, publish_date: str) -> List[dict]:
    results = []
    main_section = report.get("tagSection", dict()).get("main", dict())
    for actor in main_section.get("actors", dict()).get("actor", []):
        if not actor or not actor.get("name"):
            continue
        actor_title = "Intrusion Set: {}".format(actor["name"])
        uid = str(uuid.uuid5(uuid.NAMESPACE_X500, actor_title))
        _id = f"{{https://api.isightpartners.com/}}threat-actor-{uid}"

        threat_actor ={
            "id": _id,
            "title": actor_title,
            "type": "threat-actor",
            'producer' : create_fireeye_info_source(),
            'description': report.get("threatDescription"),
            'identity': actor['name'],
            'timestamp': publish_date,
        }
        meta = {
            'estimated_observed_time' : publish_date,
            'estimated_threat_start_time' : publish_date,
        }

        entity_data = EntitySchema().load({
            'data': threat_actor,
            'meta' : meta
        })
        results.append(entity_data)
    return results


#Overview

def process_malware_main_section(report: dict):
    extracts = []
    tags = []
    report_tags = []
    countries_block = ""

    main_section = report.get("tagSection", dict()).get("main")
    if main_section:
        countries = ", ".join(
            main_section.get("targetGeographies", dict()).get("targetGeography", [])
        )
        if countries:
            countries_block = f"<div>Countries: {countries}</div>"

        tags_data = [
            ("affectedSystems", "affectedSystem"),
            ("affectedIndustries", "affectedIndustry"),
            ("targetedInformations", "targetedInformation"),
            ("intendedEffects", "intendedEffect"),
            ("motivations", "motivation"),
        ]

        for parent, child in tags_data:
            for tag in main_section.get(parent, dict()).get(child, []):
                tags.extend(TAGS[parent].get(tag or "bogus", []))

        for ttp in main_section.get("ttps", dict()).get("ttp", []):
            report_tags.extend(TAGS["ttps"].get(ttp or "bogus", []))

        for malware in main_section.get("malwareFamilies", dict()).get(
                "malwareFamily", []
        ):
            if malware and malware.get("name"):
                tags.append(f"Malware: {malware.get('name')}")

    return {
        "extracts": extracts,
        "tags": tags,
        "report_tags": report_tags,
        "countries_block": countries_block,
    }

# MALWARE


def create_malware_report(
    report: dict, extracts: List[dict], tags: List[str], countries_block: str
) -> dict:
    publish_date = parse_published_date(report)
    return create_report(
        create_fireeye_report_uuid(report),
        report.get("title") or "Untitled",
        timestamp=publish_date,
        description=report.get("analysis", "") + countries_block,
        information_source=create_fireeye_info_source(),
        summary=report.get("execSummary", ""),
        tags=tags,
        extracts=extracts + report.get("extracts", []),
        threat_start_time=publish_date,
        observed_time=publish_date,
        attachments=[report["attachment"]] if report.get("attachment") else [],
    )


def process_malware_files(
    report: dict, entities: List[dict], relations: List[dict], tags: List[str]
):
    if (
         report.get("tagSection")
        or  report["tagSection"].get("files")
        or  report["tagSection"]["files"].get("file")
    ):

        return process_indicators(report, tags, entities, relations, "file")


def process_malware_networks(
    report: dict, entities: List[dict], relations: List[dict], tags: List[str]
):
    if (
         report.get("tagSection")
        or  report["tagSection"].get("networks")
        or  report["tagSection"]["networks"].get("network")
    ):
        return process_indicators(report, tags, entities, relations, "network")


def process_malware_emails(
    report: dict, entities: List[dict], relations: List[dict], tags: List[str]
):
    if (
         report.get("tagSection")
        or  report["tagSection"].get("emails")
        or  report["tagSection"]["emails"].get("email")
    ):
        return process_indicators(report, tags, entities, relations, "email")


def process_indicators(
    report: dict,
    tags: List[str],
    entities: List[dict],
    relations: List[dict],
    section: str,
):

    publish_date = parse_published_date(report)
    confidence = determine_confidence(report.get("analysis", ""))
    data_keys = {
        "file": {
            "parent": "files",
            "child": "file",
            "indicator_function": create_file_indicator,
        },
        "network": {
            "parent": "networks",
            "child": "network",
            "indicator_function": create_network_indicator,
        },
        "email": {
            "parent": "emails",
            "child": "email",
            "indicator_function": create_email_indicator,
        },
    }
    parent = data_keys[section]["parent"]
    child = data_keys[section]["child"]
    data = {}

    data = report["tagSection"].get(parent, {}).get(child, {})

    for item in data:
        if item.get("identifier") == "Victim":
            add_targeted_victim(entities, relations, item, section, publish_date, tags)
            continue

        indicator_function = data_keys[section]["indicator_function"]
        indicator = indicator_function(report, item, publish_date, tags, confidence)
        add_or_merge_indicator(item, indicator, entities, relations)


def determine_confidence(analysis: str) -> str:
    if re.search("high confidence", analysis, re.IGNORECASE):
        return "High"
    elif re.search("medium confidence", analysis, re.IGNORECASE):
        return "Medium"
    elif re.search("low confidence", analysis, re.IGNORECASE):
        return "Low"
    else:
        return "Unknown"


def add_or_merge_indicator(
    item: dict, indicator: dict, entities: List[dict], relations: List[dict]
):
    if not indicator:
        return

    for entity in entities:
        if (
            entity["data"]["type"] != "indicator"
            or entity["data"]["id"] != indicator["data"]["id"]
        ):
            continue
        # if indicators' stix ids are the same, then merge them, because they won't
        # get de-duplicated and that will cause more trouble (EIQ-4240)
        merge_extracts(entity, indicator)
        merge_types(entity, indicator)
        entity["data"]["description"] = create_indicator_description(
            item, current_description=entity["data"]["description"]
        )
        return

    # if the new indicator is not merged, then add it to the list
    entities.append(indicator)
    relations.append(
        {
            "data": {
                "source": 0,
                "target": len(entities) - 1,
                "key": "indicators",
                "source_type": "report",
                "target_type": "indicator",
                "type": "relation",
            }
        }
    )


def merge_extracts(entity: dict, indicator: dict):
    entity_extracts = [
        (extract["kind"], extract["value"])
        for extract in entity["meta"]["bundled_extracts"]
    ]
    for extract in indicator["meta"]["bundled_extracts"]:
        if (extract["kind"], extract["value"]) in entity_extracts:
            continue
        entity["meta"]["bundled_extracts"].append(extract)
        try:
            entity["data"]["observable"]["composition"].extend(
                create_observables([extract])
            )
        except:
            pass


def merge_types(existing_indicator: dict, indicator: dict):
    existing_types = [item["value"] for item in existing_indicator["data"]["types"]]
    for item in indicator["data"]["types"]:
        if item["value"] not in existing_types:
            existing_indicator["data"]["types"].append({"value": item["value"]})


def add_targeted_victim(
    entities: List[dict],
    relations: List[dict],
    item: dict,
    section: str,
    date: str,
    tags: List[str],
):
    if section == "file":
        victim_name = (
            item.get("md5")
            or item.get("sha1")
            or item.get("sha256")
            or item.get("fileName")
        )
    elif section == "network":
        victim_name = (
            item.get("domain")
            or item.get("ip")
            or item.get("url")
            or item.get("registrantEmail")
            or item.get("asn")
        )
    else:
        victim_name = item.get("senderAddress")

    if not victim_name:
        return

    title = f"Targeted Victim: {victim_name}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_X500, title))
    _id = f"{{https://api.isightpartners.com/}}TTP-{uid}"

    entities.append(
        create_ttp(
            title,
            _id,
            information_source=create_fireeye_info_source(),
            tags=tags or [],
            extraction_ignore_paths=["title", "behavior"],
            timestamp=date,
            observed_time=date,
            threat_start_time=date,
        )
    )
    relations.append(
        {
            "data": {
                "source": 0,
                "target": len(entities) - 1,
                "key": "ttps",
                "source_type": "report",
                "target_type": "ttp",
                "type": "relation",
            }
        }
    )


def create_ttp(
    stix_id: str,
    title: str,
    information_source: dict = {},
    description: str = '',
    observed_time: str = '',
    threat_start_time: str = '',
    threat_end_time: str = '',
    timestamp: str = '',
    extracts: list = [],
    tags: list = [],
    extraction_ignore_paths: list = [],
    tlp_color: str = 'NONE',
    half_life: int = 1,
    observable: list = None,
    taxonomy: list = [],
    taxonomy_paths: list = None,
    behaviour: dict = {},
    victim_targeting: dict = {},
    intended_effects: list = [],
    attacks: list = [],
) -> dict:

    meta_part = {
        'estimated_observed_time': observed_time,
        'estimated_threat_start_time': threat_start_time,
        'estimated_threat_end_time': threat_end_time,
        'half_life': half_life,
        'tags': tags,
        'taxonomy': taxonomy,
        'attack': attacks,
        'tlp_color': tlp_color,
        'bundled_extracts': extracts,
        'extraction_ignore_paths': extraction_ignore_paths
    }

    ttp_part = {
        "id": stix_id,
        "title": title,
        "type": "ttp",
        'description': description,
        'producer': information_source,
        'timestamp': timestamp,
        'behavior' : behaviour,
        'victim_targeting' : victim_targeting,
        'intended_effects' : intended_effects
    }

    retrun_data = EntitySchema().load({
        'data': ttp_part,
        'meta': meta_part,
    })

    return retrun_data


# THREAT


def create_threat_report(
    report: dict, extracts: List[dict], tags: List[str], countries_block: str
) -> dict:
    publish_date = parse_published_date(report)
    for cve in report.get("cveIds", dict()).get("cveId", []):
        add_extract(
            extracts, ExtractType.CVE, cve.replace("CVE-", ""), classification="safe"
        )
    return create_report(
        create_fireeye_report_uuid(report),
        report.get("title") or "Untitled",
        summary=report.get("execSummary", ""),
        description=report.get("threatDetail", "") + countries_block,
        timestamp=publish_date,
        information_source=create_fireeye_info_source(),
        observed_time=publish_date,
        threat_start_time=publish_date,
        tags=tags,
        extracts=extracts + report.get("extracts", []),
        attachments=[report["attachment"]] if report.get("attachment") else [],
    )


def process_threat_actors(
    report: dict, entities: List[dict], relations: List[dict], tags: List[str]
):
    main_section = report.get("tagSection", dict()).get("main")
    if main_section:
        publish_date = parse_published_date(report)
        for actor in create_threat_actors(main_section, publish_date, tags):
            entities.append(actor)
            relations.append(
                {
                    "data": {
                        "source": 0,
                        "target": len(entities) - 1,
                        "key": "threat_actors",
                        "source_type": "report",
                        "target_type": "threat-actor",
                        "type": "relation",
                    }
                }
            )

# COMMON
def create_file_indicator(
    report: dict,
    file: dict,
    publish_date: str,
    tags: List[str] = None,
    confidence: str = "High",
) -> Optional[dict]:
    extracts = []
    title = None
    tags = tags or []
    description = create_indicator_description(file)

    if file.get("md5"):
        title = file["md5"]
        add_extract(
            extracts,
            ExtractType.HASH_MD5.value,
            file["md5"],
            classification="high",
        )
    if file.get("sha1"):
        title = title or file["sha1"]
        add_extract(
            extracts,
            ExtractType.HASH_SHA1.value,
            file["sha1"],
            classification="high",
        )
    if file.get("sha256"):
        title = title or file["sha256"]
        add_extract(
            extracts,
            ExtractType.HASH_SHA256.value,
            file["sha256"],
            classification="high",
        )
    if file.get("fileName", "unknown").lower() not in BAD_FILENAMES:
        title = title or file["fileName"]
        add_extract(
            extracts,
            ExtractType.FILE.value,
            file["fileName"],
            classification="low",
        )
    if file.get("userAgent"):
        for user_agent in file["userAgent"]:
            add_extract(
                extracts,
                ExtractType.PRODUCT.value,
                user_agent,
            )

    if not title:
        return None

    return create_indicator(
        create_fireeye_indicator_uuid(report, title),
        title,
        description=description or title,
        confidence=confidence,
        observable=create_observables(extracts),
        types=["File Hash Watchlist"],
        information_source=create_fireeye_info_source(),
        timestamp=publish_date,
        observed_time=publish_date,
        threat_start_time=publish_date,
        extracts=extracts,
        tags=tags,
        extraction_ignore_paths=["title"],
    )


def create_network_indicator(  # noqa:C901
    report: dict,
    network: dict,
    publish_date: str,
    tags: List[str] = None,
    confidence: str = "High",
) -> Optional[dict]:
    extracts = []
    types = []
    title = None
    tags = tags or []
    description = create_indicator_description(network)

    if network.get("ip"):
        title = title or network["ip"]
        add_extract(
            extracts,
            ExtractType.IPV4.value,
            network["ip"],
            classification="high",
        )
        types.append("IP Watchlist")
    if network.get("cidr"):
        title = title or network["cidr"]
        add_extract(
            extracts,
            ExtractType.IPV4.value,
            network["cidr"],
            classification="high",
        )
    if network.get("domain"):
        title = title or network["domain"]
        add_extract(
            extracts,
            ExtractType.DOMAIN.value,
            network["domain"],
            classification="high",
        )
        types.append("Domain Watchlist")
    if network.get("url"):
        title = title or network["url"]
        add_extract(
            extracts,
            ExtractType.URI.value,
            network["url"],
            classification="high",
        )
        types.append( "URL Watchlist")
    if network.get("asn"):
        title = title or network["asn"]
        add_extract(extracts, ExtractType.ASN.value, network["asn"], classification="safe")
    if network.get("registrantEmail"):
        title = title or network["registrantEmail"]
        add_extract(extracts, ExtractType.EMAIL.value, network["registrantEmail"])
    if network.get("registrantName"):
        title = title or network["registrantName"]
        add_extract(extracts, ExtractType.NAME.value, network["registrantName"])
    if network.get("port"):
        add_extract(extracts, ExtractType.PORT.value, network["port"])

    if not title or not extracts:
        return None

    return create_indicator(
        create_fireeye_indicator_uuid(report, title),
        title,
        description=description or title,
        confidence=confidence,
        observable=create_observables(extracts),
        types=types,
        information_source=create_fireeye_info_source(),
        timestamp=publish_date,
        observed_time=publish_date,
        threat_start_time=publish_date,
        extracts=extracts,
        tags=tags,
        extraction_ignore_paths=["title"],
    )


def create_email_indicator(
    report: dict,
    email: dict,
    publish_date: str,
    tags: List[str] = None,
    confidence: str = "High",
) -> Optional[dict]:
    if not email.get("senderAddress"):
        return None

    tags = tags or []
    title = email.get("senderAddress")
    description = create_indicator_description(email)

    extracts = []
    add_extract(extracts, ExtractType.EMAIL.value, email.get("senderAddress"))
    if email.get("senderName"):
        add_extract(extracts, ExtractType.NAME.value, email["senderName"])
    if email.get("sourceDomain"):
        add_extract(
            extracts,
            ExtractType.DOMAIN.value,
            email["sourceDomain"],
            classification="low",
        )
    if email.get("sourceIp"):
        add_extract(
            extracts,
            ExtractType.IPV4.value,
            email["sourceIp"],
            classification="low",
        )

    return create_indicator(
        create_fireeye_indicator_uuid(report, title),
        title,
        description=description or title,
        timestamp=publish_date,
        confidence=confidence,
        observable=create_observables(extracts),
        types=[ "Malicious E-mail"],
        information_source=create_fireeye_info_source(),
        observed_time=publish_date,
        threat_start_time=publish_date,
        extracts=extracts,
        tags=tags,
        extraction_ignore_paths=["title"],
    )



def create_indicator(
    stix_id: str,
    title: str,
    description: str = '',
    information_source: dict = {},
    types: list = [],
    observed_time: str = '',
    threat_start_time: str = '',
    threat_end_time: str = '',
    confidence: dict = {},
    timestamp: str = '',
    extracts: list = [],
    tags: list = [],
    summary: str = '',
    extraction_ignore_paths: list = [],
    tlp_color: str = 'NONE',
    half_life: int = 1,
    observable: list = None,
    taxonomy: list = [],
    taxonomy_paths: list = None,
    likely_impact: str = 'Unknown',
    test_mechanisms: list = [],
    relationship: str = None,
    attacks: list = [],
) -> dict:


    indicator_schema = {
        "id": stix_id,
        "title": title,
        "type": "indicator",
        'description': description,
        'short_description': summary,
        'producer': information_source,
        'timestamp': timestamp,
        'types' : types,
        'likely_impact':likely_impact,
        'test_mechanisms' :test_mechanisms,
        'confidence':confidence,
    }
    meta_part = {
        'estimated_observed_time': observed_time,
        'estimated_threat_start_time': threat_start_time,
        'estimated_threat_end_time': threat_end_time,
        'half_life': half_life,
        'tags': tags,
        'taxonomy': taxonomy,
        'attack': attacks,
        'tlp_color': tlp_color,
        'bundled_extracts': extracts,
        'extraction_ignore_paths': extraction_ignore_paths
    }

    ret_data = EntitySchema().load({
       'data' : indicator_schema,
        'meta' : meta_part,
   })
    return ret_data

def make_confidence(confidence: str, description: str = None) -> dict:
    confidence = confidence.capitalize()
    if confidence not in ["Low", "Medium", "High"]:
        confidence = "Unknown"
    final_confidence = {
        "type": "confidence",
        "value": confidence,
        "value_vocab": "{http://stix.mitre.org/default_vocabularies-1}"
        "HighMediumLowVocab-1.0",
    }
    if description:
        final_confidence["description"] = description
    return final_confidence


def create_threat_actor(
    stix_id: str,
    title: str,
    description: str = '',
    information_source: dict = {},
    observed_time: str = '',
    threat_start_time: str = '',
    threat_end_time: str = '',
    confidence: dict = None,
    timestamp: str = '',
    extracts: list = [],
    tags: list = [],
    summary: str = '',
    extraction_ignore_paths: list = [],
    attachments : list = [],
    tlp_color: str = 'NONE',
    half_life: int = 1,
    observable: list = None,
    taxonomy: list = [],
    taxonomy_paths: list = None,
    motivations: list = [],
    actor_types: list = None,
    intended_effects: list = [],
    sophistication: list = [],
    actor_identity: str = 'kita',
    attacks: list = [],
) -> dict:
    data_threat_actor = {
        "id": stix_id,
        "title": title,
        "type": "threat-actor",
        'description': description,
        'short_description': summary,
        'producer': information_source,
        'identity' : actor_identity,
        'timestamp': timestamp,
        'intended_effects' : intended_effects,
        'motivations' : motivations,
        'sophistication' :sophistication,
    }
    meta_part = {
        'estimated_observed_time': observed_time,
        'estimated_threat_start_time': threat_start_time,
        'estimated_threat_end_time': threat_end_time,
        'half_life': half_life,
        'tags': tags,
        'taxonomy': taxonomy,
        'attack': attacks,
        'tlp_color': tlp_color,
        'bundled_extracts': extracts,
        'extraction_ignore_paths': extraction_ignore_paths
    }

    ret_data  = EntitySchema().load({
        'data' : data_threat_actor,
        'meta' : meta_part,
        'attachments' : attachments
    })

    return ret_data

def create_threat_actors(
        main_section: dict, publish_date: str, tags: List[str]
) -> List[dict]:
    if not main_section.get("actors", dict()).get("actor"):
        return []

    motivations = []
    if main_section.get("motivations", dict()).get("motivation"):
        motivations = create_actor_motivations(
            main_section["motivations"]["motivation"]
        )

    intended_effects = []
    if main_section.get("intendedEffects", dict()).get("intendedEffect"):
        intended_effects = create_actor_intended_effects(
            main_section["intendedEffects"]["intendedEffect"]
        )

    actors = []
    for actor in main_section["actors"]["actor"]:
        if not actor or not actor.get("name"):
            continue
        actor_title = "Intrusion Set: {}".format(actor["name"])
        id5 = str(uuid.uuid5(uuid.NAMESPACE_X500, actor_title))
        threat_actor = create_threat_actor(
            f"{{http://api.isightpartners.com/}}threat-actor-{id5}",
            actor_title,
            timestamp=publish_date,
            actor_identity=actor["name"],
            information_source=create_fireeye_info_source(),
            observed_time=publish_date,
            threat_start_time=publish_date,
            tags=tags,
        )
        if motivations:
            threat_actor["data"]["motivations"] = motivations
        if intended_effects:
            threat_actor["data"]["intended_effects"] = intended_effects

        actors.append(threat_actor)

    return actors

def create_actor_motivations(data: List) -> List[dict]:
    motivations = []
    for item in data:
        if not item:
            continue
        for motivation in THREAT_ACTOR_MOTIVATIONS.get(item, [item]):
            motivations.append(
                {
                    "type": "statement",
                    "value": motivation,
                    "value_vocab": (
                        "{http://stix.mitre.org/default_vocabularies-1}"
                        "MotivationVocab-1.1"
                    ),
                }
            )
    return motivations

def create_actor_intended_effects(data: List[str]) -> List[dict]:
    intended_effects = []
    for item in data:
        for intended_effect in THREAT_ACTOR_INTENDED_EFFECTS.get(item, [item]):
            intended_effects.append(
                {
                    "type": "statement",
                    "value": intended_effect,
                    "value_vocab": (
                        "{http://stix.mitre.org/default_vocabularies-1}"
                        "IntendedEffectVocab-1.0"
                    ),
                }
            )
    return intended_effects


def create_fireeye_indicator_uuid(report: dict, indicator: str) -> str:
    # de-duplicate indicators coming from different versions of the same report
    if report.get("title"):
        identifier = re.sub(
            r"\(\w\w\w \d+, \d\d\d\d\)", "", report.get("title")
        ).strip()
    else:
        identifier = report.get("reportId", "")
    return "{{https://api.isightpartners.com/}}Indicator-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, identifier + indicator))
    )

def create_indicator_description(indicator: dict, current_description: str = "") -> str:
    description_lines = []
    if current_description:
        description_lines.append(current_description)
    malware_text = (
        f"Malware: {indicator['malwareFamily']}"
        if indicator.get("malwareFamily")
        else ""
    )
    for text in [
        INDICATOR_DESCRIPTION.get(indicator.get("identifier")),
        indicator.get("description"),
        malware_text,
    ]:
        if text and text not in current_description:
            description_lines.append(text)
    return "\n\n".join(description_lines)

def create_observables(extracts: List[dict]) -> List[dict]:
    observables = []
    for extract in extracts:
        if extract and extract["kind"] in formats:
            observables.append(create_observable(extract["kind"], extract["value"]))
    return observables

def create_observable(kind: str, value: str) -> dict:

    observable_object = ObservableObjectSchema().load({
        "properties_xml": formats.get(kind).format(
            xml.sax.saxutils.escape(str(value).lower())
        ),
        "properties_xml_type": properties_xml_types.get(kind),
    })
    observable_schema = ObservableSchema().load({
        "object" : observable_object
    })
    return observable_schema

THREAT_ACTOR_MOTIVATIONS = {
    "Ego": ["Ego"],
    "Financial or Economic": ["Financial or Economic"],
    "Anti-Corruption/Anti-Establishment/Information Freedom": [
        "Ideological - Anti-Corruption",
        "Ideological - Anti-Establishment",
        "Ideological - Information Freedom",
    ],
    "Environmental": ["Ideological - Environmental"],
    "Ethnic/nationalist": ["Ideological - Ethnic / Nationalist"],
    "Ideological/Religious": ["Ideological - Religious"],
    "Military/Security/Diplomatic": ["Military", "Political"],
    "Opportunistic": ["Opportunistic"],
}

THREAT_ACTOR_INTENDED_EFFECTS = {
    "Military Advantage": ["Advantage - Military"],
    "Political Advantage": ["Advantage - Political"],
    "Competitive Advantage in Business or Economic Advantage": ["Advantage - Economic"],
    "IP or Business Information Theft": ["Theft - Intellectual Property"],
    "IP or Confidential Business Information Theft": ["Theft - Intellectual Property"],
    "Identity Theft": ["Theft - Identity Theft"],
    "Credential Theft/Account Takeover": ["Theft - Credential Theft"],
    "Financial Theft": ["Theft", "Advantage - Economic"],
    "Disruption": ["Disruption"],
    "Degradation": ["Degradation of Service"],
    "Denial and Deception": ["Denial and Deception"],
    "Destruction": ["Destruction"],
    "Embarrassment/Exposure/Brand Damage": [
        "Brand Damage",
        "Embarrassment",
        "Exposure",
    ],
    "Interference with ICS": ["ICS Control"],
}

TAGS = {
    "affectedSystems": {
        "Enterprise/Application Layer": [
            "Targeted Technology - Enterprise/Application Layer"
        ],
        "Enterprise/Database Layer": [
            "Targeted Technology - Enterprise/Database Layer"
        ],
        "Enterprise Technologies/Support Infrastructure": [
            "Targeted Technology - Enterprise Technologies/Support Infrastructure"
        ],
        "Enterprise/Network Systems": [
            "Targeted Technology - Enterprise/Network Systems"
        ],
        "Enterprise/Networking Devices": [
            "Targeted Technology - Enterprise/Networking Devices"
        ],
        "Mobile Systems/Mobile OS": ["Targeted Technology - Mobile Systems/Mobile OS"],
        "Mobile systems/Near Field Communications": [
            "Targeted Technology - Mobile systems/Near Field Communications"
        ],
        "Mobile Systems/Mobile devices": [
            "Targeted Technology - Mobile Systems/Mobile devices"
        ],
        "Third Party Services": ["Targeted Technology - Third Party Services"],
        "Users/Application and Software": [
            "Targeted Technology - Users/Application and Software"
        ],
        "Equipment Under Control": ["Targeted Technology - Control Systems"],
        "Equipment Under Control >> Actuators": [
            "Targeted Technology - Control Systems"
        ],
        "Equipment Under Control >> Sensors and Meters": [
            "Targeted Technology - Control Systems"
        ],
        "Equipment Under Control >> Valves": ["Targeted Technology - Control Systems"],
        "Operations Management": ["Targeted Technology - Control Systems"],
        "Operations Management >> Asset manager": [
            "Targeted Technology - Control Systems"
        ],
        "Operations Management >> Demand management System": [
            "Targeted Technology - Control Systems"
        ],
        "Operations Management >> Energy Management System": [
            "Targeted Technology - Control Systems"
        ],
        "Operations Management >> Geographic Information System": [
            "Targeted Technology - Control Systems"
        ],
        "Operations Management >> Global Positioning System": [
            "Targeted Technology - Control Systems"
        ],
        "Operations Management >> Load Management System": [
            "Targeted Technology - Control Systems"
        ],
        "Operations Management >> Outage Management System": [
            "Targeted Technology - Control Systems"
        ],
        "Safety Protection and Local Control": [
            "Targeted Technology - Control Systems"
        ],
        "Safety Protection and Local Control >> Flow Computer": [
            "Targeted Technology - Control Systems"
        ],
        "Safety Protection and Local Control >> "
        "Intelligent Electronic Device": ["Targeted Technology - Control Systems"],
        "Safety Protection and Local Control >> "
        "Programmable Automation Controller": ["Targeted Technology - Control Systems"],
        "Safety Protection and Local Control >> "
        "Programmable Logic Controller": ["Targeted Technology - Control Systems"],
        "Safety Protection and Local Control >> Protective Relay": [
            "Targeted Technology - Control Systems"
        ],
        "Safety Protection and Local Control >> Remote Terminal Units (RTUs)": [
            "Targeted Technology - Control Systems"
        ],
        "Safety Protection and Local Control >> Variable Frequency Drive": [
            "Targeted Technology - Control Systems"
        ],
        "Safety Protection and Local Control >> Safety Controller": [
            "Targeted Technology - Control Systems"
        ],
        "Supervisory Control": ["Targeted Technology - Control Systems"],
        "Supervisory Control >> SCADA/HMI": ["Targeted Technology - Control Systems"],
        "Supervisory Control >> Advanced Metering Infrastructure": [
            "Targeted Technology - Control Systems"
        ],
        "Supervisory Control >> Front-End Processor (Input/Output Server)": [
            "Targeted Technology - Control Systems"
        ],
        "Supervisory Control >> Historian Server": [
            "Targeted Technology - Control Systems"
        ],
        "Supervisory Control >> Master Terminal Unit": [
            "Targeted Technology - Control Systems"
        ],
        "Supervisory Control >> Meter management System": [
            "Targeted Technology - Control Systems"
        ],
        "Supervisory Control >> Phasor Data Concentrator": [
            "Targeted Technology - Control Systems"
        ],
        "Supervisory Control >> Engineering Workstation": [
            "Targeted Technology - Control Systems"
        ],
        "Supervisory Control >> Panel Based HMI": [
            "Targeted Technology - Control Systems"
        ],
        "Network Components": ["Targeted Technology - Network Components"],
        "Application Server": ["Targeted Technology - Application Server"],
        "Industrial Network Protocol": [
            "Targeted Technology - Industrial Network Protocol"
        ],
    },
    "affectedIndustries": {
        "Agriculture/Farming/Forestry/Paper": ["Industry Sector - Agriculture"],
        "Basic Materials/Chemicals/Mining/Metals": ["Industry Sector - Mining"],
        "Retail and Hospitality/Consumer": ["Industry Sector - Retail"],
        "Goods/Travel/Gaming/Food & Beverage": ["Industry Sector - Retail"],
        "Media/Entertainment/Publishing": ["Industry Sector - Media"],
        "Financial Services": ["Industry Sector - Financial Services"],
        "Financial Services >> Retail Banks/ATMs/Credit Cards": [
            "Industry Sector - Financial Services"
        ],
        "Financial Services >> Equity Management/Investment Banking": [
            "Industry Sector - Financial Services"
        ],
        "Financial Services >> Insurance (non-health insurance)": [
            "Industry Sector - Insurance"
        ],
        "Financial Services >> Real Estate": ["Industry Sector - Financial Services"],
        "Healthcare": ["Industry Sector - Healthcare"],
        "Healthcare >> Healthcare Equipment & Supplies": [
            "Industry Sector - Healthcare"
        ],
        "Healthcare >> Healthcare Providers (Hospitals)": [
            "Industry Sector - Healthcare"
        ],
        "Healthcare >> Health Insurance": ["Industry Sector - Insurance"],
        "Aerospace & Defense": [
            "Industry Sector - Aerospace",
            "Industry Sector - Defense",
        ],
        "Construction & Engineering": ["Industry Sector - Construction"],
        "Transportation/Industrial": ["Industry Sector - Automotive"],
        "Manufacturing/Automotive": ["Industry Sector - Automotive"],
        "Energy & Utilities": [
            "Industry Sector - Energy",
            "Industry Sector - Utilities",
        ],
        "Energy & Utilities >> Alternative Energy": [
            "Industry Sector - Energy",
            "Industry Sector - Utilities",
        ],
        "Energy & Utilities >> Energy Producers (Oil/Gas)": [
            "Industry Sector - Energy",
            "Industry Sector - Utilities",
        ],
        "Energy & Utilities >> Energy Services/Distribution": [
            "Industry Sector - Energy",
            "Industry Sector - Utilities",
        ],
        "Energy & Utilities >> Nuclear": [
            "Industry Sector - Energy",
            "Industry Sector - Utilities",
        ],
        "Energy & Utilities >> Electricity": [
            "Industry Sector - Energy",
            "Industry Sector - Utilities",
        ],
        "Energy & Utilities >> Utilities (Gas/Water)": [
            "Industry Sector - Energy",
            "Industry Sector - Utilities",
        ],
        "High Tech/Software/Hardware/Services": ["Industry Sector - Technology"],
        "Telecommunications": ["Industry Sector - Telecommunications"],
        "Governments": ["Industry Sector - Government National"],
        "Governments >> US State and Local Governments and Agencies": [
            "Industry Sector - Government Local"
        ],
        "Governments >> National Government": ["Industry Sector - Government National"],
        "Governments >> Security/Military/Law Enforcement": [
            "Industry Sector - Government National"
        ],
        "Governments >> Regional Govt (Subnational govt outside of US)": [
            "Industry Sector - Government Regional"
        ],
        "Education/Academia/Research Institutions": ["Industry Sector - Education"],
        "Civil Society": ["Industry Sector - Civil Society"],
        "Civil Society >> NGO/Nonprofit": ["Industry Sector - Non-profit"],
        "Civil Society >> International Governance (NATO/EU)": [
            "Industry Sector - NATO / EU"
        ],
        "Civil Society >> Political Party/Political organization": [
            "Industry Sector - Government National"
        ],
        "Civil Society >> Religious Org": ["Industry Sector - Religious Organisation"],
        "Business and Professional ": ["Industry Sector - Legal"],
        "Services/Legal/Accounting/Consulting": ["Industry Sector - Legal"],
        "Control Systems": ["Industry Sector - Infrastructure"],
        "Control Systems >> Discrete Automation": ["Industry Sector - Infrastructure"],
        "Control Systems >> Process Automation": ["Industry Sector - Infrastructure"],
        "Control Systems >> Building Automation": ["Industry Sector - Infrastructure"],
    },
    "targetedInformations": {
        "Corporate Employee Info": ["Targeted Information - Corporate Employee Info"],
        "Customer Data": ["Targeted Information - Customer Data"],
        "Financial Data": ["Targeted Information - Financial Data"],
        "Intellectual Property": ["Targeted Information - Intellectual Property"],
        "Credentials": ["Targeted Information - Credentials"],
        "Government Information": ["Targeted Information - Government Information"],
        "IT Information": ["Targeted Information - IT Information"],
        "Legal Documents": ["Targeted Information - Legal Documents"],
        "Sales/Marketing Data": ["Targeted Information - Sales/Marketing Data"],
        "Authentication Cookies": ["Targeted Information - Authentication Cookies"],
    },
    "intendedEffects": {
        "Military Advantage": ["Advantage - Military"],
        "Political Advantage": ["Advantage - Political"],
        "Competitive Advantage in Business or Economic Advantage": [
            "Advantage - Economic",
            "Competitive Advantage",
        ],
        "IP or Business Information Theft": ["Theft"],
        "IP or Confidential Business Information Theft": ["Theft"],
        "Identity Theft": ["Theft - Identity Theft"],
        "Credential Theft/Account Takeover": [
            "Theft - Credential Theft",
            "Account Takeover",
        ],
        "Financial Theft": ["Theft"],
        "Disruption": ["Disruption"],
        "Degradation": ["Degradation of Service"],
        "Denial and Deception": ["Denial and Deception"],
        "Destruction": ["Destruction"],
        "Embarrassment/Exposure/Brand Damage": [
            "Brand Damage",
            "Embarrassment",
            "Exposure",
        ],
        "Interference with ICS": ["ICS Control"],
    },
    "motivations": {
        "Ego": ["Motivation - Ego"],
        "Financial or Economic": ["Motivation - Financial or Economic"],
        "Anti-Corruption/Anti-Establishment/Information Freedom": [
            "Motivation - Anti-Corruption/Anti-Establishment/Information Freedom"
        ],
        "Environmental": ["Motivation - Environmental"],
        "Ethnic/nationalist": ["Motivation - Ethnic/nationalist"],
        "Ideological/Religious": ["Motivation - Ideological/Religious"],
        "Military/Security/Diplomatic": ["Motivation - Military/Security/Diplomatic"],
        "Opportunistic": ["Motivation - Opportunistic"],
    },
    "ttps": {
        "Enabling Infrastructures": ["TTP - Enabling Infrastructures"],
        "Communications": ["TTP - Communications"],
        "Domain Registration/DNS Abuse and Manipulation": [
            "TTP - Domain Registration/DNS Abuse and Manipulation"
        ],
        "Hosting": ["TTP - Hosting"],
        "Exploit Development": ["TTP - Exploit Development"],
        "Malware Propagation and Deployment": [
            "TTP - Malware Propagation and Deployment"
        ],
        "Malware Research and Development": ["TTP - Malware Research and Development"],
        "Monetization and Laundering": ["TTP - Monetization and Laundering"],
        "Defacement": ["TTP - Defacement"],
        "Distributed Denial-of-Service (DDoS) Attack": [
            "TTP - Distributed Denial-of-Service (DDoS) Attack"
        ],
        "Doxing": ["TTP - Doxing"],
        "Fraud": ["TTP - Fraud"],
        "Hardware/Supply Chain Compromise": ["TTP - Hardware/Supply Chain Compromise"],
        "Man-in-the-middle-attack": ["TTP - Man-in-the-middle-attack"],
        "Network Reconnaissance": ["TTP - Network Reconnaissance"],
        "Social Engineering": ["TTP - Social Engineering"],
        "Web Application Attacks": ["TTP - Web Application Attacks"],
        "PoS/ATM Malware/ATM Skimming": ["TTP - PoS/ATM Malware/ATM Skimming"],
        "Ransomware": ["TTP - Ransomware"],
        "Insider Threat": ["TTP - Insider Threat"],
        "Pen Testing": ["TTP - Pen Testing"],
    },
}

OVERVIEW_MALWARE_TYPES = {
    "Downloader": "Malware - Downloader",
    "POS Malware": "Malware - PoS",
    "Ransomware": "Malware - Ransomware",
    "Uploader": "Malware - Uploader",
    "Backdoor": "Malware - Backdoor",
    "Dropper": "Malware - Dropper",
    "Installer": "Malware - Installer",
    "Launcher": "Malware - Launcher",
    "Console": "Malware - Console",
    "Controller": "Malware - Controller",
    "Builder": "Malware - Builder",
    "Disruption Tool": "Malware - Disruption Tool",
    "Credential Stealer": "Malware - Information Stealer Harvester",
    "Privilege Escalation Tool": "Malware - Privilege Escalation Tool",
    "Remote Exploitation Tool": "Malware - Remote Exploitation Kit",
    "Exploit": "Malware - Exploit kit",
    "Tunneler": "Malware - Tunneler",
    "Reconnaissance Tool": "Malware - Reconnaissance Tool",
    "Lateral Movement Tool": "Malware - Lateral Movement Tool",
    "Data Miner": "Malware - information Stealer Harvester",
    "Keylogger": "Malware - Spyware",
    "Sniffer": "Malware - Spyware",
    "Archiver": "Malware - Archiver",
    "Bootkit": "Malware - Bootkit",
    "Rootkit": "Malware - Rootkit",
    "Driver": "Malware - Driver",
    "Utility": "Malware - Utility",
}

properties_xml_types = {
    "cve": "{http://cybox.mitre.org/objects#ProductObject-2}ProductObjectType",
    "file": "{http://cybox.mitre.org/objects#FileObject-2}FileObjectType",
    "hash-md5": "{http://cybox.mitre.org/objects#FileObject-2}FileObjectType",
    "hash-sha1": "{http://cybox.mitre.org/objects#FileObject-2}FileObjectType",
    "hash-sha256": "{http://cybox.mitre.org/objects#FileObject-2}FileObjectType",
    "product": "{http://cybox.mitre.org/objects#ProductObject-2}ProductObjectType",
    "uri": "{http://cybox.mitre.org/objects#URIObject-2}URIObjectType",
    "ipv4": "{http://cybox.mitre.org/objects#AddressObject-2}AddressObjectType",
    "port": "{http://cybox.mitre.org/objects#PortObject-2}PortObjectType",
    "domain": "{http://cybox.mitre.org/objects#DomainNameObject-1}"
    "DomainNameObjectType",
    "email": "{http://cybox.mitre.org/objects#AddressObject-2}AddressObjectType",
}

cybox_cve_format = """
    <cybox:Properties
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:ProductObj = "http://cybox.mitre.org/objects#ProductObject-2"
        xmlns:DeviceObj = "http://cybox.mitre.org/objects#DeviceObject-2"
        xmlns:SystemObj = "http://cybox.mitre.org/objects#SystemObject-2"
        xmlns:cyboxCommon = "http://cybox.mitre.org/common-2"
        xmlns:cybox = "http://cybox.mitre.org/cybox-2"
        xsi:type = "ProductObj:ProductObjectType">
        <ProductObj:Product>{product}</ProductObj:Product>
        <ProductObj:Vendor>{vendor}</ProductObj:Vendor>
        <ProductObj:Version>{version}</ProductObj:Version>
    </cybox:Properties>
"""

cybox_file_name_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
            xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
            xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
            xsi:type="FileObj:FileObjectType">
        <FileObj:File_Name>{}</FileObj:File_Name>
    </cybox:Properties>"""

cybox_md5_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:common="http://cybox.mitre.org/common-2"
            xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
            xsi:type="FileObj:FileObjectType">
        <FileObj:Hashes>
            <common:Hash>
                <common:Type>MD5</common:Type>
                <common:Simple_Hash_Value>{}</common:Simple_Hash_Value>
            </common:Hash>
        </FileObj:Hashes>
    </cybox:Properties>"""

cybox_sha1_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:common="http://cybox.mitre.org/common-2"
            xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
            xsi:type="FileObj:FileObjectType">
        <FileObj:Hashes>
            <common:Hash>
                <common:Type>SHA1</common:Type>
                <common:Simple_Hash_Value>{}</common:Simple_Hash_Value>
            </common:Hash>
        </FileObj:Hashes>
    </cybox:Properties>"""

cybox_sha256_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:common="http://cybox.mitre.org/common-2"
            xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
            xsi:type="FileObj:FileObjectType">
        <FileObj:Hashes>
            <common:Hash>
                <common:Type>SHA256</common:Type>
                <common:Simple_Hash_Value>{}</common:Simple_Hash_Value>
            </common:Hash>
        </FileObj:Hashes>
    </cybox:Properties>"""

cybox_product_format = """
    <cybox:Properties
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:ProductObj = "http://cybox.mitre.org/objects#ProductObject-2"
        xmlns:cyboxCommon = "http://cybox.mitre.org/common-2"
        xmlns:cybox = "http://cybox.mitre.org/cybox-2"
        xsi:type = "ProductObj:ProductObjectType">
        <ProductObj:Product>{}</ProductObj:Product>
    </cybox:Properties>
"""

cybox_uri_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2"
            xsi:type="URIObj:URIObjectType"
            type="URL">
        <URIObj:Value condition="Equals">{}</URIObj:Value>
    </cybox:Properties>"""

cybox_ipv4_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
            xsi:type="AddressObj:AddressObjectType"
            category="ipv4-addr">
        <AddressObj:Address_Value>{}</AddressObj:Address_Value>
    </cybox:Properties>"""

cybox_port_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
            xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
            xmlns:PortObj="http://cybox.mitre.org/objects#PortObject-2"
            xsi:type="PortObj:PortObjectType">
        <PortObj:Port_Value>{}</PortObj:Port_Value>
    </cybox:Properties>"""

cybox_domain_name_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1"
            xsi:type="DomainNameObj:DomainNameObjectType"
            type="FQDN">
        <DomainNameObj:Value>{}</DomainNameObj:Value>
    </cybox:Properties>"""

cybox_email_format = """
    <cybox:Properties
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:cybox="http://cybox.mitre.org/cybox-2"
            xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
            xsi:type="AddressObj:AddressObjectType"
            category="e-mail">
        <AddressObj:Address_Value>{}</AddressObj:Address_Value>
    </cybox:Properties>"""

formats = {
    "cve": cybox_cve_format,
    "file": cybox_file_name_format,
    "hash-md5": cybox_md5_format,
    "hash-sha1": cybox_sha1_format,
    "hash-sha256": cybox_sha256_format,
    "product": cybox_product_format,
    "uri": cybox_uri_format,
    "ipv4": cybox_ipv4_format,
    "port": cybox_port_format,
    "domain": cybox_domain_name_format,
    "email": cybox_email_format,
}
