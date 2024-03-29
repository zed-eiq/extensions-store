import datetime
import re
import uuid
from typing import List, Optional

from eiq_edk import create_entity
from eiq_edk._data_objects import ExtractType

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
               "more methods, like passive DNS, geo-location and connectivity detection."
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
        extract = {
            "kind": ExtractType.CVE.value,
            "value": item.replace("CVE-", ""),
            "classification": "safe"
        }
        extracts.append(extract)

    recommendations = report.get("mitigationDetails", "") + report.get("vendorFix", "")
    for item in report.get("vendorFixUrls", dict()).get("vendorFixUrl", []):
        if item.get("name"):
            if item.get("url"):
                recommendations += f"<p><a href=\"{item['url']}\">{item['name']}</a></p>"
            else:
                recommendations += f"<p>{item['name']}</p>"
        if item.get("url"):
            references.append(item["url"])
    if recommendations:
        recommendations = (
            f'<section itemscope itemtype="http://eclecticiq.com/microdata/section">'
            f'<h1 itemprop="title">Recommendations</h1>'
            f'<div itemprop="content">{recommendations}</div>'
            f"</section>"
        )
    description = (
        f"{report.get('summary', '')}"
        f"<br>{report.get('vulnerableProducts', '')}<br>{recommendations}"
    )
    tags = [
        f"Mitigation - {item}"
        for item in report.get("mitigations", dict()).get("mitigation", [])
    ]
    report_data = {
        "id": create_fireeye_report_uuid(report),
        "title": report.get("title") or "Untitled",
        "timestamp": publish_date,
        "description": description,
        "producer": create_fireeye_info_source(references=references, role="Aggregator"),
        "short_description": report.get("execSummary", ""),
    }
    report_meta = {
        "tags": tags,
        "bundled_extracts": extracts,
        "estimated_threat_start_time": publish_date,
        "estimated_observed_time": discovered_date,
    }

    return create_entity({
        "type": "report",
        "data": report_data,
        "meta": report_meta,
        "attachments": [report["attachment"]] if report.get("attachment") else []
    })


def parse_published_date(report: dict) -> str:
    # just in case sometimes we don't receive publishDate,
    # set the default date to today (it actually never happened before)
    publish_date = datetime.datetime.utcnow().isoformat()
    if report.get("publishDate"):
        publish_date = datetime.datetime.strptime(
            report["publishDate"], "%B %d, %Y %I:%M:%S %p"
        ).isoformat()
    return publish_date


def create_fireeye_report_uuid(report: dict) -> str:
    return "{{https://api.isightpartners.com/}}Report-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, report.get("reportId")))
    )


def create_fireeye_info_source(references: List = [], role: str = '') -> dict:
    role = role or "Initial Author"

    producer = {
        'identity': "FireEye iSIGHT Intelligence Report API",
        'description': "https://api.isightpartners.com",
        'references': references,
        'roles': [role]
    }
    return producer


# Overview
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
    report_data = {
        "id": create_fireeye_report_uuid(report),
        "title": report.get("title") or "Untitled",
        "timestamp": publish_date,
        "description": report.get("threatDescription"),
        "producer": create_fireeye_info_source(),
    }
    report_meta = {
        "tags": [item for item in tags if item],
        "bundled_extracts": report.get("extracts", []),
        "estimated_threat_start_time": publish_date,
        "estimated_observed_time": publish_date,
    }

    return create_entity({
        "type": "report",
        "data": report_data,
        "meta": report_meta,
        "attachments": [report["attachment"]] if report.get("attachment") else []
    })


def create_actor_overview_report(report: dict, publish_date: str) -> dict:
    report_data = {
        "id": create_fireeye_report_uuid(report),
        "title": report.get("title") or "Untitled",
        "timestamp": publish_date,
        "description": report.get("threatDescription"),
        "producer": create_fireeye_info_source(),
    }
    report_meta = {
        "bundled_extracts": report.get("extracts", []),
        "estimated_threat_start_time": publish_date,
        "estimated_observed_time": publish_date,
    }

    return create_entity({
        "type": "report",
        "data": report_data,
        "meta": report_meta,
        "attachments": [report["attachment"]] if report.get("attachment") else []
    })


def create_actor_overview_actors(report: dict, publish_date: str) -> List[dict]:
    results = []
    main_section = report.get("tagSection", dict()).get("main", dict())
    for actor in main_section.get("actors", dict()).get("actor", []):
        if not actor or not actor.get("name"):
            continue
        actor_title = "Intrusion Set: {}".format(actor["name"])
        uid = str(uuid.uuid5(uuid.NAMESPACE_X500, actor_title))
        _id = f"{{https://api.isightpartners.com/}}threat-actor-{uid}"

        threat_actor_data = {
            "id": _id,
            "title": actor_title,
            "producer": create_fireeye_info_source(),
            "description": report.get("threatDescription"),
            "identity": actor['name'],
            "timestamp": publish_date,
        }
        threat_actor_meta = {
            "estimated_observed_time": publish_date,
            "estimated_threat_start_time": publish_date,
        }

        results.append(
            create_entity({
                "type": "threat-actor",
                "data": threat_actor_data,
                "meta": threat_actor_meta
            })
        )
    return results


# Overview

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
    report_data = {
        "id": create_fireeye_report_uuid(report),
        "title": report.get("title") or "Untitled",
        "timestamp": publish_date,
        "description": report.get("analysis", "") + countries_block,
        "producer": create_fireeye_info_source(),
        "short_description": report.get("execSummary", ""),
    }
    report_meta = {
        "tags": tags,
        "bundled_extracts": extracts + report.get("extracts", []),
        "estimated_threat_start_time": publish_date,
        "estimated_observed_time": publish_date,
    }
    return create_entity({
        "type": "report",
        "data": report_data,
        "meta": report_meta,
        "attachments": [report["attachment"]] if report.get("attachment") else []
    })


def process_malware_files(
        report: dict, entities: List[dict], relations: List[dict], tags: List[str]
):
    if (
            not report.get("tagSection")
            or not report["tagSection"].get("files")
            or not report["tagSection"]["files"].get("file")
    ):
        return
    process_indicators(report, tags, entities, relations, "file")


def process_malware_networks(
        report: dict, entities: List[dict], relations: List[dict], tags: List[str]
):
    if (
            not report.get("tagSection")
            or not report["tagSection"].get("networks")
            or not report["tagSection"]["networks"].get("network")
    ):
        return
    process_indicators(report, tags, entities, relations, "network")


def process_malware_emails(
        report: dict, entities: List[dict], relations: List[dict], tags: List[str]
):
    if (
            not report.get("tagSection")
            or not report["tagSection"].get("emails")
            or not report["tagSection"]["emails"].get("email")
    ):
        return
    process_indicators(report, tags, entities, relations, "email")


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
    ttp_data = {
        "id": _id,
        "title": title,
        "timestamp": date,
    }
    ttp_meta = {
        "tags": tags or [],
        "estimated_threat_start_time": date,
        "estimated_observed_time": date,
        "extraction_ignore_paths": ["title", "behavior"],
    }
    entities.append(create_entity({"type": "ttp", "data": ttp_data, "meta": ttp_meta}))
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


# THREAT


def create_threat_report(
        report: dict, extracts: List[dict], tags: List[str], countries_block: str
) -> dict:
    publish_date = parse_published_date(report)
    for cve in report.get("cveIds", dict()).get("cveId", []):
        extract = {
            "kind": ExtractType.CVE.value,
            "value": cve.replace("CVE-", ""),
            "classification": "safe"
        }
        extracts.append(extract)

    report_data = {
        "id": create_fireeye_report_uuid(report),
        "title": report.get("title") or "Untitled",
        "timestamp": publish_date,
        "description": report.get("threatDetail", "") + countries_block,
        "producer": create_fireeye_info_source(),
        "short_description": report.get("execSummary", ""),
    }
    report_meta = {
        "tags": tags,
        "bundled_extracts": extracts + report.get("extracts", []),
        "estimated_threat_start_time": publish_date,
        "estimated_observed_time": publish_date,
    }

    return create_entity({
        "type": "report",
        "data": report_data,
        "meta": report_meta,
        "attachments": [report["attachment"]] if report.get("attachment") else []
    })


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
        extract = {
            "kind": ExtractType.HASH_MD5.value,
            "value": file["md5"],
            "classification": "high"
        }
        extracts.append(extract)
    if file.get("sha1"):
        title = title or file["sha1"]
        extract = {
            "kind": ExtractType.HASH_SHA1.value,
            "value": file["sha1"],
            "classification": "high"
        }
        extracts.append(extract)
    if file.get("sha256"):
        title = title or file["sha256"]
        extract = {
            "kind": ExtractType.HASH_SHA256.value,
            "value": file["sha256"],
            "classification": "high"
        }
        extracts.append(extract)
    if file.get("fileName", "unknown").lower() not in BAD_FILENAMES:
        title = title or file["fileName"]
        extract = {
            "kind": ExtractType.FILE.value,
            "value": file["fileName"],
            "classification": "low"
        }
        extracts.append(extract)
    if file.get("userAgent"):
        for user_agent in file["userAgent"]:
            extract = {
                "kind": ExtractType.PRODUCT.value,
                "value": user_agent,
            }
            extracts.append(extract)

    if not title:
        return None

    indicator_data = {
        "id": create_fireeye_indicator_uuid(report, title),
        "title": title,
        "timestamp": publish_date,
        "description": description or title,
        "confidence": confidence,
        "producer": create_fireeye_info_source(),
        "types": ["File Hash Watchlist"],
        "short_description": report.get("execSummary", ""),
    }
    indicator_meta = {
        "tags": tags,
        "bundled_extracts": extracts,
        "estimated_threat_start_time": publish_date,
        "estimated_observed_time": publish_date,
        "extraction_ignore_paths": ["title"],
    }

    return create_entity({
        "type": "indicator",
        "data": indicator_data,
        "meta": indicator_meta
    })


def create_network_indicator(
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
        extract = {
            "kind": ExtractType.IPV4.value,
            "value": network["ip"],
            "classification": "high"
        }
        extracts.append(extract)
        types.append("IP Watchlist")
    if network.get("cidr"):
        title = title or network["cidr"]
        extract = {
            "kind": ExtractType.IPV4.value,
            "value": network["cidr"],
            "classification": "high"
        }
        extracts.append(extract)
    if network.get("domain"):
        title = title or network["domain"]
        extract = {
            "kind": ExtractType.DOMAIN.value,
            "value": network["domain"],
            "classification": "high"
        }
        extracts.append(extract)
        types.append("Domain Watchlist")
    if network.get("url"):
        title = title or network["url"]
        extract = {
            "kind": ExtractType.URI.value,
            "value": network["url"],
            "classification": "high"
        }
        extracts.append(extract)
        types.append("URL Watchlist")
    if network.get("asn"):
        title = title or network["asn"]
        extract = {
            "kind": ExtractType.ASN.value,
            "value": network["asn"],
            "classification": "safe"
        }
        extracts.append(extract)
    if network.get("registrantEmail"):
        title = title or network["registrantEmail"]
        extract = {
            "kind": ExtractType.EMAIL.value,
            "value": network["registrantEmail"],
        }
        extracts.append(extract)
    if network.get("registrantName"):
        title = title or network["registrantName"]
        extract = {
            "kind": ExtractType.NAME.value,
            "value": network["registrantName"],
        }
        extracts.append(extract)
    if network.get("port"):
        extract = {
            "kind": ExtractType.PORT.value,
            "value": network["port"],
        }
        extracts.append(extract)

    if not title or not extracts:
        return None

    indicator_data = {
        "id": create_fireeye_indicator_uuid(report, title),
        "title": title,
        "timestamp": publish_date,
        "description": description or title,
        "confidence": confidence,
        "producer": create_fireeye_info_source(),
        "types": types,
    }
    indicator_meta = {
        "tags": tags,
        "bundled_extracts": extracts,
        "estimated_threat_start_time": publish_date,
        "estimated_observed_time": publish_date,
        "extraction_ignore_paths": ["title"],
    }

    return create_entity({
        "type": "indicator",
        "data": indicator_data,
        "meta": indicator_meta
    })


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
    extract = {
        "kind": ExtractType.EMAIL.value,
        "value": email.get("senderAddress"),
    }
    extracts.append(extract)
    if email.get("senderName"):
        extract = {
            "kind": ExtractType.NAME.value,
            "value": email.get("senderName"),
        }
        extracts.append(extract)
    if email.get("sourceDomain"):
        extract = {
            "kind": ExtractType.DOMAIN.value,
            "value": email.get("sourceDomain"),
            "classification": "low"
        }
        extracts.append(extract)
    if email.get("sourceIp"):
        extract = {
            "kind": ExtractType.IPV4.value,
            "value": email.get("sourceIp"),
            "classification": "low"
        }
        extracts.append(extract)

    indicator_data = {
        "id": create_fireeye_indicator_uuid(report, title),
        "title": title,
        "timestamp": publish_date,
        "description": description or title,
        "confidence": confidence,
        "producer": create_fireeye_info_source(),
        "types": ["Malicious E-mail"],
    }
    indicator_meta = {
        "tags": tags,
        "bundled_extracts": extracts,
        "estimated_threat_start_time": publish_date,
        "estimated_observed_time": publish_date,
        "extraction_ignore_paths": ["title"],
    }

    return create_entity({
        "type": "indicator",
        "data": indicator_data,
        "meta": indicator_meta
    })


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

        threat_actor_data = {
            "id": f"{{http://api.isightpartners.com/}}threat-actor-{id5}",
            "title": actor_title,
            "producer": create_fireeye_info_source(),
            "timestamp": publish_date,
            "identity": actor["name"],
            "motivations": motivations or [],
            "intended_effects": intended_effects or []
        }
        threat_actor_meta = {
            "tags": tags,
            "estimated_observed_time": publish_date,
            "estimated_threat_start_time": publish_date,
        }
        actors.append(create_entity({
            "type": "threat-actor",
            "data": threat_actor_data,
            "meta": threat_actor_meta
        }))

    return actors


def create_actor_motivations(data: List) -> List[dict]:
    motivations = []
    for item in data:
        if not item:
            continue
        for motivation in THREAT_ACTOR_MOTIVATIONS.get(item, [item]):
            motivations.append(motivation)
    return motivations


def create_actor_intended_effects(data: List[str]) -> List[dict]:
    intended_effects = []
    for item in data:
        for intended_effect in THREAT_ACTOR_INTENDED_EFFECTS.get(item, [item]):
            intended_effects.append(intended_effect)
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

