import datetime
import uuid
import json
from typing import List, Dict, Tuple
from urllib import parse

from utils import set_dates
from eiq_edk import create_entity, create_extract
from eiq_edk.schemas.entities import ExtractType
from eiq_edk.schemas.entities import CONFIDENCES_EXTRACT_VALUES

import iso3166
import validators


def transform_posts(posts: List) -> Dict:
    entities = []
    if isinstance(posts, dict):
        posts = [posts]
    if posts:
        entities.append(create_posts_report(posts))
    return {"type": "linked-entities", "entities": entities}


def create_posts_report(posts: list) -> Dict:
    if posts[0].get("content_type"):
        actor = posts[0].get("links").get("authorActor").get("handle")
    else:
        actor = posts[0]["searched_actor"]

    analysis, tags = create_post_analysis_tags(posts, actor)

    extracts = [create_extract({"kind": ExtractType.ACTOR_ID.value, "value": actor})]
    for post in posts:
        forum = post.get("links").get("forum")
        if not forum:
            continue
        domain_check = validators.domain(forum.get("name"))
        if domain_check:
            extracts.append(
                create_extract({
                    "kind": ExtractType.DOMAIN.value,
                    "value": forum.get("name"),
                    "classification": "unknown"
                })
            )
        else:
            extracts.append(
                create_extract({
                    "kind": ExtractType.FORUM_NAME.value,
                    "value": forum.get("name"),
                    "classification": "unknown"
                })
            )
    extracts = filter_empty_extracts(extracts)
    _id = "{{https://intel471.com/}}Report-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, str(actor)))
    )

    report_data = {
        "id": _id,
        "title": actor,
        "description": analysis
    }

    report_meta = {
        "estimated_observed_time": set_dates(posts),
        "tags": tags,
        "bundled_extracts": extracts
    }

    post_report = create_entity({
        "type": "report", "data": report_data, "meta": report_meta
    })
    return post_report


def create_post_analysis_tags(posts: list, actor: str) -> Tuple[str, list]:
    forum_description, post_analysis = "", ""
    tags = ["Posts Report"]
    title = f"<p>Intel 471 Forum Posts - {actor}<p>"
    summary = (
        f"<h4>SUMMARY</h4><p>This Intel 471 report gives an overview of "
        f"forums posts created by {actor}.</p>"
    )
    analysis = "<h4>ANALYSIS *</h4>"
    for post in posts:
        forum_description = ""
        if post["links"]["forum"].get("description"):
            forum_description = (
                f"<p>Forum Description: " f"{post['links']['forum']['description']}</p>"
            )
        post_date = datetime.datetime.utcfromtimestamp(post["date"] / 1000).isoformat()
        if post.get("links", {}).get("thread", {}).get("topic"):
            thread_topic = f"<p>Thread Topic: {post['links']['thread']['topic']}.</p>"
        elif post.get("links", {}).get("thread", {}).get("topicOriginal"):
            thread_topic = (
                f"<p>Thread Topic: {post['links']['thread']['topicOriginal']}.</p>"
            )
        else:
            thread_topic = ""
        post_analysis += (
            f"<p><u><strong>Post</u></strong></p>"
            f"<p>Forum Name: {post['links']['forum']['name']}</p>"
            + forum_description
            + thread_topic
            + f"<p>Date: "
            f"{post_date}</p>"
            f"<p>{post['message'].replace('<img title=', '<img src=')}</p><br>"
        )
        if post["links"]["forum"].get("name") not in tags:
            tags.append(post["links"]["forum"].get("name"))

    full_analysis = title + summary + analysis + post_analysis
    return full_analysis, tags


def transform_adversary_report(blob: bytes) -> Dict:
    """
    Transformer for Intel471 Report JSON blob, fetched by Intel471Provider.
    """
    entities, relations = [], []
    data = blob
    if type(data) == bytes:
        data = json.loads(data.decode("utf-8"))
    report = create_adversary_report(data)
    entities.append(report)

    if data.get("actorSubjectOfReport"):
        actors, actor_relations = create_adversary_actors(data, entities)
        entities.append(actors)
        relations.extend(actor_relations)

    return {"type": "linked-entities", "entities": entities, "relations": relations}


def create_adversary_actors(data: dict, entities: list) -> Tuple[Dict, List]:
    # Do not create Report Actor Extracts if they are equal to the values within
    # “actorSubjectOfReport.handle”
    # and “actorSubjectOfReport.aliases” fields.

    # Tags
    tags = data.get("tags") or list()
    # taxonomy = list()
    actor_motivations = list()
    # Admiralty tags
    if data.get("admiraltyCode"):
        tags.append(RELIABILITY.get(data.get("admiraltyCode")[0]))
        tags.append(CREDIBILITY.get(data.get("admiraltyCode")[1]))
    # Motivation tags
    for motivation in data.get("motivation", []):
        tags.append(MOTIVATION_TAGS.get(motivation, motivation))
        for motivation_intent in MOTIVATION_INTENT.get(motivation, []):
            actor_motivations.append(motivation_intent)

    title_actor = data["actorSubjectOfReport"][0].get("handle")
    _id = "{{http://www.intel471.com/}}threat-actor-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, title_actor))
    )

    information_source = {
        "identity": "Intel 471 Adversary Intelligence Feed",
        "description": "Intel 471 Adversary Intelligence Feed"
    }
    threat_actor_data = {
        "id": _id,
        "title": title_actor,
        "producer": information_source,
        "confidence": CONFIDENCES_EXTRACT_VALUES[2],
        "motivations": actor_motivations,
        "identity": title_actor
    }
    threat_actor_meta = {
        "bundled_extracts": create_actor_extracts(data),
        "tags": tags,
        # "taxonomy_paths": taxonomy
    }

    threat_actor = create_entity({
        "type": "threat-actor", "data": threat_actor_data, "meta": threat_actor_meta
    })
    actor_relations = [
        {
            "data": {
                "source": 0,
                "target": len(entities),
                "key": "threat_actors",
                "source_type": "report",
                "target_type": "threat-actor",
                "type": "relation",
            }
        }
    ]
    return threat_actor, actor_relations


def create_actor_extracts(data: dict) -> List:
    if not data.get("actorSubjectOfReport"):
        return []
    return [
        create_extract({"kind": ExtractType.NAME.value, "value": alias,
                        "classification": "unknown"})
        for alias in data["actorSubjectOfReport"][0].get("aliases", [])
    ]


def create_indicator_title(data: dict) -> str:
    indicator_data = data["data"]
    title = ""
    if indicator_data["indicator_type"] == "file":
        title = (
            indicator_data["indicator_data"]
            .get("file")
            .get(list(indicator_data["indicator_data"].get("file").keys())[0])
        )
    elif indicator_data["indicator_type"] == "ipv4":
        title = indicator_data["indicator_data"].get("address")
    elif indicator_data["indicator_type"] == "url":
        parsed_url = parse.urlparse(indicator_data["indicator_data"].get("url"))
        if parsed_url.port:
            title = f'{indicator_data["indicator_data"].get("url")}/'
        else:
            title = indicator_data["indicator_data"].get("url")

    return title


def create_adversary_report(data: dict) -> Dict:
    references = [item["url"] for item in data.get("sources", []) if item.get("url")]
    if data.get("portalReportUrl"):
        references.append(data.get("portalReportUrl"))
    summary = ""
    if data.get("executiveSummary"):
        summary += f'<p>{data.get("executiveSummary")}</p>'
    if data.get("sourceCharacterization"):
        summary += f'<p>{data.get("sourceCharacterization")}</p>'
    analysis = create_adversary_analysis(data)
    tags, taxonomy = create_adversary_tags(data)
    bundled_extracts = create_adversary_report_extracts(data)
    report_date = ""
    if data.get("dateOfInformation"):
        report_date = datetime.datetime.utcfromtimestamp(
            data.get("dateOfInformation") / 1000
        )
    role_values = []
    if references:
        role_values.append("Initial Author")
    intents = ["Threat Report"]
    _id = "{{http://www.intel471.com/}}Report-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, data["uid"]))
    )
    information_source = {
        "identity": "Intel 471 Adversary Intelligence Feed",
        "references": references,
        "roles": role_values,
        "description": "Intel 471 Adversary Intelligence Feed"
    }

    report_data = {
        "id": _id,
        "title": data.get("subject"),
        "description": analysis,
        "producer": information_source,
        "intents": intents,
        "short_description": summary,
        "timestamp": report_date.isoformat(),
    }

    report_meta = {
        "bundled_extracts": bundled_extracts,
        "tags": tags,
        # "taxonomy_paths": taxonomy,
        "estimated_observed_time": report_date.isoformat()

    }

    report = create_entity({
        "type": "report", "data": report_data, "meta": report_meta
    })
    return report


def create_adversary_analysis(data: dict) -> str:
    analysis = ""
    if data.get("researcherComments"):
        analysis += (
            f"<strong><u>Researcher Comments</u></strong>"
            f'<p>{data.get("researcherComments", "")}</p>'
        )

    if data.get("rawTextTranslated") or data.get("rawText"):
        analysis += data.get("rawTextTranslated") or data.get("rawText")

    return analysis


def create_adversary_tags(data: dict) -> Tuple[list, list]:
    # Tags
    taxonomy = list()
    unique_tags = set()
    # Original tags
    if data.get("tags"):
        for tag in data["tags"]:
            unique_tags.add(tag)
    # Admiralty tags
    if data.get("admiraltyCode"):
        unique_tags.add(RELIABILITY.get(data.get("admiraltyCode")[0]))
        unique_tags.add(CREDIBILITY.get(data.get("admiraltyCode")[1]))
    # Motivation tags
    for motivation in data.get("motivation", []):
        unique_tags.add(MOTIVATION_TAGS.get(motivation, motivation))
    if data.get("documentType"):
        unique_tags.add(data.get("documentType"))
    if data.get("documentFamily"):
        unique_tags.add(data.get("documentFamily"))
    tags = list(unique_tags)
    return sorted(tags), taxonomy


def create_adversary_report_extracts(data: dict) -> List:
    actor_subject = []
    bundled_extracts = []
    if data.get("locations"):
        location_extracts(data.get("locations"), bundled_extracts)
    for actors in data.get("actorSubjectOfReport", []):
        if actors.get("handle"):
            actor_subject.append(actors.get("handle"))
        if actors.get("aliases"):
            actor_subject.extend(actors.get("aliases"))
    for entity in data.get("entities", []):
        extract = ENTITIES_TO_EXTRACTS.get(entity.get("type")) or None
        if entity.get("value") in actor_subject:
            continue
        if extract is None:
            continue
        if entity.get("type") == "Jabber":
            value = f'jabber|{entity.get("value")}'
        else:
            value = entity.get("value")
        bundled_extracts.append(
            create_extract({
                "kind": extract.get("kind"),
                "value": value,
                "classification": extract.get("classification")
            })
        )
    bundled_extracts = filter_empty_extracts(bundled_extracts)
    return bundled_extracts


def location_extracts(locations: list, bundled_extracts: list):
    for location in locations:
        try:
            country = iso3166.countries.get(location.get("country"))
        except KeyError:
            continue
        bundled_extracts.append(
            create_extract({
                "kind": ExtractType.COUNTRY.value,
                "value": country.name,
                "classification": "good"
            })
        )
        bundled_extracts.append(
            create_extract({
                "kind": ExtractType.COUNTRY_CODE.value,
                "value": country.alpha2,
                "classification": "good"
            })
        )


def filter_empty_extracts(extracts):
    extracts = [i for i in extracts if i]
    return extracts


ENTITIES_TO_EXTRACTS = {
    "MD5": {"kind": ExtractType.HASH_MD5.value, "classification": "unknown"},
    "SHA1": {"kind": ExtractType.HASH_SHA1.value, "classification": "unknown"},
    "SHA256": {"kind": ExtractType.HASH_SHA256.value, "classification": "unknown"},
    "MaliciousURL": {"kind": ExtractType.URI.value, "classification": "unknown"},
    "BitcoinID": {"kind": ExtractType.BANK_ACCOUNT.value, "classification": "unknown"},
    "BitcoinWalletID": {"kind": ExtractType.BANK_ACCOUNT.value,
                        "classification": "unknown"},
    "IPAddress": {"kind": ExtractType.IPV4.value, "classification": "unknown"},
    "ActorWebsite": {"kind": ExtractType.URI.value, "classification": "unknown"},
    "ActorDomain": {"kind": ExtractType.DOMAIN.value, "classification": "unknown"},
    "AutonomousSystem": {"kind": ExtractType.ASN.value, "classification": "good"},
    "EmailAddress": {"kind": ExtractType.EMAIL.value, "classification": "unknown"},
    "FileType": {"kind": ExtractType.FILE.value, "classification": "unknown"},
    "Handle": {"kind": ExtractType.NAME.value, "classification": "unknown"},
    "IPv4Prefix": {"kind": ExtractType.IPV4.value, "classification": "unknown"},
    "IPv6Prefix": {"kind": ExtractType.IPV6.value, "classification": "unknown"},
    "Jabber": {"kind": ExtractType.EMAIL.value, "classification": "unknown"},
    "Phone": {"kind": ExtractType.TELEPHONE.value, "classification": "unknown"},
    "Twitter": {"kind": ExtractType.HANDLE.value, "classification": "unknown"},
    "URL": {"kind": ExtractType.URI.value, "classification": "unknown"},
    "VK": {"kind": ExtractType.URI.value, "classification": "unknown"},
    "Telegram": {"kind": ExtractType.HANDLE.value, "classification": "unknown"},
}
MOTIVATION_TAGS = {"CC": "Cyber Crime", "CE": "Cyber Espionage", "HA": "Hacktivism"}
MOTIVATION_INTENT = {
    "CC": ["Financial or Economic"],
    "CE": ["Political", "Military"],
    "HA": ["Ideological"],
}

RELIABILITY = {
    "A": "Admiralty Code - Completely reliable",
    "B": "Admiralty Code - Usually reliable",
    "C": "Admiralty Code - Fairly reliable",
    "D": "Admiralty Code - Not usually reliable",
    "E": "Admiralty Code - Unreliable",
    "F": "Admiralty Code - Reliability cannot be judged",
}
CREDIBILITY = {
    "1": "Admiralty Code - Confirmed by other sources",
    "2": "Admiralty Code - Probably True",
    "3": "Admiralty Code - Possibly True",
    "4": "Admiralty Code - Doubtful",
    "5": "Admiralty Code - Improbable",
    "6": "Admiralty Code - Truth cannot be judged",
}
