import datetime
import uuid
import json
from typing import List, Dict, Tuple
from urllib import parse
from dev_kit.eiq_edk.schemas.entities import (
    EntityMetaSchema,
    EntitySchema,
    ExtractSchema,
    CONFIDENCES_EXTRACT_VALUES,
    ReportDataSchema,
    ThreatActorDataSchema,
    ExtractType
)
import iso3166
import structlog

log = structlog.get_logger(__name__)


def transform_posts(posts: List) -> Dict:
    log.info("Transformer started")
    entities = []
    if isinstance(posts, dict):
        posts = [posts]
    if posts:
        entities.append(create_posts_report(posts))
    log.info("Transformer finished successfully")
    return {"type": "linked-entities", "entities": entities}


def create_posts_report(posts: list) -> Dict:
    if posts[0].get("content_type"):
        actor = posts[0].get("links").get("authorActor").get("handle")
    else:
        actor = posts[0]["searched_actor"]

    analysis, tags = create_post_analysis_tags(posts, actor)

    extracts = [create_extract(ExtractType.ACTOR_ID, actor)]
    for post in posts:
        forum = post.get("links").get("forum")
        if not forum:
            continue
        domain_check = validators.domain(forum.get("name"))
        if domain_check:
            extracts.append(
                create_extract(
                    ExtractType.DOMAIN, forum.get("name"), classification="unknown"
                )
            )
        else:
            extracts.append(
                create_extract(
                    ExtractType.FORUM_NAME, forum.get("name"), classification="unknown"
                )
            )
    extracts = filter_empty_extracts(extracts)
    _id = "{{https://intel471.com/}}Report-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, str(actor)))
    )
    post_report = create_report(
        _id,
        f"Intel 471 Forum Posts - {actor}",
        description=analysis,
        observed_time=set_dates(posts),
        tags=tags,
        extracts=extracts,
    )
    return post_report


def transform_adversary_report(blob: bytes) -> Dict:
    """
    Transformer for Intel471 Report JSON blob, fetched by Intel471Provider.
    """
    log.info("Transformer started")
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

    log.info("Transformer finished successfully")
    return {"type": "linked-entities", "entities": entities, "relations": relations}


def create_adversary_actors(data: dict, entities: list) -> Tuple[Dict, List]:
    # Do not create Report Actor Extracts if they are equal to the values within
    # “actorSubjectOfReport.handle”
    # and “actorSubjectOfReport.aliases” fields.

    # Tags
    tags = data.get("tags") or list()
    taxonomy = list()
    actor_motivations = list()
    # Admiralty tags
    if data.get("admiraltyCode"):
        add_admiralty_taxonomy(taxonomy, data["admiraltyCode"])
    # Motivation tags
    for motivation in data.get("motivation", []):
        tags.append(MOTIVATION_TAGS.get(motivation, motivation))
        for motivation_intent in MOTIVATION_INTENT.get(motivation, []):
            actor_motivations.append(
                {
                    "type": "statement",
                    "value": motivation_intent,
                    "value_vocab": (
                        "{http://stix.mitre.org/default_vocabularies-1}"
                        "MotivationVocab-1.1"
                    ),
                }
            )

    title_actor = data["actorSubjectOfReport"][0].get("handle")
    _id = "{{http://www.intel471.com/}}threat-actor-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, title_actor))
    )
    information_source = create_information_source(
        "Intel 471 Adversary Intelligence Feed",
        description="Intel 471 Adversary Intelligence Feed",
    )

    threat_actor = create_threat_actor(
        _id,
        f"Threat Actor: {title_actor}",
        information_source=information_source,
        confidence=CONFIDENCES_EXTRACT_VALUES[2],
        extracts=create_actor_extracts(data),
        tags=tags,
        motivations=actor_motivations,
        taxonomy=taxonomy,
        actor_identity=title_actor,
    )

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


def create_information_source(
    identity_name: str,
    references: list = [],
    role_values: list = [],
    description: str = "",
) -> dict:

    information_source = {
            "type": "information-source",
            "identity": identity_name,
            "references":references,
            "roles": role_values,
            "description": description
    }

    return information_source


def create_threat_actor(
    stix_id: str,
    title: str,
    description: str = "",
    information_source: dict = None,
    identity: str = "", 
    observed_time: str = None,
    threat_start_time: str = None,
    threat_end_time: str = None,
    confidence: dict = None,
    timestamp: str = None,
    extracts: list = None,
    tags: list = None,
    types: list = None,
    summary: str = None,
    extraction_ignore_paths: list = None,
    attachments: list = None,
    tlp_color: str = None,
    half_life: int = None,
    observable: list = None,
    taxonomy: list = [],
    motivations: list = None,
    actor_types: list = None,
    intended_effects: list = None,
    sophistication: list = None,
    actor_identity: str = None,
    attacks: list = None,
) -> dict:
    threat_actor = ThreatActorDataSchema().load({
            "id": stix_id,
            "type": "threat-actor",
            "title": title,
            "description": description,
            "information_source": information_source,
            "timestamp": timestamp,
            "identity": identity,
            "intended_effects": intended_effects,
            "motivations": motivations,
            "sophistication": sophistication,
            "types": types
        }
    )

    entity_meta = EntityMetaSchema().load(
        {
            "estimated_observed_time": observed_time,
            "estimated_threat_start_time": threat_start_time,
            "estimated_threat_end_time": threat_end_time,
            "half_life": half_life,
            "tags": tags,
            "taxonomy": taxonomy,
            "attack": attacks,
            "tlp_color": tlp_color,
            "bundled_extracts": extracts,
            "extraction_ignore_paths": extraction_ignore_paths,
        }
    )

    entity_data = EntitySchema().load(
        {
            "data": threat_actor,
            "meta": entity_meta,
            "attachments": attachments
        }
    )
    return entity_data


def create_actor_extracts(data: dict) -> List:
    if not data.get("actorSubjectOfReport"):
        return []
    return [
        {"kind":ExtractType.NAME.value, "value":alias, "classification": "unknown", "link_type": "observed"}
        for alias in data["actorSubjectOfReport"][0].get("aliases", [])
    ]


def create_extract(
    kind: str,
    value: str,
    classification: str = None,
    confidence: str = None,
    link_type: str = None,
) -> dict:
    extract = ExtractSchema().load(
        {
            "kind": kind,
            "value": value,
            "classification": classification,
            "link_type":  link_type
        }
    )
    
    return extract


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


def add_admiralty_taxonomy(taxonomy: list, admiralty: tuple):
    reliability_taxonomy = (
        "Admiralty Code - Reliability", admiralty[0]
    )
    if reliability_taxonomy:
        taxonomy.append(reliability_taxonomy)
    credibility_taxonomy = (
        "Admiralty Code - Credibility", admiralty[1]
    )
    if credibility_taxonomy:
        taxonomy.append(credibility_taxonomy)


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
    intents = [{"value": "Threat Report"}]
    information_source = create_information_source(
        "Intel 471 Adversary Intelligence Feed",
        references=references,
        role_values=role_values,
        description="Intel 471 Adversary Intelligence Feed",
    )
    _id = "{{http://www.intel471.com/}}Report-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, data["uid"]))
    )
    report = create_report(
        _id,
        data.get("subject"),
        description=analysis,
        information_source=information_source,
        observed_time=report_date.isoformat(),
        timestamp=report_date.isoformat(),
        intents=intents,
        extracts=bundled_extracts,
        tags=tags,
        summary=summary,
        taxonomy=taxonomy,
    )
    return report


def create_report(
    stix_id: str = "",
    title: str = "",
    description: str = "",
    short_description: str = "",
    information_source: dict = {},
    observed_time: str = "",
    threat_start_time: str = "",
    threat_end_time: str = "",
    timestamp: str = "",
    extracts: list = [],
    tags: list = [],
    summary: str = "",
    intents: list = [],
    extraction_ignore_paths: list = [],
    attachments: list = [],
    tlp_color: str = None,
    half_life: int = 1,
    observable: list = [],
    taxonomy: list = [],
    taxonomy_paths: list = [],
    relationship: str = "",
    attacks: list = [],
) -> dict:

    report = ReportDataSchema().load(
        {
            "id": stix_id,
            "type": "report",
            "title": title,
            "description": description,
            "short_description": short_description,
            "information_source": information_source,
            "intents": intents,
            "timestamp": timestamp
        }
    )

    entity_meta = EntityMetaSchema().load({
            "estimated_observed_time": observed_time,
            "estimated_threat_start_time": threat_start_time,
            "estimated_threat_end_time": threat_end_time,
            "half_life": half_life,
            "tags": tags,
            "taxonomy": taxonomy,
            "attack": attacks,
            "tlp_color": tlp_color,
            "bundled_extracts": extracts,
            "extraction_ignore_paths": extraction_ignore_paths
        }
    )

    entity_data = EntitySchema().load(
        {
            "data": report, 
            "meta": entity_meta,
            "attachments": attachments
        }
    )

    return entity_data


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
        add_admiralty_taxonomy(taxonomy, data["admiraltyCode"])
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
                {
                    "kind": extract.get("kind"),
                    "value": value,
                    "classification": extract.get("classification"),
                    "link_type": "observed"
                }
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
            {"kind": ExtractType.COUNTRY.value, "value": country.name, "classification": "good"}
        )
        bundled_extracts.append(
                {"kind": ExtractType.COUNTRY_CODE.value, "value": country.alpha2, "classification": "good"}
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
    "BitcoinWalletID": {"kind": ExtractType.BANK_ACCOUNT.value, "classification": "unknown"},
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