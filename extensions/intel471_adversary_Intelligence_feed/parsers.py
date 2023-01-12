import datetime
import uuid
from typing import List, Dict, Tuple
from urllib import parse
import iso3166

from eiq_ext import ExtractType
from eiq_ext.legacy import get_admiralty_id
from eiq.extensions.commons.utils import (
    create_extract,
    create_information_source,
    make_confidence,
)

from eiq.extensions.commons.entities import create_report, create_threat_actor


ENTITIES_TO_EXTRACTS = {
    "MD5": {"kind": ExtractType.HASH_MD5, "classification": "unknown"},
    "SHA1": {"kind": ExtractType.HASH_SHA1, "classification": "unknown"},
    "SHA256": {"kind": ExtractType.HASH_SHA256, "classification": "unknown"},
    "MaliciousURL": {"kind": ExtractType.URI, "classification": "unknown"},
    "BitcoinID": {"kind": ExtractType.BANK_ACCOUNT, "classification": "unknown"},
    "BitcoinWalletID": {"kind": ExtractType.BANK_ACCOUNT, "classification": "unknown"},
    "IPAddress": {"kind": ExtractType.IPV4, "classification": "unknown"},
    "ActorWebsite": {"kind": ExtractType.URI, "classification": "unknown"},
    "ActorDomain": {"kind": ExtractType.DOMAIN, "classification": "unknown"},
    "AutonomousSystem": {"kind": ExtractType.ASN, "classification": "good"},
    "EmailAddress": {"kind": ExtractType.EMAIL, "classification": "unknown"},
    "FileType": {"kind": ExtractType.FILE, "classification": "unknown"},
    "Handle": {"kind": ExtractType.NAME, "classification": "unknown"},
    "IPv4Prefix": {"kind": ExtractType.IPV4, "classification": "unknown"},
    "IPv6Prefix": {"kind": ExtractType.IPV6, "classification": "unknown"},
    "Jabber": {"kind": ExtractType.EMAIL, "classification": "unknown"},
    "Phone": {"kind": ExtractType.TELEPHONE, "classification": "unknown"},
    "Twitter": {"kind": ExtractType.HANDLE, "classification": "unknown"},
    "URL": {"kind": ExtractType.URI, "classification": "unknown"},
    "VK": {"kind": ExtractType.URI, "classification": "unknown"},
    "Telegram": {"kind": ExtractType.HANDLE, "classification": "unknown"},
}
MOTIVATION_TAGS = {"CC": "Cyber Crime", "CE": "Cyber Espionage", "HA": "Hacktivism"}
MOTIVATION_INTENT = {
    "CC": ["Financial or Economic"],
    "CE": ["Political", "Military"],
    "HA": ["Ideological"],
}


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
        confidence=make_confidence("High"),
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


def create_actor_extracts(data: dict) -> List:
    if not data.get("actorSubjectOfReport"):
        return []
    return [
        create_extract(ExtractType.NAME, alias, classification="unknown")
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


def add_admiralty_taxonomy(taxonomy: list, admiralty: tuple):
    reliability_taxonomy = get_admiralty_id(
        "Admiralty Code - Reliability", admiralty[0]
    )
    if reliability_taxonomy:
        taxonomy.append(reliability_taxonomy)
    credibility_taxonomy = get_admiralty_id(
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
        references,
        role_values,
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
            create_extract(
                extract.get("kind"), value, classification=extract.get("classification")
            )
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
            create_extract(ExtractType.COUNTRY, country.name, classification="good")
        )
        bundled_extracts.append(
            create_extract(
                ExtractType.COUNTRY_CODE, country.alpha2, classification="good"
            )
        )


def filter_empty_extracts(extracts):
    extracts = [i for i in extracts if i]
    return extracts