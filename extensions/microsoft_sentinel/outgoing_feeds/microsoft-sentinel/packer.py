import copy
import datetime
import logging
import re
from typing import Union

import dateutil
import pytz
from eiq_edk.schemas.entities import TLP_COLORS_ORDERED

log = logging.getLogger(__name__)


def to_ms_sentinel_json(update_strategy, list_elements):
    results = dict()
    indicator_ids = []
    for element in list_elements:  #### package level
        if str(element["id"]) in indicator_ids:
            continue

        deleted = element.get("diff") == "del"
        if entity_has_expired(element["meta"]):
            # handle expired data
            if (
                    update_strategy in ["APPEND", "REPLACE"]
                    or element.get("diff") == "add"
            ):
                continue
            deleted = True

        if deleted:
            indicators = {str(element["id"]): {"deleted": True}}
        else:
            indicators = make_ms_sentinel_indicators(element)
        indicator_ids.append(str(element["id"]))
        results.update(indicators)

    return results


def make_ms_sentinel_indicators(entity_stream_element):
    extracts = []

    # get extracts from data dict
    extracts_from_data = extract_from_entity_meta(meta=entity_stream_element["meta"])

    for extract in extracts_from_data.values():
        if extract["kind"] == "asn":
            try:
                extract["value"] = extract_asn_from_value(extract["value"])
            except ValueError as e:
                log.warning(f"Skipping an observable due to an error - {str(e)}")
                continue
        extracts.append(
            {
                "kind": extract["kind"],
                "value": extract["value"],
                "classification": extract["classification"] or "unknown",
                "confidence": extract["confidence"],
            }
        )

    # get extracts from entity_extracts
    for extract in entity_stream_element["extracts"]:
        if extract["kind"] == "asn":
            try:
                extract["value"] = extract_asn_from_value(extract["value"])
            except ValueError as e:
                log.warning(f"Skipping an observable due to an error - {str(e)}")
                continue
        extracts.append(
            {
                "kind": extract["kind"],
                "value": extract["value"],
                "classification": extract["meta"].get("classification") or "unknown",
                "confidence": extract["meta"].get("confidence"),
            }
        )
    if not extracts:
        return {}
    confidence = max(
        [CONFIDENCE.index(extract["confidence"] or "unknown") for extract in extracts]
    )
    # create MS Sentinel indicators that should be pushed
    indicator_template = make_ms_sentinel_indicator(entity_stream_element, confidence)

    indicators = dict()
    for extract in extracts:
        indicator = copy.deepcopy(indicator_template)
        # fill in the value we have and set the other values to None
        indicator_value = prepare_indicator_value(extract["kind"], extract["value"])
        if indicator_value is None:
            continue
        for field in SENTINEL_FIELD.values():
            indicator[field] = indicator_value.get(field)
        indicator["fileHashType"] = SENTINEL_HASH_FORMAT.get(extract["kind"])
        indicators[f"{extract['kind']}:{extract['value']}"] = indicator

    return {str(entity_stream_element["id"]): indicators}


def extract_from_entity_meta(meta):
    found_extracts = dict()
    counter = 0
    # Extracts bundled with an entity always get included
    for d in meta.get("bundled_extracts", []):
        found_extracts[counter] = d
        counter += 1

    return found_extracts


def extract_asn_from_value(asn: Union[str, int]) -> Union[str, int]:
    try:
        int(asn)
        return asn
    except ValueError:
        # it's not already a number, try to extract it from string
        pass

    # we expect something like: AS-6400
    asn_found = re.search(r"AS-?(\d+)", asn)
    if asn_found:
        return asn_found.group(1)
    else:
        raise ValueError(f"Invalid ASN: {asn}")


def make_ms_sentinel_indicator(entity_stream_element, extract_confidence):
    threat_type = "WatchList"
    if entity_stream_element["data"].get("types"):
        threat_type = SENTINEL_THREAT_TYPE.get(
            entity_stream_element["data"]["types"][0]["value"]
        )

    expiration_date_time = None
    if entity_stream_element["meta"].get("estimated_threat_start_time"):
        half_life = int(entity_stream_element["meta"].get("half_life", 0))
        expiration_date_time = (
                dateutil.parser.isoparse(
                    entity_stream_element["meta"].get("estimated_threat_start_time")
                )
                + datetime.timedelta(days=half_life)
        ).isoformat()

    indicator_confidence = 0
    if entity_stream_element["data"].get("confidence"):
        indicator_confidence = SENTINEL_CONFIDENCE.get(
            entity_stream_element["data"]["confidence"]["value"], 0
        )

    tags, kill_chain = parse_tags(entity_stream_element["meta"])

    color_form_meta = entity_stream_element["meta"].get("tlp_color")
    tlp_color = "unknown"
    for item in TLP_COLORS_ORDERED:
        if item == color_form_meta:
            tlp_color = item.lower()
            break

    indicator = {
        "action": "alert",
        "targetProduct": "Azure Sentinel",
        "externalId": str(entity_stream_element["id"]),
        "description": f"Entity from EclecticIQ Platform. "
                       f"{entity_stream_element['data']['title']}",
        "tlpLevel": tlp_color,
        "confidence": indicator_confidence,
        "severity": SENTINEL_SEVERITY.get(CONFIDENCE[extract_confidence or 0].lower()),
        "threatType": threat_type,
        "expirationDateTime": expiration_date_time,
        "lastReportedDateTime": (
            entity_stream_element["meta"].get("estimated_observed_time")
        ),
        "tags": tags,
        "killChain": kill_chain,
        "isActive": True,
    }

    return indicator


def filter_data_for_extracts(entity_data):
    result = copy.deepcopy(entity_data)
    for field in IGNORE_PATHS:
        if field in result:
            result.pop(field)
    return result


def parse_tags(meta):
    # take only leaf nodes in taxonomy
    taxonomy_tags = [
        taxonomy_path[-1] for taxonomy_path in meta.get("taxonomy_paths", [])
    ]
    tags = meta.get("tags", []) + taxonomy_tags
    kill_chain = extract_kill_chain(tags)
    return tags, kill_chain


def extract_kill_chain(tags):
    kill_chain = []
    for tag in tags:
        if not tag.startswith("Kill chain phase -"):
            continue
        key = tag.replace("Kill chain phase -", "").strip()
        if key in SENTINEL_KILL_CHAIN:
            kill_chain.append(SENTINEL_KILL_CHAIN[key])
    return kill_chain


def prepare_indicator_value(extract_kind, extract_value):
    try:
        data = {SENTINEL_FIELD[extract_kind]: extract_value}
        if extract_kind == "email":
            data["emailSourceDomain"] = extract_value.split("@")[-1]
        return data
    except KeyError:
        return None


def entity_has_expired(meta):
    if not meta.get("estimated_threat_start_time"):
        return False
    half_life = int(meta.get("half_life", 0))
    expiration_date_time = dateutil.parser.isoparse(
        meta.get("estimated_threat_start_time")
    ) + datetime.timedelta(days=half_life)
    return expiration_date_time.replace(
        tzinfo=pytz.UTC
    ) <= datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)


IGNORE_PATHS = [
    "title",
    "description",
    "short_description",
    "producer",
    "information_source",
]

SOURCE_LIMIT = 200
DESCRIPTION_LIMIT = 200
CONFIDENCE = ["unknown", "low", "medium", "high"]

SENTINEL_CONFIDENCE = {"Low": 33, "Medium": 66, "High": 100}
SENTINEL_SEVERITY = {"unknown": 0, "low": 1, "medium": 3, "high": 5}
SENTINEL_THREAT_TYPE = {
    "Malicious E-mail": "Phishing",
    "IP Watchlist": "WatchList",
    "File Hash Watchlist": "WatchList",
    "Domain Watchlist": "WatchList",
    "URL Watchlist": "WatchList",
    "Malware Artifacts": "Malware",
    "C2": "C2",
    "Anonymization": "Proxy",
    "Exfiltration": "WatchList",
    "Host Characteristics": "WatchList",
    "Compromised PKI Certificate": "WatchList",
    "Login Name": "WatchList",
    "IMEI Watchlist": "WatchList",
    "IMSI Watchlist": "WatchList",
}
SENTINEL_HASH_FORMAT = {"hash-md5": "md5", "hash-sha1": "sha1", "hash-sha256": "sha256"}
SENTINEL_KILL_CHAIN = {
    "Actions on Objectives": "Actions",
    "Command and Control": "C2",
    "Delivery": "Delivery",
    "Exploitation": "Exploitation",
    "Installation": "Installation",
    "Reconnaissance Artifacts": "Reconnaissance",
    "Weaponization": "Weaponization",
}
SENTINEL_FIELD = {
    "asn": "networkSourceAsn",
    "domain": "domainName",
    "email": "emailSenderAddress",
    "emailSourceDomain": "emailSourceDomain",
    "email-subject": "emailSubject",
    "file": "fileName",
    "hash-sha1": "fileHashValue",
    "hash-sha256": "fileHashValue",
    "hash-md5": "fileHashValue",
    "ipv4": "networkIPv4",
    "ipv6": "networkIPv6",
    "mutex": "fileMutexName",
    "port": "networkPort",
    "uri": "url",
}
