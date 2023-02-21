import base64
import hashlib
import hmac
from urllib import parse
import uuid
from datetime import datetime
from typing import List

import requests
import structlog
from pkg_resources import get_distribution as gd

from eiq_edk.schemas.entities import ExtractType
from eiq_edk import create_entity


log = structlog.get_logger(__name__)

DEFAULT_PORT = 80

EXTENSION_NAME = "Silobreaker"
EXTENSION_VERSION = gd("eclecticiq-extension-silobreaker").version
PLATFORM_VERSION = gd("eiq-platform").version
REQUEST_HEADERS = {
    "User-Agent": (
        f"EclecticIQ IC/{PLATFORM_VERSION} " f"{EXTENSION_NAME}/{EXTENSION_VERSION}"
    ),
    "SB-EclecticIQ-Secret": "",
}
REQUESTS_TIMEOUT = 3 * 60  # not responsive as it should be
ECLECTICIQ_HEADER = "6htbpuxf6rksxod27i11"
DOC_ENTITIES = ["ThreatActor", "Malware", "Vulnerability"]
DOC_TAGS = [
    "ThreatActor",
    "Attacktype",
    "Malware",
    "Vulnerability",
    "Keyphrase",
    "Hashtag",
]
KIND = {
    "IPv4": ExtractType.IPV4,
    "Malware": ExtractType.MALWARE,
    "ThreatActor": ExtractType.ACTOR_ID,
    "Vulnerability": ExtractType.CVE,
    "Email": ExtractType.EMAIL,
    "Domain": ExtractType.DOMAIN,
    32: ExtractType.HASH_MD5,
    40: ExtractType.HASH_SHA1,
    64: ExtractType.HASH_SHA256,
}


def fetch_data(
    url: str,
    params: str,
    api_key: str,
    shared_key: str,
    verify: bool,
    method: str = "GET",
) -> dict:
    if method == "GET":
        url = url + f"?{params}"
        data = f"GET {url}"
        url = make_url(url, api_key, shared_key, data)
        REQUEST_HEADERS["SB-EclecticIQ-Secret"] = make_header_digest(data).decode()
        response = requests.get(
            url, headers=REQUEST_HEADERS, timeout=REQUESTS_TIMEOUT, verify=verify
        )
    else:
        data = "POST {url}"
        url = make_url(url, api_key, shared_key, data)
        response = None

    log_service_response(log_=log, response=response)
    log.info("Provider made a request", method="GET", url=url)
    try:
        data = response.json()
    except ValueError:
        log.error("Enricher failed, unsuspected data type encountered")
        raise
    return data


def make_url(url: str, api_key: str, shared_key: str, data: str) -> str:
    hmac_sha1 = hmac.new(shared_key.encode(), data.encode(), digestmod=hashlib.sha1)
    digest = base64.b64encode(hmac_sha1.digest())
    url = url + "&apiKey=" + api_key + "&digest=" + parse.quote(digest.decode())
    return url


def make_header_digest(data: str) -> bytes:
    hmac_sha1 = hmac.new(
        ECLECTICIQ_HEADER.encode(), data.encode(), digestmod=hashlib.sha1
    )
    digest = base64.b64encode(hmac_sha1.digest())
    return digest


def log_service_response(
    ext_type: str = None, log_: structlog = None, response: requests.Response = None
):
    """
    Prep and log service response entries based on response status.
    :param ext_type: string with the type of extension
    :param log_: structlog instance
    :param response: response instance from requests
    :return: nothing, raises HTTPError
    """

    if not all(
        [
            isinstance(log_, structlog._config.BoundLoggerLazyProxy),
            isinstance(response, requests.models.Response),
        ]
    ):
        raise ValueError

    status = response.status_code
    msg = None

    if status == 400:
        msg = "{} failed, malformed request".format(ext_type)
    if status == 401 or status == 403:
        msg = "{} failed, authentication error".format(ext_type)
    if status == 404:
        msg = "{} failed, request endpoint can't be found".format(ext_type)
    if 500 <= status <= 599 and status != 503:
        msg = "{} failed, service unavailable".format(ext_type)

    if msg:
        log_.error(msg, code=response.status_code, message=response.text)
        raise requests.exceptions.HTTPError(msg)


def get_report_page(content: str) -> str:
    return f"<div>{content}</div>"


def get_summary(value: str, timestamp: str) -> str:
    return f"<p>This is a Silobreaker In Focus Enrichment Report.</p>" \
           f"<p>Enriched observable: {value}</p>" \
           f"<p>Enrichment Date: {timestamp}</p>"  # noqa


def make_doc_report(
    data: dict,
    urls: List[str],
    title: str,
    extracts: List[dict],
    tags: List[str],
    description: str,
    start_time: str,
    observed_time: str,
) -> dict:
    timestamp = datetime.utcnow()
    report_id = "{{https://api.silobreaker.com/}}report-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, data["Id"]))
    )
    information_source = {
        "identity": "Silobreaker",
        "references": urls,
        "roles": ["Aggregator"]
    }

    report_data = {
        "id": report_id,
        "title": title,
        "description": description,
        "producer": information_source,
        "intents": [{"value": "Collective Threat Intelligence"}],
        "timestamp": timestamp.isoformat(),
    }
    report_meta = {
        "bundled_extracts": extracts,
        "tags": tags,
        "estimated_observed_time": observed_time,
        "estimated_threat_start_time": start_time
    }
    report = create_entity({
        "type": "report", "data": report_data, "meta": report_meta
    })
    return report
