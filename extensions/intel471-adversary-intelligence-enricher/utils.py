import re
import sys
from typing import List, Optional

import requests
import validators
from eiq_edk import create_extract
from eiq_edk.schemas.entities import ExtractType

HEADERS = {}

REPORT_ENDPOINT = "reports/{}"
HTTP_REQUEST_TIMEOUT = 120
PAGE_SIZE = 100
# Description needs to be under 18MB, because there are too big images
DESCRIPTION_SIZE_LIMIT = 18874368
# Description has multiple images that are over 10MB and package fails.
# We remove every image above 1MB.
IMAGE_SIZE_LIMIT = 10485760
API_URL = "https://api.intel471.com/v1/"
ACTORS_CONTACT_INFO = ["ICQ", "Jabber", "MSN", "YahooIM", "AIM", "Skype"]


def fetch_results(self, url, auth, verify_ssl, ext_type="Provider", **params):
    try:
        response = requests.get(
            url=url,
            auth=auth,
            headers=HEADERS,
            timeout=HTTP_REQUEST_TIMEOUT,
            verify=verify_ssl,
            **params,
        )
    except requests.Timeout:

        self.send_error(
            {
                "code": "ERR-0000",
                "description": f"{ext_type}  failed, service timeout",
                "message": f"{response.text}",
            }
        )
        raise
    if not response.ok:
        if response.status_code == 404:
            self.send_error(
                {
                    "code": "ERR-0000",
                    "description": f"{ext_type}  failed, service unavailable",
                    "message": f"{response.text}",
                }
            )
            return {}
        handle_errors(self, response, ext_type)
        response.raise_for_status()
    try:
        data = response.json()
        # some blobs come in too big - fields bellow can be larger than 20mb,
        # which is blob size limit.. so instead of rejecting the whole blob, we'll
        # just drop some fields, if they're too big.
        # Some images also come with large base64 encoding and package fails,
        # so we remove that image to ingest the report
        the_text = ""
        complete_fields_size = (
                data.get("researcherComments", "")
                + data.get("rawText", "")
                + data.get("rawTextTranslated", "")
        )

        if sys.getsizeof(complete_fields_size) > DESCRIPTION_SIZE_LIMIT:
            for field in ["researcherComments", "rawText", "rawTextTranslated"]:
                remove_images_from_description(data, field)
                if (
                        sys.getsizeof(data.get(field, "") + the_text)
                        < DESCRIPTION_SIZE_LIMIT
                ):
                    the_text += data.get(field, "")
                else:
                    data.pop(field)
    except ValueError:
        self.send_error(
            {
                "code": "ERR-0000",
                "description": f"{ext_type} failed",
                "message": f"unexpected data type encountered",
            }
        )
        raise
    return data


def remove_images_from_description(data, field):
    matches = re.findall('<img.*?src="(.*?)"[^>]+>', data.get(field, ""))
    for match in matches:
        if sys.getsizeof(match) > IMAGE_SIZE_LIMIT:
            data[field].replace(match, "")


def handle_errors(self, response, ext_type):
    # if file is not found, don't stop the feed
    if response.status_code in (401, 403):
        self.send_error(
            {
                "code": "401 / 403",
                "description": f"{ext_type} failed, authentication error",
                "message": f"{response.text} {response.status_code}.",
            }
        )
        pass
    elif response.status_code > 500:
        self.send_error(
            {
                "code": "500",
                "description": f"{ext_type} failed, service unavailable",
                "message": f"{response.text}.",
            }
        )
        pass
    else:
        self.send_error(
            {
                "code": "ERR-0000",
                "description": f"{ext_type} failed, malformed request",
                "message": f"{response.text}.",
            }
        )
        pass


class Intel471Exception(Exception):
    def __init__(self, arg):
        self.strerror = arg
        self.args = {arg}


def make_adversary_enricher_extracts(actors: List, value: str) -> List:
    extracts = []
    for actor in actors:
        if value != actor.get("handles")[0]:
            append_if_exist(
                extracts,
                create_extract({
                    "kind": ExtractType.HANDLE.value,
                    "value": actor.get("handles")[0],
                    "classification": "unknown",
                }),
            )
        if not actor.get("links").get("forums"):
            continue
        for forum in actor.get("links").get("forums"):
            if value != forum.get("name") and forum.get("name") is not None:
                domain_check = validators.domain(forum.get("name"))
                if domain_check:
                    append_if_exist(
                        extracts,
                        create_extract({
                                "kind": ExtractType.DOMAIN.value,
                                "value": forum.get("name"),
                                "classification": "unknown",
                        }),
                    )
                else:
                    append_if_exist(
                        extracts,
                        create_extract({
                            "kind": ExtractType.FORUM_NAME.value,
                            "value": forum.get("name"),
                            "classification": "unknown",
                        }),
                    )
            if (
                value != forum.get("actorHandle")
                and forum.get("actorHandle") is not None
            ):
                append_if_exist(
                    extracts,
                    create_extract({
                        "kind": ExtractType.HANDLE.value,
                        "value": forum.get("actorHandle"),
                        "classification": "unknown",
                    }),
                )
            contact_info_observables(forum, extracts)
    return extracts


def append_if_exist(extracts: List[dict], extract: Optional[dict]):
    if extract:
        extracts.append(extract)


def contact_info_observables(forum, extracts):
    if not forum.get("contactInfo"):
        return

    for contact_info in forum.get("contactInfo"):
        if contact_info.get("type") == "EmailAddress":
            append_if_exist(
                extracts,
                create_extract({
                    "kind": ExtractType.EMAIL.value,
                    "value": contact_info.get("value"),
                    "classification": "unknown",
                }),
            )
        elif contact_info.get("type") == "YahooIM":
            append_if_exist(
                extracts,
                create_extract({
                    "kind": ExtractType.HANDLE,
                    "value": f'yahoo|{contact_info.get("value")}',
                    "classification": "unknown",
                }),
            )
        elif contact_info.get("type") == "BitcoinWalletID":
            extracts.append(
                create_extract({
                    "kind": ExtractType.BANK_ACCOUNT.value,
                    "value": contact_info.get("value"),
                    "classification": "unknown",
                })
            )
        elif contact_info.get("type") in ACTORS_CONTACT_INFO:
            append_if_exist(
                extracts,
                create_extract({
                    "kind": ExtractType.HANDLE.value,
                    "value": f'{contact_info.get("type").lower()}|{contact_info.get("value")}',
                    "classification": "unknown",
                }),
            )
