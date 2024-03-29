import itertools
import re
import sys
from datetime import datetime

import pytz
import requests

HEADERS = {}

REPORT_ENDPOINT = "reports/{}"
HTTP_REQUEST_TIMEOUT = 120
PAGE_SIZE = 100
# Description needs to be under 18MB, because there are too big images
DESCRIPTION_SIZE_LIMIT = 18874368
# Description has multiple images that are over 10MB and package fails.
# We remove every image above 1MB.
IMAGE_SIZE_LIMIT = 10485760


def batch(iterable, size):
    """Break given iterable into chunks of given size. Generator."""
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk


def fetch_with_paging(
        self,
        api_url,
        count_col_name,
        root_node,
        created_col_name,
        auth,
        query_params,
        verify_ssl,
        page_size=PAGE_SIZE,
):
    offset = 0
    last_report_timestamp = query_params["from"]
    while True:
        query_params.update({"count": page_size, "offset": offset})
        response = fetch_results(
            self, url=api_url, auth=auth, verify_ssl=verify_ssl, params=query_params
        )
        if response:
            item_count = response.get(count_col_name, 0)
            items = response.get(root_node, [])

            for item in items:
                if root_node == "posts":
                    item["searched_actor"] = query_params.get("actor")

                # allow both [activity.first|activity.last] and [date|created|etc]
                # to be passed as created_col_name argument
                parts = created_col_name.split(".")
                if len(parts) > 1:
                    parent = item.get(parts[0])
                    field = parts[1]
                else:
                    parent = item
                    field = parts[0]
                last_report_timestamp = parent.get(field, last_report_timestamp)

                yield item

            if item_count <= offset + page_size:
                break
        else:
            # When user make invalid URL to make request Intel471 API return
            # 404: Not Found error, we handle that with custom exception on first
            # request from pagination
            raise Intel471Exception(
                'Provided parameters result with "404: not found" error'
            )

        if offset + page_size > 1000:
            # offset is out the range [0-1000]
            # reset offset and move time filters
            offset = 0
            query_params.update({"from": last_report_timestamp, "offset": offset})
        else:
            offset += page_size


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

        self.send_error({
            "code": "ERR-0000",
            "description": f"{ext_type}  failed, service timeout",
            "message": f"{response.text}"})
        raise
    if not response.ok:
        if response.status_code == 404:
            self.send_error({
                "code": "ERR-0000",
                "description": f"{ext_type}  failed, service unavailable",
                "message": f"{response.text}"})
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
        self.send_error({
            "code": "ERR-0000",
            "description": f"{ext_type} failed",
            "message": f"unexpected data type encountered"})
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
        self.send_error({
            "code": "ERR-0000",
            "description": f"{ext_type} failed, authentication error",
            "message": f"{response.text} {response.status_code}."
        })
        pass
    elif response.status_code > 500:
        self.send_error({
            "code": "ERR-0000",
            "description": f"{ext_type} failed, service unavailable",
            "message": f"{response.text}."
        })
        pass
    else:
        self.send_error({
            "code": "ERR-0000",
            "description": f"{ext_type} failed, malformed request",
            "message": f"{response.text}."
        })
        pass


def get_time_params(since: datetime):
    until = now_as_utc()
    from_param = 1000 * int(since.timestamp()) if since else 0
    until_param = 1000 * int(until.timestamp())
    if from_param > until_param:
        raise Intel471Exception(
            "The date and time must not be greater than present time!"
        )
    return from_param, until_param, until


def now_as_utc(*, with_microseconds=True) -> datetime:
    """
    Return a time-zone aware datetime for the current time in UTC.
    """
    dt = datetime.utcnow()
    if not with_microseconds:
        dt = dt.replace(microsecond=0)
    return pytz.utc.localize(dt)


class Intel471Exception(Exception):
    def __init__(self, arg):
        self.strerror = arg
        self.args = {arg}
