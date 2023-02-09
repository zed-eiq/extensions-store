import itertools
import re
import sys
import uuid
from datetime import datetime
from typing import Tuple
import validators
from eiq_edk.schemas.entities import ExtractType
from eiq_edk import create_entity
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
            self.send_error(
                {
                    "code": "404",
                    "description": "Not Found error, we handle that with custom exception on first",
                    "message": f"API returned error for {api_url}",
                }
            )
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


def fetch_with_cursor(
        self,
        api_url,
        root_node,
        auth,
        query_params,
        verify_ssl,
):
    response = fetch_results(
        self, url=api_url, auth=auth, verify_ssl=verify_ssl, params=query_params
    )
    if response:
        while response.get("cursorNext"):
            if not response.get(root_node, []):
                break
            items = response.get(root_node, [])
            for item in items:
                yield item
            query_params["cursor"] = response.get("cursorNext")
            response = fetch_results(
                self, url=api_url, auth=auth, verify_ssl=verify_ssl, params=query_params
            )
    else:
        self.send_error(
            {
                "code": "404",
                "description": "3rd party connector error",
                "message": f"An error occurred during contacting 3rd party  {api_url}. Aborting.",
            }
        )
        pass

    if response.get("indicatorTotalCount") == 0:
        self.send_warning(
            {
                "code": "WAR-0001",
                "message": "No results",
                "description": "Provider finished with no results.",
            }
        )
        pass


def transform_posts(posts: list) -> list:
    entities = []
    if isinstance(posts, dict):
        posts = [posts]
    if posts:
        entities.append(create_posts_report(posts))
    return entities


def create_posts_report(posts: list) -> dict:
    if posts[0].get("content_type"):
        actor = posts[0].get("links").get("authorActor").get("handle")
    else:
        actor = posts[0]["searched_actor"]

    analysis, tags = create_post_analysis_tags(posts, actor)

    extracts = [{'kind': ExtractType.ACTOR_ID.value, 'value': actor}]
    for post in posts:
        forum = post.get("links").get("forum")
        if not forum:
            continue
        domain_check = validators.domain(forum.get("name"))
        if domain_check:
            extracts.append(
                {
                    'kind': ExtractType.DOMAIN.value, 'value': forum.get("name"), 'classification': "unknown"
                }
            )
        else:
            extracts.append(
                {
                    'kind': ExtractType.FORUM_NAME.value, 'value': forum.get("name"), 'classification': "unknown"
                }
            )

    # filter empty extracts

    extracts = [i for i in extracts if i]
    _id = "{{https://intel471.com/}}Report-{}".format(
        str(uuid.uuid5(uuid.NAMESPACE_X500, str(actor)))
    )

    data = {
        "id": _id,
        'title': f"Intel 471 Forum Posts - {actor}",
        'description': analysis
    }
    meta = {
        'estimated_observed_time': set_dates(posts),
        'tags': tags,
        'bundled_extracts': extracts
    }
    post_report = create_entity({'data': data, 'meta': meta, "type": "report"})
    return post_report


def set_dates(posts: list) -> str:
    dates = []
    for post in posts:
        dates.append(post["date"])
    date = datetime.utcfromtimestamp(min(dates) / 1000).isoformat()
    return date


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
        post_date = datetime.utcfromtimestamp(post["date"] / 1000).isoformat()
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


class Intel471Exception(Exception):
    def __init__(self, arg):
        self.strerror = arg
        self.args = {arg}
