from urllib import parse
import furl
import requests
import base64
import time
import hmac
import hashlib
from simplejson import errors
from email import utils

EXTENSION_NAME = "Fire Eye"
PLATFORM_VERSION = '1'
EXTENSION_VERSION = '0.1'
USER_AGENT = f"EclecticIQ IC/{PLATFORM_VERSION} {EXTENSION_NAME}/{EXTENSION_VERSION}"
ACCEPT_VERSION = "2.6"
REQUESTS_TIMEOUT = 120
SERVICE_TIMEOUT = 5  # seconds
PAGE_SIZE = 1000



def get_reports_list(
    api_url: str,
    search_path: str,
    public_key: str,
    private_key: str,
    verify_ssl: bool,
    ext_type: str,
    params: dict,
) -> list[dict]:
    results = []
    offset = 0
    while True:
        params.update({"offset": offset})
        query = "?" + parse.urlencode(params)
        reports_list, _ = send_reports_query(
            ext_type, public_key, private_key, verify_ssl, api_url, search_path, query
        )
        results.extend(reports_list)
        if len(reports_list) == PAGE_SIZE:
            offset += PAGE_SIZE
            continue
        break
    return results



def send_reports_query(
    ext_type: str,
    public_key: str,
    private_key: str,
    verify_ssl: bool,
    api_url: str,
    path: str,
    query: str,
):
    content_type = "application/json"
    headers = make_headers(public_key, private_key, path + query, content_type)
    url = furl.furl(api_url).add(path=path).url + query
    response = make_request(
        ext_type=ext_type, url=url, headers=headers, verify=verify_ssl
    )
    # 200+ responses are expected - 200 = OK
    # 204 = Not Found (return empty array)
    # 400+ status = request not valid (authentication, parameters etc)
    if response.status_code == 204:
        return [], response.content
    try:
        return response.json()["message"], response.content
    except ValueError:
        raise FireeyeException({
            'code' : 'ERR-0000',
            'description': 'Unexpected data type encountered',
            'message' : f"{ext_type} failed, unexpected data type encountered"
        })



def get_report(
    api_url: str,
    public_key: str,
    private_key: str,
    report: str,
    verify_ssl: bool,
    ext_type: str,
    pdf: bool = False,
):
    report_query = "report/{}".format(report)
    content_type = "application/pdf" if pdf else "application/json"
    headers = make_headers(public_key, private_key, report_query, content_type)
    url = furl.furl(api_url).add(path=report_query).url

    # 200+ responses are expected
    # 200 = OK
    # 204 or 404 = Not Found (return None)
    # 400+ status = request not valid (authentication, parameters etc)
    response = None
    try:
        response = make_request(
            ext_type=ext_type, url=url, headers=headers, verify=verify_ssl
        )
    except requests.exceptions.HTTPError:
        # handle report downloads gracefully, don't break the feed
        if pdf:
            raise  FireeyeWarningException({
                'code': 'WAR-0001',
                'description': "PDF file couldn't be downloaded for report",
                'message': f"PDF file couldn't be downloaded for response {response}"
            })
        else:
            raise FireeyeWarningException({
                'code': 'WAR-0001',
                'description': "Report not found.",
                'message': f"Response {response} not found."
            })

    if response.status_code == 204:
        return None
    try:
        if pdf:
            return base64.b64encode(response.content).decode()
        else:
            return response.json()["message"]["report"]
    except ValueError:
        raise FireeyeException({
            'code': 'ERR-0000',
            'description': "failed, unexpected data type encountered",
            'message': f"{ext_type} failed, unexpected data type encountered"
        })




def make_request(ext_type: str, **kwargs) -> requests.Response:
    already_tried = kwargs.pop("already_tried", False)
    kwargs["timeout"] = REQUESTS_TIMEOUT
    try:
        response = requests.get(**kwargs)
    except requests.Timeout:
        raise FireeyeException({
            'code': 'ERR-0000',
            'description': "Failed, service timed out",
            'message': f"{ext_type} failed, service timed out"
        })

    if not response.ok:
        try:
            fireeye_message = response.json().get("message", dict()).get("description")
        except errors.JSONDecodeError:
            fireeye_message = None
        message = fireeye_message or response.text
        response.reason = fireeye_message or response.reason

        if response.status_code >= 500 and not already_tried:

            time.sleep(SERVICE_TIMEOUT)
            kwargs["already_tried"] = True
            return make_request(ext_type, **kwargs)

        response.raise_for_status()
    return response


# generate time-based password
def make_headers(
    public_key: str, private_key: str, query: str, content_type: str
) -> dict:
    time_stamp = utils.formatdate(localtime=True)
    raw_string = "/" + query + ACCEPT_VERSION + content_type + time_stamp
    hashed = hmac.new(private_key.encode(), raw_string.encode(), hashlib.sha256)
    return {
        "Accept": content_type,
        "Accept-Version": ACCEPT_VERSION,
        "X-Auth": public_key,
        "X-Auth-Hash": hashed.hexdigest(),
        "X-App-Name": "EclecticIQ Platform",
        "Date": time_stamp,
        "User-Agent": USER_AGENT,
    }



class FireeyeException(Exception):
    
    def __init__(self, message):
        self.message = message
        super().__init__()



class FireeyeWarningException(Exception):

    def __init__(self, message):
        self.message = message
        super().__init__()