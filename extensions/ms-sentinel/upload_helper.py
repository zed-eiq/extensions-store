from datetime import datetime
import time
from furl import furl
import requests

REQUESTS_TIMEOUT = 120



class Oauth2Service:

    def __init__(
            self,
            stash,
            auth_url,
            scope_field,
            scope_value,
            tenant_id,
            **kwargs
    ):
        self.user_agent_header = f"EclecticIQ IC/{kwargs['edk_protocol']}-Microsoft Sentinel/{kwargs['version']}"
        self.stash = stash
        self.url = auth_url.format(kwargs['tenant_id'])
        self.data = {
            "CLIENT_ID": kwargs['client_id'],
            "CLIENT_SECRET": kwargs['client_secret'],
            "grant_type": "client_credentials",
            scope_field: scope_value,
        }
        self.headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self.user_agent_header,
        }
        self.tenant_id = tenant_id

    def get_token(self):
        token_data = self.stash
        if token_data and token_data.get(self.tenant_id, dict()).get("access_token"):
            api_data = token_data.get(self.tenant_id)
            created_token_time = api_data.get("created_token_time")
            elapsed_time = datetime.utcnow().timestamp() - created_token_time
            expires_token_in = api_data.get("expires_token_in")
            if int(elapsed_time) > int(expires_token_in):
                token_data = self.create_new_token()
        else:
            token_data = self.create_new_token()
        return token_data.get(self.tenant_id).get("access_token")

    def create_new_token(self):

        response = requests.post(self.url, headers=self.headers, data=self.data)
        data = response.json()
        if data.get("access_token"):
            stash_data = {
                    "access_token": data.get("access_token"),
                    "created_token_time": datetime.utcnow().timestamp(),
                    "expires_token_in": data.get("expires_in"),

            }
            self.stash[self.tenant_id] = stash_data
            return self.stash
        else:
            raise MSSentinelException(
                {
                    'code':'ERR-0000',
                    'description': "OAuth2 couldn't generate token",
                    'message': f'Status code {response.status_code}, response text {response.text}, response reason {data.get("error_description")}'
                }
            )


class MicrosoftSentinelService:

    def __init__(self, url, token_service):
        self.api_url = url
        self.token_service = token_service
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": token_service.user_agent_header,
        }
        self.get_indicators_url = furl(self.api_url).add(path="security/tiIndicators").url
        self.submit_indicators_url = (
            furl(self.api_url).add(path="security/tiIndicators/submitTiIndicators").url
        )
        self.update_indicators_url = (
            furl(self.api_url).add(path="security/tiIndicators/updateTiIndicators").url
        )
        self.delete_multi_external_url = (
            furl(self.api_url)
            .add(path="security/tiIndicators/deleteTiIndicatorsByExternalId")
            .url
        )

    def refresh_headers(self):
        # meant to be used for refreshing oauth2 token
        access_token = self.token_service.get_token()
        self.headers.update({"Authorization": "Bearer " + access_token})

    def get_indicators(self, external_ids=None, already_tried=False):
        self.refresh_headers()
        url = self.get_indicators_url

        if external_ids:
            query = " or ".join(
                [f"externalId eq '{external_id}'" for external_id in external_ids]
            )
            url += f"?$filter={query}"


        response = requests.get(url, headers=self.headers)
        # if there's a quota issue or "UnknownError", try again - API is a beta version
        if self.handle_errors(response) and not already_tried:
            time.sleep(1)
            return self.get_indicators(external_ids, already_tried=True)

        return response.json()["value"]

    def submit_indicators(self, package, already_tried=False):
        self.refresh_headers()
        if not package:
            raise MSSentinelException(
                {
                    'code': 'ERR-0000',
                    'description': f"Service received an empty package to submit.",
                    'message': f'Service received {len(package)}'
                }
            )
        response = requests.post(
            self.submit_indicators_url, headers=self.headers, json={"value": package}
        )
        # if there's a quota issue or "UnknownError", try again - API is a beta version
        if self.handle_errors(response) and not already_tried:
            time.sleep(1)
            return self.submit_indicators(package, already_tried=True)



    def update_indicators(self, package, already_tried=False):
        self.refresh_headers()
        if not package:
            raise MSSentinelException(
                {
                    'code': 'ERR-0000',
                    'description': f"Service received an empty package to update.",
                    'message': f'Service received {len(package)}'
                }
            )

        response = requests.post(
            self.update_indicators_url, headers=self.headers, json={"value": package}
        )
        # if there's a quota issue or "UnknownError", try again - API is a beta version
        if self.handle_errors(response) and not already_tried:
            time.sleep(1)
            return self.update_indicators(package, already_tried=True)


    def delete_indicators(self, package, already_tried=False):
        if not package:
            raise MSSentinelException(
                {
                    'code': 'ERR-0000',
                    'description': f"Service received an empty package to delete.",
                    'message': f'Service received {len(package)}'
                }
            )

        self.refresh_headers()
        the_word = "entities" if len(package) > 1 else "entity"

        response = requests.post(
            self.delete_multi_external_url,
            headers=self.headers,
            json={"value": package},
        )
        if self.handle_errors(response) and not already_tried:
            time.sleep(1)
            return self.delete_indicators(package, already_tried=True)


    @staticmethod
    def handle_errors(response):
        if response.status_code in [429, 504]:
            return True
        if not response.ok:
            raise MSSentinelException(
                {
                    'code': 'ERR-0000',
                    'description': f"{response.text}",
                    'message': f'Status code {response.status_code}, response reason {response.json().get("error", dict()).get("message")}'
                }
            )
    
    
class MSSentinelException(Exception):
    
    def __init__(self, message: dict):
        self.message = message
        super().__init__()

