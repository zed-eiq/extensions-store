#!/usr/bin/env python3
from eiq_edk import EnrichmentProcess
from datetime import datetime
from eiq_edk.schemas.entities import ExtractType
from typing import List

from utils import fetch_with_paging, transform_posts
from furl import furl


class MainApp(EnrichmentProcess):

    def enrich(self, kind: str, value: str):
        self.send_info(
            {
                "code": "INF-0001",
                "message": "Execution started",
                "description": "Intel471 started downloading enrich data"
            }
        )
        api_url = self.config['api_url']
        api_email = self.config['email']
        api_key = self.config['api_key']
        actor = self.config['actor']
        from_param = "0"
        until_param = str(int(datetime.utcnow().timestamp()) * 1000)
        auth = (api_email, api_key)
        posts_url = furl(api_url).add(path="posts").url
        posts_response = list(
            fetch_with_paging(
                self,
                posts_url,
                "postTotalCount",
                "posts",
                "date",
                auth,
                query_params={
                    "from": from_param,
                    "until": until_param,
                    "actor": value or actor,
                    "sort": "relevance",
                },
                verify_ssl=True,
            )
        )
        transformed = transform_posts(posts_response)
        self.save_enrichment_result(entities=[transformed])

        self.send_info(
            {
                "code": "INF-0003",
                "message": "Execution completed successfully",
                "description": "Intel471 enrich completed successfully."
            }
        )

    def supported_extract_types(self) -> List[ExtractType]:
        return [ExtractType.ACTOR_ID, ExtractType.NAME]


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
