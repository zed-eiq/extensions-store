#!/usr/bin/env python3
import json
from typing import List
from furl import furl
from utils import fetch_results, make_adversary_enricher_extracts
from eiq_edk.schemas.entities import ExtractType
from eiq_edk import EnrichmentProcess


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
        verify_ssl = True
        auth = (api_email, api_key)
        actors_url = furl(api_url).add(path="actors").add({"actor": str(value)}).url
        actors_response = fetch_results(
            self, actors_url, auth, verify_ssl, ext_type="Enricher", params={"count": 100}
        )
        extracts = []
        if actors_response.get("actors"):
            extracts = make_adversary_enricher_extracts(
                actors_response.get("actors"), value
            )
        self.save_enrichment_result(
            entities=[],
            extracts=extracts,
            raw_data=json.dumps(actors_response)
        )
        self.send_info(
            {
                "code": "INF-0003",
                "message": "Execution completed successfully",
                "description": "Intel471 enrich completed successfully."
            }
        )

    def supported_extract_types(self) -> List[ExtractType]:
        return [ExtractType.ACTOR_ID, ExtractType.HANDLE, ExtractType.NAME]


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
