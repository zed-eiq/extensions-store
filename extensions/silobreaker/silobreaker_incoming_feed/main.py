#!/usr/bin/env python3
import json
from datetime import datetime, timezone
import urllib

from eiq_edk import ImporterProcess
from utils import fetch_data

API_URL = "https://api.silobreaker.com/search/documents"

EXTRAS = (
    "extras=documentTeasers&extras=relatedEntities"
    "&EntityTypes=threatactor,malware,attacktype,malware,vulnerability,keyphrase,hashtag"
)


class MainApp(ImporterProcess):

    def download(self):
        self.send_info(
            {
                "code": "INF-0001",
                "message": "Execution started",
                "description": "Intel471 started downloading data"
            }
        )
        api_url = self.config['api_url']
        api_key = self.config['api_key']
        since = self.config['since']
        until = self.config['until']
        shared_key = self.config['shared_key']
        query = self.config['query']

        delta = datetime.now(timezone.utc) - since
        days, seconds = delta.days, delta.seconds
        hours = days * 24 + seconds // 3600
        query = f"{query} AND fromdate:-{hours}h"
        page = 0
        params = f"pageSize=1000&pageNumber={page}&q={query}&{EXTRAS}"
        params = urllib.parse.quote(params, safe="~@#$&()*!+=:;,.?/'")
        verify_ssl = True
        data = fetch_data(api_url, params, api_key, shared_key, verify_ssl, method="GET")
        self.save_raw_data(
            json.dumps(data).encode("utf-8"),
            content_type=silobreaker_document.id,
            timestamp=ensure_aware(until),
        )
        total_result = data["TotalCount"]
        page += 1
        while total_result > page * 1000:
            params = f"pageSize=1000&pageNumber={page}&q={query}&{EXTRAS}"
            params = urllib.parse.quote(params, safe="~@#$&()*!+=:;,.?/'")
            verify_ssl = custom_ssl or verify
            data = fetch_data(
                api_url, params, api_key, shared_key, verify_ssl, method="GET"
            )
            ctx.submit(
                json.dumps(data).encode("utf-8"),
                content_type=silobreaker_document.id,
            )
            page += 1

        log.info("Silobreaker Feed execution finished")

    def transform(self, raw_data):
        print("Transform single package of raw data. Add your code here")


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
