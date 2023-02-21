#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from urllib import parse

from eiq_edk import ImporterProcess, create_extract

from utils import DOC_TAGS, DOC_ENTITIES, KIND, make_doc_report, fetch_data


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
        custom_ssl = self.config['custom_ssl']
        verify = True

        delta = datetime.now(timezone.utc) - since
        days, seconds = delta.days, delta.seconds
        hours = days * 24 + seconds // 3600
        query = f"{query} AND fromdate:-{hours}h"
        page = 0
        params = f"pageSize=1000&pageNumber={page}&q={query}&{EXTRAS}"
        params = parse.quote(params, safe="~@#$&()*!+=:;,.?/'")
        verify_ssl = verify or custom_ssl
        data = fetch_data(api_url, params, api_key, shared_key, verify_ssl, method="GET")
        self.save_raw_data(
            json.dumps({"raw_data": data, "timestamp": until.isoformat()}).encode()
        )
        total_result = data["TotalCount"]
        page += 1
        while total_result > page * 1000:
            params = f"pageSize=1000&pageNumber={page}&q={query}&{EXTRAS}"
            params = parse.quote(params, safe="~@#$&()*!+=:;,.?/'")
            verify_ssl = True
            data = fetch_data(
                api_url, params, api_key, shared_key, verify_ssl, method="GET"
            )
            self.save_raw_data(
                json.dumps(data).encode("utf-8")
            )
            page += 1

        self.send_info(
            {
                "code": "INF-0003",
                "message": "Execution completed successfully",
                "description": "Intel471 stored raw data  completed successfully."
            }
        )

    def transform(self, raw_data):

        self.send_info(
            {
                "code": "INF-0001",
                "message": "Execution started",
                "description": "Intel471 started transforming raw data"
            }
        )
        raw_data = json.loads(raw_data.decode("utf-8"))['raw_data']
        items = raw_data.get("Items")
        reports, related_entities = [], []
        for item in items:
            urls, extracts, tags = [], [], []
            observed_time = None
            title = item.get("Description")
            extras = item.get("Extras", {})
            if extras.get("DocumentTeasers"):
                description = extras["DocumentTeasers"].get("HtmlSnippet")
            else:
                description = "No teaser available"
            if extras.get("RelatedEntities"):
                related_entities = extras["RelatedEntities"].get("Items")
            if "." in item.get("FirstReported"):
                start_time = datetime.strptime(
                    item.get("FirstReported"), "%Y-%m-%dT%H:%M:%S.%fZ"
                ).isoformat()
            else:
                start_time = datetime.strptime(
                    item.get("FirstReported"), "%Y-%m-%dT%H:%M:%SZ"
                ).isoformat()
            if "." in item.get("CreatedDate"):
                observed_time = datetime.strptime(
                    item.get("CreatedDate"), "%Y-%m-%dT%H:%M:%S.%fZ"
                ).isoformat()
            else:
                observed_time = datetime.strptime(
                    item.get("CreatedDate"), "%Y-%m-%dT%H:%M:%SZ"
                ).isoformat()
            urls.append(item.get("SourceUrl"))
            urls.append(item.get("SilobreakerUrl"))
            for ent in related_entities:
                ent_type = ent.get("Type")
                ent_value = ent.get("Description")
                if ent_type in DOC_TAGS:
                    tags.append(ent_value)
                if ent_type in DOC_ENTITIES:
                    if ent_type == "Vulnerability":
                        ent_value = ent_value.split("-")
                        if len(ent_value) < 2:
                            continue
                        ent_value = "-".join(ent_value[-2:])
                    kind = KIND.get(ent_type)
                    if kind:
                        extracts.append(create_extract({"kind": kind, "value": ent_value}))
            reports.append(
                make_doc_report(
                    item,
                    urls,
                    title,
                    extracts,
                    tags,
                    description,
                    start_time,
                    observed_time,
                )
            )
        linked_entities = {"type": "linked-entities", "entities": reports}
        self.save_transformed_data(linked_entities)
        self.send_info({
            "code": "INF-0003",
            "message": "Execution completed successfully",
            "description": f"Intel471 transformed data successfully."
        })


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
