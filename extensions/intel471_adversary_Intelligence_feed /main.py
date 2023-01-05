#!/usr/bin/env python3
import json
import math
from datetime import datetime
import pytz

from dateutil import parser
from eiq_edk import ImporterProcess
from furl import furl


from parsers import parse_indicators, parse_ttps, parse_report
from utils import batch, fetch_results, fetch_with_paging, get_time_params, Intel471Exception, REPORT_ENDPOINT





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
        api_email = self.config['email']
        api_key = self.config['api_key']
        since = self.config['since']
        until = self.config['until']
        verify = True
        since = parser.isoparse(since)
        from_param, until_param, until = get_time_params(since)
        reports_stream = fetch_with_paging(
            furl(api_url).add(path="reports").url,
            "reportTotalCount",
            "reports",
            "created",
            auth=(api_email, api_key),
            query_params={"from": from_param, "until": until_param, "sort": "earliest"},
            verify_ssl=verify,
        )

        downloaded_reports = set()
        for chunk in batch(reports_stream, 10):
            processed_reports = 0
            for report in chunk:
                if report["uid"] in downloaded_reports:
                    continue
                downloaded_reports.add(report["uid"])
                report_url = (
                    furl(api_url).add(path=REPORT_ENDPOINT.format(report["uid"])).url
                )
                detailed_report = fetch_results(
                    report_url, auth=(api_email, api_key), verify_ssl=verify
                )

                if not detailed_report:
                    continue

                timestamp = None
                if report.get("created"):
                    timestamp = datetime.datetime.utcfromtimestamp(
                        report.get("created") / 1000
                    )

                self.save_raw_data({
                    "raw_data": detailed_report, "timestamp": timestamp.isoformat()
                })
                processed_reports += 1

                self.send_info(
                    {
                        "code": "INF-0003",
                        "message": "Execution completed successfuly",
                        "description": "Intel471 stored raw data  completed successfuly."
                    }
                )

    def transform(self, raw_data=None):

        self.send_info(
            {
                "code": "INF-0001",
                "message": "Execution started",
                "description": "Intel471 started transforming raw data"
            }
        )

        raw_data = json.loads(raw_data.decode("utf-8"))['raw_data']
        entities, relations = [], []
        feed_type = raw_data.get("feed_type")
        parse_indicators([raw_data["indicator"]], entities, relations, feed_type)
        parse_ttps(
            [raw_data["indicator"]],
            entities,
            relations,
            raw_report=raw_data["report"] if raw_data.get("report") else None,
            feed_type=feed_type
        )
        if raw_data.get("report"):
            report, report_relation = parse_report(raw_data["report"], entities)
            entities.extend(report)
            relations.extend(report_relation)
        linked_entities = {
            "type": "linked-entities",
            "entities": entities,
            "relations": relations,
        }

        self.save_transformed_data(linked_entities)
        self.send_info({
            "code": "INF-0003",
            "message": "Execution completed successfuly",
            "description": f"Intel471 transformed data successfuly."
        })


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
