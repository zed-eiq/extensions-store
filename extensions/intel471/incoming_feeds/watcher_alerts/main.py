#!/usr/bin/env python3
import json
from datetime import datetime

from dateutil import parser
from eiq_edk import ImporterProcess
from furl import furl

from parsers import transform_adversary_report, transform_posts
from utils import fetch_results, fetch_alerts, download_related_reports, REPORT_ENDPOINT


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
        verify = True
        since = parser.isoparse(since)
        verify_ssl = verify
        timestamp = datetime.fromtimestamp(since.timestamp())
        auth = (api_email, api_key)
        alerts = fetch_alerts(
            self, furl(api_url).add(path="alerts").url, auth, timestamp, verify_ssl
        )
        downloaded_alerts = set()
        for alert in alerts:
            if alert["uid"] in downloaded_alerts:
                continue
            downloaded_alerts.add(alert["uid"])
            alert_data = None
            if alert.get("report"):
                report_url = (
                    furl(api_url)
                    .add(path=REPORT_ENDPOINT.format(alert["report"]["uid"]))
                    .url
                )
                report = fetch_results(self, report_url, auth, verify_ssl)
                if report:
                    report["relatedReports"], downloaded_reports = download_related_reports(
                        self,
                        api_url,
                        api_email,
                        api_key,
                        verify_ssl,
                        report.get("relatedReports", []),
                        downloaded_alerts,
                    )
                    alert_data = report
                    alert_data["content_type"] = "intel471_adversary_report"
            if alert.get("post"):
                alert_data = alert.get("post")
                alert_data["content_type"] = "intel471_posts"
            if alert_data:
                timestamp = datetime.utcfromtimestamp(int(alert["foundTime"] / 1000))
                self.save_raw_data(json.dumps({
                        "raw_data": alert_data, "timestamp": timestamp.isoformat()
                    }).encode())

        self.send_info(
            {
                "code": "INF-0003",
                "message": "Execution completed successfully",
                "description": "Intel471 stored raw data  completed successfully."
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

        raw_data = json.loads(raw_data)['raw_data']
        alert_transformer = {
            "intel471_adversary_report": transform_adversary_report,
            "intel471_posts": transform_posts,
        }
        self.save_transformed_data(alert_transformer[raw_data["content_type"]](raw_data))

        self.send_info({
            "code": "INF-0003",
            "message": "Execution completed successfully",
            "description": f"Intel471 transformed data successfully."
        })


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
