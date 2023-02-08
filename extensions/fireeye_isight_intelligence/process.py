#!/usr/bin/env python3
import json
import math

from dateutil import parser
from eiq_edk import ImporterProcess
from marshmallow.exceptions import ValidationError

from transformer import transform_reports
from utils import get_report, get_reports_list, FireeyeException, FireeyeWarningException

PAGE_SIZE = 1000


class MainApp(ImporterProcess):

    def download(self):
        self.send_info({
            "code": "INF-0001",
            "message": "Download started",
            "description": "Fireeye isight intelligence started downloading data",
        })

        since = self.config['since']
        until = self.config['until']
        api_url: str = self.config['api_url']
        public_key: str = self.config['public_key']
        private_key: str = self.config['private_key']

        verify_ssl: bool = True
        ssl_cert: str = ''
        include_threats: bool = True
        include_malwares: bool = True
        include_vulnerabilities: bool = True
        include_overviews: bool = True
        download_pdf: bool = True
        verify_ssl = ssl_cert or verify_ssl

        since = parser.isoparse(since)
        until = parser.isoparse(until)
        # if until - since >= 90 days, we have to submit multiple queries
        max_offset = 90 * 86400 - 1  # 90 days minus 1 second
        since_timestamp = math.floor(since.timestamp())
        until_timestamp = math.floor(until.timestamp())
        types_param = create_types_param(
            include_threats, include_malwares, include_vulnerabilities, include_overviews
        )
        reports_list = []
        reports_chunk = None

        while since_timestamp < until_timestamp:
            max_until = min(since_timestamp + max_offset, until_timestamp)
            params = {
                "startDate": since_timestamp,
                "endDate": max_until,
                "intelligenceType": types_param,
                "limit": PAGE_SIZE,
                "sortBy": "publishDate:asc",
            }
            try:
                reports_chunk = get_reports_list(
                    api_url, "report/index", public_key, private_key, verify_ssl,
                    'fireeye', params
                )
            except FireeyeException as ex:
                self.send_error(ex.message)
            except FireeyeWarningException as ex:
                self.send_warning(ex.message)
            reports_list.extend(reports_chunk)
            since_timestamp += max_offset

        report_ids = set()
        # set a default timestamp, but there's 0.0002%
        # it will be ever submitted with a blob
        timestamp = math.floor(since.timestamp())
        for item in reports_list:
            if item["reportId"] in report_ids:
                continue
            report_ids.add(item["reportId"])

            report = get_report(
                api_url, public_key, private_key, item["reportId"], verify_ssl,
                'ext_type'
            )
            if not report:
                continue
            if item.get("publishDate"):
                timestamp = max(item.get("publishDate"), timestamp)
            if download_pdf:
                report_file = get_report(
                    api_url,
                    public_key,
                    private_key,
                    item["reportId"],
                    verify_ssl,
                    'fireeye',
                    pdf=True,
                )
                if report_file:
                    report["attachment"] = {
                        "filename": f"{item['title']}.pdf",
                        "data": report_file,
                    }
            # timestamp is increased by a second to avoid downloading duplicates
        self.save_raw_data(json.dumps(reports_list).encode())
        self.send_info(
            {
                "code": "INF-0001",
                "message": "Download finished",
                "description": "Fireeye isight intelligence ended downloading data",
            }
        )

    def transform(self, raw_data):
        self.send_info({
            "code": "INF-0001",
            "message": "Transform started",
            "description": "Fireeye isight intelligence started transforming data",
        })

        data_to_transform = None

        try:
            data_to_transform = transform_reports(json.loads(raw_data))
        except ValidationError as ex:
            self.send_error({
                "code": "ERR-0000",
                "message": "Validation error while transforming data",
                "description": f"Fireeye isight intelligence failed to "
                               f"transform data {data_to_transform}, "
                               f"error : {ex.messages}",
            })

        self.save_transformed_data(data_to_transform)
        self.send_info({
            "code": "INF-0001",
            "message": "Transforming finished",
            "description": "Fireeye isight intelligence ended transforming data",
        })


def create_types_param(
        include_threats: bool,
        include_malwares: bool,
        include_vulnerabilities: bool,
        include_overviews: bool,
) -> str:
    intelligence_types = []
    if include_threats:
        intelligence_types.append("threat")
    if include_malwares:
        intelligence_types.append("malware")
    if include_vulnerabilities:
        intelligence_types.append("vulnerability")
    if include_overviews:
        intelligence_types.append("overview")
    if not intelligence_types:
        return ""
    return ",".join(intelligence_types)


if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()
