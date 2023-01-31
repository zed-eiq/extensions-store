import json
import unittest
from packer import to_ms_sentinel_json
from upload_helper import Oauth2Service, MicrosoftSentinelService
from process import populate_indicator_lists


class MyTestCase(unittest.TestCase):
    def test_pack_data_with_diff_add(self):
        # diff state is add
        ret_data = to_ms_sentinel_json([my_test_case_input])
        print(ret_data)
        self.assertEqual(ret_data, my_test_case)  # add assertion here

        deleted_indicators = []
        new_indicators = []
        populate_indicator_lists(
            new_indicators,
            deleted_indicators,
            ret_data,
            "APPEND",
        )
        print("Data data")
        print(new_indicators)


input_indicator = {
    "data": {
        "id": "{{http://www.eclecticiq.com/}}indicator-{123}",
        "title": "test.com",
        "type": "indicator",
        "types": [{"value": "Anonymization"}],
        "confidence": {"type": "confidence", "value": "High"},
        "likely_impact": {
            "type": "statement",
            "value": "High",
            "value_vocab": (
                "{http://stix.mitre.org/default_vocabularies-1}"
                "HighMediumLowVocab-1.0"
            ),
        },
        "description": "This is a test",
        "timestamp": "2017-11-21T16:19:16",
        "producer": {
            "description": "https://www.eclecticiq.com",
            "type": "information-source",
            "identity": {"name": "unit test", "type": "identity"},
        },
    },
    "diff": "add",
    "id": "403f4cf5-98bc-47ef-9bbe-f6e8b574c8c3",
    "extracts": [
        {
            "kind": "domain",
            "value": "test.high.com",
            "meta": {"classification": "bad", "confidence": "high"},
        },
        {
            "kind": "domain",
            "value": "test.medium.com",
            "meta": {"classification": "bad", "confidence": "medium"},
        },
        {
            "kind": "hash-sha1",
            "value": "test.sha1",
            "meta": {"classification": "unknown", "confidence": "unknown"},
        },
        {
            "kind": "asn",
            "value": "AS-4200 This will be sent as '4200",
            "meta": {"classification": "bad", "confidence": "high"},
        },
    ],
    "meta": {
        "estimated_threat_start_time": "2117-11-21T16:19:16",
        "estimated_observed_time": "2017-11-21T16:19:16",
        "tags": ["test"],
        "taxonomy_paths": [
            ["Kill chain phase", "Kill chain phase - Reconnaissance Artifacts"],
            ["Admiralty", "Admiralty - Credibility", "Admiralty - Possibly True"],
        ],
        "tlp_color": "AMBER",
        "half_life": 30,
        "bundled_extracts": [
            {
                "kind": "email",
                "value": "someone@email.domain.com",
                "classification": "bad",
                "confidence": "medium",
            },
        ],
    },
}

expected_output = {
    "403f4cf5-98bc-47ef-9bbe-f6e8b574c8c3": {
        "email:someone@email.domain.com": {
            "action": "alert",
            "targetProduct": "Azure Sentinel",
            "externalId": "403f4cf5-98bc-47ef-9bbe-f6e8b574c8c3",
            "description": "Entity from EclecticIQ Platform. test.com",
            "tlpLevel": "amber",
            "confidence": 100,
            "severity": 5,
            "threatType": "Proxy",
            "expirationDateTime": "2117-12-21T16:19:16",
            "lastReportedDateTime": "2017-11-21T16:19:16",
            "tags": [
                "test",
                "Kill chain phase - Reconnaissance Artifacts",
                "Admiralty - Possibly True",
            ],
            "killChain": ["Reconnaissance"],
            "fileHashType": None,
            "networkSourceAsn": None,
            "domainName": None,
            "emailSenderAddress": "someone@email.domain.com",
            "emailSourceDomain": "email.domain.com",
            "emailSubject": None,
            "fileName": None,
            "fileHashValue": None,
            "networkIPv4": None,
            "networkIPv6": None,
            "fileMutexName": None,
            "networkPort": None,
            "url": None,
            "isActive": True,
        },
        "domain:test.high.com": {
            "action": "alert",
            "targetProduct": "Azure Sentinel",
            "externalId": "403f4cf5-98bc-47ef-9bbe-f6e8b574c8c3",
            "description": "Entity from EclecticIQ Platform. test.com",
            "tlpLevel": "amber",
            "confidence": 100,
            "severity": 5,
            "threatType": "Proxy",
            "expirationDateTime": "2117-12-21T16:19:16",
            "lastReportedDateTime": "2017-11-21T16:19:16",
            "tags": [
                "test",
                "Kill chain phase - Reconnaissance Artifacts",
                "Admiralty - Possibly True",
            ],
            "killChain": ["Reconnaissance"],
            "fileHashType": None,
            "networkSourceAsn": None,
            "domainName": "test.high.com",
            "emailSenderAddress": None,
            "emailSourceDomain": None,
            "emailSubject": None,
            "fileName": None,
            "fileHashValue": None,
            "networkIPv4": None,
            "networkIPv6": None,
            "fileMutexName": None,
            "networkPort": None,
            "url": None,
            "isActive": True,
        },
        "domain:test.medium.com": {
            "action": "alert",
            "targetProduct": "Azure Sentinel",
            "externalId": "403f4cf5-98bc-47ef-9bbe-f6e8b574c8c3",
            "description": "Entity from EclecticIQ Platform. test.com",
            "tlpLevel": "amber",
            "confidence": 100,
            "severity": 5,
            "threatType": "Proxy",
            "expirationDateTime": "2117-12-21T16:19:16",
            "lastReportedDateTime": "2017-11-21T16:19:16",
            "tags": [
                "test",
                "Kill chain phase - Reconnaissance Artifacts",
                "Admiralty - Possibly True",
            ],
            "killChain": ["Reconnaissance"],
            "fileHashType": None,
            "networkSourceAsn": None,
            "domainName": "test.medium.com",
            "emailSenderAddress": None,
            "emailSourceDomain": None,
            "emailSubject": None,
            "fileName": None,
            "fileHashValue": None,
            "networkIPv4": None,
            "networkIPv6": None,
            "fileMutexName": None,
            "networkPort": None,
            "url": None,
            "isActive": True,
        },
        "hash-sha1:test.sha1": {
            "action": "alert",
            "targetProduct": "Azure Sentinel",
            "externalId": "403f4cf5-98bc-47ef-9bbe-f6e8b574c8c3",
            "description": "Entity from EclecticIQ Platform. test.com",
            "tlpLevel": "amber",
            "confidence": 100,
            "severity": 5,
            "threatType": "Proxy",
            "expirationDateTime": "2117-12-21T16:19:16",
            "lastReportedDateTime": "2017-11-21T16:19:16",
            "tags": [
                "test",
                "Kill chain phase - Reconnaissance Artifacts",
                "Admiralty - Possibly True",
            ],
            "killChain": ["Reconnaissance"],
            "fileHashType": "sha1",
            "networkSourceAsn": None,
            "domainName": None,
            "emailSenderAddress": None,
            "emailSourceDomain": None,
            "emailSubject": None,
            "fileName": None,
            "fileHashValue": "test.sha1",
            "networkIPv4": None,
            "networkIPv6": None,
            "fileMutexName": None,
            "networkPort": None,
            "url": None,
            "isActive": True,
        },
        "asn:4200": {
            "action": "alert",
            "targetProduct": "Azure Sentinel",
            "externalId": "403f4cf5-98bc-47ef-9bbe-f6e8b574c8c3",
            "description": "Entity from EclecticIQ Platform. test.com",
            "tlpLevel": "amber",
            "confidence": 100,
            "severity": 5,
            "threatType": "Proxy",
            "expirationDateTime": "2117-12-21T16:19:16",
            "lastReportedDateTime": "2017-11-21T16:19:16",
            "tags": [
                "test",
                "Kill chain phase - Reconnaissance Artifacts",
                "Admiralty - Possibly True",
            ],
            "killChain": ["Reconnaissance"],
            "fileHashType": None,
            "networkSourceAsn": "4200",
            "domainName": None,
            "emailSenderAddress": None,
            "emailSourceDomain": None,
            "emailSubject": None,
            "fileName": None,
            "fileHashValue": None,
            "networkIPv4": None,
            "networkIPv6": None,
            "fileMutexName": None,
            "networkPort": None,
            "url": None,
            "isActive": True,
        },
    }
}

my_test_case_input = {
    "attachments": [],
    "data": {
        "confidence": {"type": "confidence", "value": "Unknown"},
        "description": "<head></head><body><p>Test</p></body>",
        "description_structuring_format": "html",
        "id": "{http://not-yet-configured.example.org/}indicator-dc690c91-d83b-4929-ad65-66d5571df1e1",
        "likely_impact": {
            "type": "statement",
            "value": "Unknown",
            "value_vocab": "{http://stix.mitre.org/default_vocabularies-1}HighMediumLowVocab-1.0",
        },
        "short_description": "<head></head><body></body>",
        "timestamp": "2023-01-25T13:48:50.941459+00:00",
        "title": "Old Sentinel Indicator",
        "type": "indicator",
        "types": [{"value": "IP Watchlist"}],
    },
    "enrichment_extracts": [],
    "external_url": "https://default/entity/dc690c91-d83b-4929-ad65-66d5571df1e1",
    "extracts": [
        {
            "instance_meta": {"link_types": ["observed"], "paths": []},
            "kind": "ipv4",
            "meta": {"classification": "bad", "confidence": "low"},
            "value": "1.1.1.1",
        }
    ],
    "id": "dc690c91-d83b-4929-ad65-66d5571df1e1",
    "meta": {
        "estimated_observed_time": "2023-01-25T13:48:50.941459+00:00",
        "estimated_threat_start_time": "2023-01-25T13:48:50.941459+00:00",
        "first_ingest_time": "2023-01-25T13:48:50.941459+00:00",
        "half_life": 30,
        "ingest_time": "2023-01-25T13:48:50.941459+00:00",
        "source_reliability": None,
        "tags": [],
        "title": "Old Sentinel Indicator",
        "tlp_color": None,
    },
    "relevancy": 0.8908987181403393,
    "sources": [
        {
            "name": "Testing Group",
            "source_id": "8a1b12c2-0435-481c-9333-5380e1173c21",
            "source_type": "group",
        }
    ],
}


my_test_case = {
    "dc690c91-d83b-4929-ad65-66d5571df1e1": {
        "ipv4:1.1.1.1": {
            "action": "alert",
            "targetProduct": "Azure Sentinel",
            "externalId": "dc690c91-d83b-4929-ad65-66d5571df1e1",
            "description": "Entity from EclecticIQ Platform. Old Sentinel Indicator",
            "tlpLevel": "unknown",
            "confidence": 0,
            "severity": 1,
            "threatType": "WatchList",
            "expirationDateTime": "2023-02-24T13:48:50.941459+00:00",
            "lastReportedDateTime": "2023-01-25T13:48:50.941459+00:00",
            "tags": [],
            "killChain": [],
            "isActive": True,
            "networkSourceAsn": None,
            "domainName": None,
            "emailSenderAddress": None,
            "emailSourceDomain": None,
            "emailSubject": None,
            "fileName": None,
            "fileHashValue": None,
            "networkIPv4": "1.1.1.1",
            "networkIPv6": None,
            "fileMutexName": None,
            "networkPort": None,
            "url": None,
            "fileHashType": None,
        }
    }
}

if __name__ == "__main__":
    unittest.main()
