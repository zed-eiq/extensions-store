import unittest
from packer import to_ms_sentinel_json

class MyTestCase(unittest.TestCase):

    def test_pack_data_with_diff_add(self):
        #diff state is add
        ret_data = to_ms_sentinel_json([input_indicator], config)
        self.assertEqual(ret_data, expected_output)  # add assertion here

    def test_pack_data_with_diff_null(self):
        input_indicator['diff'] = 'null'
        ret_data = to_ms_sentinel_json([input_indicator], config)
        self.assertEqual(ret_data, expected_output)

    def test_packer_expired_data(self):
        input_indicator["meta"].update(
            {"estimated_threat_start_time": "2007-11-21T16:19:16"}
        )
        input_indicator['diff'] = 'null'
        config['update_strategy'] = 'REPLACE'
        ret_data = to_ms_sentinel_json([input_indicator], config)
        self.assertEqual(ret_data, None)

        input_indicator['diff'] = 'add'
        config['update_strategy'] = 'APPEND'
        ret_data = to_ms_sentinel_json([input_indicator], config)
        self.assertEqual(ret_data, None)

    def test_packer_deleted_data(self):
        input_indicator['diff'] = 'del'
        config['update_strategy'] = 'DIFF'
        ret_data = to_ms_sentinel_json([input_indicator], config)
        self.assertEqual(ret_data['403f4cf5-98bc-47ef-9bbe-f6e8b574c8c3']['deleted'], True)


config = {
    "update_strategy" : "APPEND",
    "ALLOWED_KINDS" : ["domain", "email", "hash-sha1", "hash-sha256", "uri", "asn"],
    "ALLOWED_STATES" : [
        {"classification": "bad", "confidence": "high"},
        {"classification": "bad", "confidence": "medium"},
        {"classification": "unknown"}]
}
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
    "extracts": [{
        "kind": "domain",
        "value": "test.high.com",
        "meta": {
            "classification": "bad",
            "confidence": "high"
        },
    },
        {
            "kind": "domain",
            "value": "test.medium.com",
            "meta": {
                "classification": "bad",
                "confidence": "medium"
            },
        },

        {
            "kind": "hash-md5",
            "value": "test.md5",
            "meta": {
                "classification": "bad",
                "confidence": "low"
            },
        },

        {
            "kind": "hash-sha1",
            "value": "test.sha1",
            "meta": {
                "classification": "unknown",
                "confidence": "unknown"
            },
        },

        {
            "kind": "hash-sha256",
            "value": "test.sha256",
            "meta": {
                "classification": "good",
                "confidence": "unknown"
            },
        },

        {
            "kind": "asn",
            "value": "This will be skipped",
            "meta": {
                "classification": "bad",
                "confidence": "high"
            },
        },
        {
            "kind": "asn",
            "value": "AS-4200 This will be sent as '4200",
            "meta": {
                "classification": "bad",
                "confidence": "high"
            },
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
                "kind": "ipv4",
                "value": "127.0.0.1",
                "classification": "bad",
                "confidence": "high",
            },
            {
                "kind": "email",
                "value": "someone@email.domain.com",
                "classification": "bad",
                "confidence": "medium",
            },
            {
                "kind": "uri",
                "value": "invalid.uri",
                "classification": "bad",
                "confidence": "high",
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

if __name__ == '__main__':
    unittest.main()
