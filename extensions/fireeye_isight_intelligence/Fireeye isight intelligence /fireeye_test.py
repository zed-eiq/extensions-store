import unittest
import json
from transformer import transform_reports

class MyTestCase(unittest.TestCase):
    def test_vurnerability(self):
        #working
        data  = None
        with open('tests/fireeye_vulnerability_report.json','r') as f:
            data = f.read()


        data = json.loads(data)
        other_data = None
        with open('tests/fireeye_output_001.json','r') as f:
            other_data = f.read()
        expected_data = json.loads(other_data)

        assert_data = transform_reports(data['message']['report'])
        self.assertEqual(assert_data, expected_data)  # add assertion here

    def test_malware_report(self):
        #data is same but without observables
        data = None
        with open('tests/fireeye_malware_report.json', 'r') as f:
            data = f.read()

        data = json.loads(data)
        other_data = None
        with open('tests/fireeye_output_002.json', 'r') as f:
            other_data = f.read()
        expected_data = json.loads(other_data)

        assert_data = transform_reports(data['message']['report'])
        print(assert_data)
        self.assertEqual(assert_data, expected_data)  # add assertion here


    def test_threat_report(self):
        #data is good but without observables in indicator
        data = None
        with open('tests/fireeye_threat_report.json', 'r') as f:
            data = f.read()

        data = json.loads(data)
        other_data = None
        with open('tests/fireeye_output_003.json', 'r') as f:
            other_data = f.read()
        expected_data = json.loads(other_data)

        assert_data = transform_reports(data['message']['report'])

        self.assertEqual(assert_data, expected_data)  # add assertion here


    def test_missing_url(self):
        #working
        data = None
        with open('tests/fireeye_vulnerability_report_missing_url.json', 'r') as f:
            data = f.read()

        data = json.loads(data)
        other_data = None
        with open('tests/fireeye_output_004.json', 'r') as f:
            other_data = f.read()
        expected_data = json.loads(other_data)

        assert_data = transform_reports(data['message']['report'])

        self.assertEqual(assert_data, expected_data)  # add assertion here'''


    def test_malware_overview(self):
        #working
        data = None
        with open('tests/fireeye_malware_overview_report.json', 'r') as f:
            data = f.read()

        data = json.loads(data)
        other_data = None
        with open('tests/fireeye_output_005.json', 'r') as f:
            other_data = f.read()
        expected_data = json.loads(other_data)

        assert_data = transform_reports(data['message']['report'])

        self.assertEqual(assert_data, expected_data)  # add assertion here'''


    def test_actor_overview_report(self):
        #working
        data = None
        with open('tests/fireeye_actor_overview_report.json', 'r') as f:
            data = f.read()

        data = json.loads(data)
        other_data = None
        with open('tests/fireeye_output_006.json', 'r') as f:
            other_data = f.read()
        expected_data = json.loads(other_data)

        assert_data = transform_reports(data['message']['report'])

        self.assertEqual(assert_data, expected_data)  # add assertion here'''

if __name__ == '__main__':
    unittest.main()
