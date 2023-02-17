import unittest
from parsers import transform_adversary_report
import json


class MyTestCase(unittest.TestCase):
    def test_transform_adversary_valid(self):
        with open("intel471_adversary_feed_input.json", "r") as f:
            pre_transform = json.loads(f.read())
        with open("intel471_adversary_feed_output.json", "r") as f:
            post_transform = json.load(f)
        transformed = transform_adversary_report(
            json.dumps(pre_transform).encode("utf-8")
        )
        assert transformed == post_transform


if __name__ == "__main__":
    unittest.main()
