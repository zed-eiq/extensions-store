import unittest
import json
from parsers import transform_posts


class MyTestCase(unittest.TestCase):

    def test_posts(self):
        with open("intel471_posts_input.json", "r") as f:
            pre_transform = json.loads(f.read())
        with open("intel471_posts_output.json", "r") as f:
            post_transform = json.load(f)
        transformed = transform_posts(pre_transform)
        assert transformed == post_transform


if __name__ == '__main__':
    unittest.main()
