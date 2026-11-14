import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "Backend"))


class ConfigurationSecurityTests(unittest.TestCase):
    def test_cors_origins_are_not_wildcard(self):
        sys.modules.pop("config", None)
        config = __import__("config")
        self.assertNotIn("*", config.CORS_ORIGINS)
        sys.modules.pop("config", None)


if __name__ == "__main__":
    unittest.main()
