import os
import sys
import unittest
from unittest.mock import patch

import dotenv

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "Backend"))


class ConfigurationSecurityTests(unittest.TestCase):
    def test_required_secrets_have_no_fallback(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(dotenv, "load_dotenv", return_value=False):
                sys.modules.pop("config", None)
                with self.assertRaisesRegex(RuntimeError, "OXVISUAL_SECRET_KEY"):
                    __import__("config")
        sys.modules.pop("config", None)

    def test_cors_origins_are_not_wildcard(self):
        with patch.dict(
            os.environ,
            {
                "OXVISUAL_SECRET_KEY": "test-secret",
                "OXVISUAL_SUPERADMIN_PASSWORD": "test-password",
            },
            clear=True,
        ):
            sys.modules.pop("config", None)
            config = __import__("config")
            self.assertNotIn("*", config.CORS_ORIGINS)
        sys.modules.pop("config", None)


if __name__ == "__main__":
    unittest.main()
