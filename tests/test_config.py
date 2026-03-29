from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from har_analyzer.config import _load_env_file, get_default_unsafe_unredacted, load_run_config


class ConfigTests(unittest.TestCase):
    def test_load_run_config_uses_env_default_for_unsafe_artifacts(self):
        with mock.patch.dict(os.environ, {"HAR_ANALYZER_UNSAFE_UNREDACTED_DEFAULT": "true"}, clear=False):
            config = load_run_config("fixture.har", ["api.example.com"])
        self.assertTrue(config.allow_unsafe_artifacts)

    def test_env_default_helper_returns_false_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(get_default_unsafe_unredacted())

    def test_env_file_overrides_stale_process_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text("HAR_ANALYZER_MODEL=zai-org/GLM-5\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"HAR_ANALYZER_MODEL": "MiniMaxAI/MiniMax-M2.5"}, clear=False):
                _load_env_file(env_path)
                self.assertEqual(os.environ["HAR_ANALYZER_MODEL"], "zai-org/GLM-5")


if __name__ == "__main__":
    unittest.main()
