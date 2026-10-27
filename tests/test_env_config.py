import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentshield.env_config import load_env


class EnvConfigTests(unittest.TestCase):
    def test_loads_values_and_preserves_process_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text('# comment\nFROM_FILE=plain\nQUOTED="value with spaces"\nexport EXPORTED=\'yes\'\nPRECEDENCE=file\nmalformed\n', encoding='utf-8')
            with patch.dict(os.environ, {'PRECEDENCE': 'process'}, clear=False):
                for name in ('FROM_FILE', 'QUOTED', 'EXPORTED'):
                    os.environ.pop(name, None)
                load_env(path)
                self.assertEqual(os.environ['FROM_FILE'], 'plain')
                self.assertEqual(os.environ['QUOTED'], 'value with spaces')
                self.assertEqual(os.environ['EXPORTED'], 'yes')
                self.assertEqual(os.environ['PRECEDENCE'], 'process')


if __name__ == '__main__':
    unittest.main()
