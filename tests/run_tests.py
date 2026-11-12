"""Run self-contained regression tests without an external APK."""
import argparse
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-decompiler', action='store_true')
    parser.add_argument(
        '--suite',
        choices=('all', 'unit', 'integration', 'gui'),
        default='all',
    )
    args = parser.parse_args()
    if args.require_decompiler and importlib.util.find_spec('dadguard') is None:
        parser.error('dadguard is required; check the source tree')
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_*.py')
    if args.suite != 'all':
        def tests(items):
            for item in items:
                if isinstance(item, unittest.TestSuite):
                    yield from tests(item)
                else:
                    yield item

        def group(test):
            test_id = test.id()
            if ('test_decompiler.DecompilerTests.' in test_id
                    or test_id.endswith('test_archive_is_reproducible_and_runs_outside_checkout')):
                return 'integration'
            if test_id.startswith((
                'test_gui_backend.',
                'test_gui_editor.',
                'test_gui_views.',
                'test_source_edit.',
            )):
                return 'gui'
            return 'unit'

        suite = unittest.TestSuite(
            test for test in tests(suite) if group(test) == args.suite
        )
    if suite.countTestCases() == 0:
        parser.error('selected suite contains no tests')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    # Strict mode rejects skips, except tests gated on an optional extra
    # (e.g. the MCP server) which say so in their skip reason.
    skipped = [
        item for item in result.skipped
        if not str(item[1]).startswith('optional dependency:')
    ]
    sys.exit(0 if result.wasSuccessful() and not (args.require_decompiler and skipped) else 1)
