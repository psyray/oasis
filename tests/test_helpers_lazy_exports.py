"""Sanity-check lazy re-exports on oasis.helpers (catches typos between __all__ and _LAZY_IMPORTS)."""

import unittest


class TestHelpersLazyExports(unittest.TestCase):
    def test_lazy_import_map_matches_all_and_symbols_resolve(self):
        import oasis.helpers as helpers

        names = getattr(helpers, "__all__", ())
        lazy = getattr(helpers, "_LAZY_IMPORTS", {})
        self.assertEqual(
            set(names),
            set(lazy),
            "__all__ and _LAZY_IMPORTS keys must match exactly",
        )
        for name in names:
            with self.subTest(name=name):
                obj = getattr(helpers, name)
                self.assertIsNotNone(obj)


if __name__ == "__main__":
    unittest.main()
