from __future__ import annotations

import unittest

from mcprift.registry import default_registry


class RegistryTests(unittest.TestCase):
    def test_default_registry_is_stable_and_rejects_duplicates(self) -> None:
        registry = default_registry(
            alice_token="alice",
            bob_token="bob",
            invalid_token="invalid",
            expired_token="expired",
        )

        self.assertEqual(len(registry.all()), 9)
        with self.assertRaises(ValueError):
            registry.register(registry.all()[0])
