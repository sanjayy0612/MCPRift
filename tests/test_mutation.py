from __future__ import annotations

import unittest

from mcprift.mutation import MutationKind, mutation_body


class MutationTests(unittest.TestCase):
    def test_mutations_are_byte_exact_and_deterministic(self) -> None:
        self.assertEqual(mutation_body(MutationKind.INVALID_JSON), b"{")
        self.assertEqual(
            mutation_body(MutationKind.MISSING_JSONRPC),
            b'{"id":"mcprift-mutation","method":"ping","params":{}}',
        )
        self.assertEqual(
            mutation_body(MutationKind.UNKNOWN_METHOD),
            b'{"id":"mcprift-mutation","jsonrpc":"2.0",'
            b'"method":"mcprift/unknown","params":{}}',
        )
        self.assertEqual(mutation_body(MutationKind.EMPTY_BATCH), b"[]")
