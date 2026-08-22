from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcprift.assessment import load_assessment, write_lab_template
from mcprift.client import ConnectionFailure


class AssessmentTests(unittest.TestCase):
    def test_lab_template_validates_without_resolving_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_lab_template(Path(directory) / "assessment.json")
            plan = load_assessment(path)

        self.assertEqual(len(plan.access), 11)
        self.assertEqual(len(plan.visibility), 7)
        self.assertEqual(len(plan.protocol), 4)
        self.assertEqual(plan.actors["alice"].token_env, "MCPRIFT_AUTH_TOKEN")

    def test_credential_resolution_is_deferred(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_lab_template(Path(directory) / "assessment.json")
            plan = load_assessment(path)
        variables = {
            "MCPRIFT_AUTH_TOKEN": "",
            "MCPRIFT_BOB_TOKEN": "",
            "MCPRIFT_INVALID_TOKEN": "",
            "MCPRIFT_EXPIRED_TOKEN": "",
        }
        with patch.dict(os.environ, variables):
            with self.assertRaises(ConnectionFailure):
                plan.resolve_actors()

    def test_strict_validation_rejects_duplicates_unknown_fields_and_inline_tokens(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assessment.json"
            write_lab_template(path)
            value = json.loads(path.read_text())
            value["access"].append(value["access"][0])
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                load_assessment(path)

            value["access"].pop()
            value["unexpected"] = True
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                load_assessment(path)

            value.pop("unexpected")
            value["actors"]["alice"]["token"] = "inline-secret"
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                load_assessment(path)

    def test_tool_case_requires_safe_action_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assessment.json"
            write_lab_template(path)
            value = json.loads(path.read_text())
            del value["access"][0]["action"]["safety_justification"]
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                load_assessment(path)

    def test_target_must_remain_loopback_and_credential_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assessment.json"
            write_lab_template(path)
            value = json.loads(path.read_text())
            value["target"] = "https://user:secret@example.test/mcp"
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError) as raised:
                load_assessment(path)
        self.assertNotIn("secret", str(raised.exception))
