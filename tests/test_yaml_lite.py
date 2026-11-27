"""Tests for the stdlib YAML-subset parser."""

from __future__ import annotations

import unittest

from agent_perm_guard.yaml_lite import YamlError, loads


class YamlTests(unittest.TestCase):
    def test_nested_mapping(self):
        value = loads("name: agent\ntools:\n  - name: a\n    enabled: true\n")
        self.assertEqual(value["name"], "agent")
        self.assertEqual(value["tools"][0]["name"], "a")
        self.assertTrue(value["tools"][0]["enabled"])

    def test_sequence_of_mappings_with_nested_permissions(self):
        text = (
            "tools:\n"
            "  - name: shell\n"
            "    command: ls\n"
            "    permissions:\n"
            "      filesystem:\n"
            "        write: [\"*\"]\n"
            "      network: true\n"
        )
        value = loads(text)
        tool = value["tools"][0]
        self.assertEqual(tool["name"], "shell")
        self.assertEqual(tool["permissions"]["filesystem"]["write"], ["*"])
        self.assertIs(tool["permissions"]["network"], True)

    def test_quoted_string_with_colon(self):
        value = loads('description: "http://example.com:8080 path"\n')
        self.assertEqual(value["description"], "http://example.com:8080 path")

    def test_comments_are_ignored(self):
        value = loads("# leading comment\nname: agent  # trailing comment\n")
        self.assertEqual(value, {"name": "agent"})

    def test_inline_list_of_numbers(self):
        value = loads("ports: [80, 443, 8080]\n")
        self.assertEqual(value["ports"], [80, 443, 8080])

    def test_inline_map(self):
        value = loads("limits: {cpu: 2, memory: 512}\n")
        self.assertEqual(value["limits"], {"cpu": 2, "memory": 512})

    def test_null_and_booleans(self):
        value = loads("a: null\nb: false\nc: true\n")
        self.assertIsNone(value["a"])
        self.assertFalse(value["b"])
        self.assertTrue(value["c"])

    def test_malformed_mapping_raises(self):
        with self.assertRaises(YamlError):
            loads("  bad-line-without-colon\n")
