"""Tests for the Python to Go bridge."""

import unittest

from hackit.sqli import go_bridge


class BuildArgsTests(unittest.TestCase):
    def test_minimal_arguments(self):
        args = go_bridge.build_args("http://example.test", verbose_lvl=0)
        self.assertEqual(args, [go_bridge.BINARY_PATH, "-u", "http://example.test"])

    def test_verbose_is_added(self):
        args = go_bridge.build_args("http://example.test", verbose_lvl=2)
        self.assertEqual(args[-2:], ["--verbose", "2"])

    def test_boolean_flags(self):
        args = go_bridge.build_args(
            "http://example.test",
            verbose_lvl=0,
            list_dbs=True,
            dump_all=True,
            follow_redirect=False,
        )
        self.assertIn("--list-dbs", args)
        self.assertIn("--dump-all", args)
        self.assertNotIn("--follow-redirect", args)

    def test_integer_flags(self):
        args = go_bridge.build_args(
            "http://example.test",
            verbose_lvl=0,
            timeout=20,
            rows=5,
            time_secs=2,
        )
        self.assertEqual(args[args.index("--timeout") + 1], "20")
        self.assertEqual(args[args.index("--rows") + 1], "5")
        self.assertEqual(args[args.index("--time-secs") + 1], "2")

    def test_string_flags(self):
        args = go_bridge.build_args(
            "http://example.test",
            verbose_lvl=0,
            database="main",
            dump_table="users",
            sql_query="SELECT 1",
            technique="union",
            dbms="sqlite",
        )
        self.assertEqual(args[args.index("--db") + 1], "main")
        self.assertEqual(args[args.index("--dump-table") + 1], "users")
        self.assertEqual(args[args.index("--sql-query") + 1], "SELECT 1")
        self.assertEqual(args[args.index("--technique") + 1], "union")
        self.assertEqual(args[args.index("--dbms") + 1], "sqlite")

    def test_empty_strings_are_omitted(self):
        args = go_bridge.build_args(
            "http://example.test",
            verbose_lvl=0,
            database="",
            sql_query="",
        )
        self.assertNotIn("--db", args)
        self.assertNotIn("--sql-query", args)

    def test_list_values_are_joined_for_string_flags(self):
        args = go_bridge.build_args(
            "http://example.test",
            verbose_lvl=0,
            header=("X-One: 1", "X-Two: 2"),
        )
        self.assertEqual(args.count("--header"), 1)
        self.assertEqual(args[args.index("--header") + 1], "X-One: 1,X-Two: 2")

    def test_unknown_keys_use_dashed_fallback(self):
        args = go_bridge.build_args(
            "http://example.test",
            verbose_lvl=0,
            custom_flag="value",
        )
        self.assertEqual(args[args.index("--custom-flag") + 1], "value")


class ParseStdoutTests(unittest.TestCase):
    def test_parses_json_list(self):
        parsed = go_bridge.parse_stdout('[{"type": "boolean"}]')
        self.assertEqual(parsed, [{"type": "boolean"}])

    def test_parses_last_json_line(self):
        parsed = go_bridge.parse_stdout('log line\n{"type": "union"}\n')
        self.assertEqual(parsed, {"type": "union"})

    def test_empty_output_returns_none(self):
        self.assertIsNone(go_bridge.parse_stdout(""))
        self.assertIsNone(go_bridge.parse_stdout("   \n"))

    def test_invalid_output_returns_none(self):
        self.assertIsNone(go_bridge.parse_stdout("not json at all"))


if __name__ == "__main__":
    unittest.main()
