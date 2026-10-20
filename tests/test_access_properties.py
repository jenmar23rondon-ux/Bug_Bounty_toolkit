import json
import unittest

try:
    from hypothesis import given, strategies as st
except ImportError:
    raise unittest.SkipTest("Install the dev extra to run property-based tests.")

from bugbounty_toolkit.access_control.range_checker import parse_id_range
from bugbounty_toolkit.access_control.comparison import parse_json, pointer_parts, replace_pointer


json_scalars = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=24))
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=12), children, max_size=4),
    ),
    max_leaves=12,
)


class AccessControlPropertyTests(unittest.TestCase):
    @given(start=st.integers(min_value=1, max_value=10_000), length=st.integers(min_value=1, max_value=25))
    def test_parse_id_range_returns_exact_bounded_interval(self, start, length):
        result = parse_id_range(f"{start}-{start + length - 1}")
        self.assertEqual(list(result), list(range(start, start + length)))

    @given(parts=st.lists(st.text(alphabet="abc/~012", max_size=12), min_size=1, max_size=8))
    def test_pointer_parts_round_trips_escaped_segments(self, parts):
        pointer = "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in parts)
        self.assertEqual(pointer_parts(pointer), parts)

    @given(value=json_values)
    def test_parse_json_round_trips_json_values(self, value):
        self.assertEqual(parse_json(json.dumps(value)), value)

    @given(original=json_scalars, replacement=json_scalars)
    def test_replace_pointer_changes_only_the_selected_scalar(self, original, replacement):
        document = {"record": {"id": 7, "value": original}, "unchanged": [True, "x"]}
        updated = replace_pointer(document, "/record/value", replacement)
        self.assertEqual(updated["record"]["value"], replacement)
        self.assertEqual(updated["record"]["id"], 7)
        self.assertEqual(updated["unchanged"], [True, "x"])
        self.assertEqual(document["record"]["value"], original)
