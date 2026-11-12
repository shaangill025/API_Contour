import copy
import unittest

from assertions import NORMAL, assert_new_records


def row(direction):
    status, structure = NORMAL[direction]
    return {
        "record": {"record_id": direction, "direction": direction, "operation": "POST",
                   "route_template": "/pilot", "status_code": status, "structure": structure},
        "metadata": {"source_id": "source", "parser_profile": "http_json_v1",
                     "project_id": "p", "service_id": "s", "environment_id": "e",
                     "deployment_id": "d", "attribution_class": "unattributed", "origin_proof": None},
    }


class AssertionsTest(unittest.TestCase):
    def test_exact_fresh_shapes_and_origin(self):
        data = [row("request"), row("response")]
        assert_new_records([], data, NORMAL, "source", ["p", "s", "e", "d"])
        modified = copy.deepcopy(data)
        modified[0]["metadata"]["attribution_class"] = "verified"
        with self.assertRaises(AssertionError):
            assert_new_records([], modified, NORMAL, "source", ["p", "s", "e", "d"])
        modified = copy.deepcopy(data)
        modified[1]["record"]["structure"] = {}
        with self.assertRaises(AssertionError):
            assert_new_records([], modified, NORMAL, "source", ["p", "s", "e", "d"])

    def test_missing_or_rewritten_history_fails(self):
        request = row("request")
        with self.assertRaises(AssertionError):
            assert_new_records([request], [], {}, "source", ["p", "s", "e", "d"])
        changed = copy.deepcopy(request)
        changed["record"]["operation"] = "GET"
        with self.assertRaises(AssertionError):
            assert_new_records([request], [changed], {}, "source", ["p", "s", "e", "d"])


if __name__ == "__main__":
    unittest.main()
