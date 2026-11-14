import copy
import unittest
from unittest.mock import patch

import driver
from assertions import NORMAL


class DriverTest(unittest.TestCase):
    def test_cases_require_committed_rows_and_attachment_switch(self):
        records, pending = [], []
        active = [True]

        def row(direction):
            status, structure = NORMAL[direction]
            return {"record": {"record_id": str(len(records) + len(pending)), "direction": direction,
                               "operation": "POST", "route_template": "/pilot",
                               "status_code": status, "structure": structure},
                    "metadata": {"source_id": "source", "parser_profile": "http_json_v1",
                                 "project_id": "p", "service_id": "s", "environment_id": "e",
                                 "deployment_id": "d", "attribution_class": "unattributed", "origin_proof": None}}

        class Response:
            status = 201
            def getheader(self, _): return "application/json"
            def read(self): return b'{"result":1}'

        class Connection:
            def __init__(self, *args, **kwargs): pass
            def request(self, method, path, body, headers, encode_chunked):
                assert method == "POST" and encode_chunked and b"".join(body) == b'{"probe":true}'
                if active[0] and path == "/pilot":
                    if headers.get("Content-Encoding") != "gzip":
                        pending.append(row("request"))
                    pending.append(row("response"))
            def getresponse(self): return Response()
            def close(self): pass

        def command(value):
            if value == "DRAIN":
                records.extend(pending)
                pending.clear()
                return "DRAIN 0 1"
            active[0] = value == "ATTACH"
            return "ATTACHED" if active[0] else "DETACHED"

        with patch.object(driver.http.client, "HTTPConnection", Connection), patch.object(driver.http.client, "HTTPSConnection", Connection):
            driver.run(command, lambda: copy.deepcopy(records), "source", ["p", "s", "e", "d"], 1, 2, object())
        self.assertEqual(len(records), 8)


if __name__ == "__main__":
    unittest.main()
