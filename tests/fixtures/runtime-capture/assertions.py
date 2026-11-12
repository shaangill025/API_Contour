"""Assertions for the owned live fixture; no fixture lifecycle or database access.

Pass actual delivered record dictionaries, joined to V2 metadata by record ID.
The enclosing owner must take each snapshot after DRAIN has acknowledged delivery.
"""


def shape(field, kind):
    return {"kind": "object", "fields": {field: {"kind": kind}}, "additional": None}


def assert_new_records(before, after, expected, source, workload, profile="http_json_v1"):
    """Check immutable history and exact fresh records, not queue counters alone.

    expected maps directions to (status, structure); workload is project,
    service, environment and deployment. Records contain a 'record' object and
    a 'metadata' object as returned by the owner's DB snapshot.
    """
    old = {row["record"]["record_id"]: row for row in before}
    current = {row["record"]["record_id"]: row for row in after}
    if len(old) != len(before) or len(current) != len(after):
        raise AssertionError("duplicate record ID")
    if any(current.get(key) != value for key, value in old.items()):
        raise AssertionError("prior delivered record changed")
    fresh = [value for key, value in current.items() if key not in old]
    if len(fresh) != len(expected):
        raise AssertionError("unexpected number of delivered records")
    directions = set()
    for row in fresh:
        record = row["record"]
        metadata = row["metadata"]
        direction = record["direction"]
        if direction in directions or direction not in expected:
            raise AssertionError("unexpected direction")
        directions.add(direction)
        status, structure = expected[direction]
        if (record["operation"], record["route_template"], record["status_code"],
            record["structure"]) != ("POST", "/pilot", status, structure):
            raise AssertionError("wrong operation, status, or structure")
        if (metadata["source_id"], metadata["parser_profile"],
            [metadata[k] for k in ("project_id", "service_id", "environment_id", "deployment_id")]) != (source, profile, workload):
            raise AssertionError("wrong operator scope")
        if metadata["attribution_class"] != "unattributed" or metadata.get("origin_proof") is not None:
            raise AssertionError("untrusted origin was attributed")
    return fresh


NORMAL = {
    "request": (None, shape("probe", "boolean")),
    "response": (201, shape("result", "integer")),
}
